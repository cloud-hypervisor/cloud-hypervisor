extern crate fibers;
extern crate futures;
extern crate handy_async;

use std::io;
use std::vec::Vec;
use std::sync::{Arc, Mutex};

use fibers::{Spawn, Executor, InPlaceExecutor, ThreadPoolExecutor};
use fibers::net::{TcpListener, TcpStream};
use futures::{Future, Stream};
use handy_async::io::{AsyncWrite, ReadFrom};
use handy_async::pattern::AllowPartial;

use crate::transport::MigrationTransport;
use crate::data::MigrationDataFile;

pub struct MigrationTCP(String);

impl MigrationTCP {
    pub fn new(addr: String) -> Self {
        MigrationTCP(addr)
    }
}

impl MigrationTransport for MigrationTCP {
    fn connect(&self, data: Arc<MigrationDataFile>) {
        let server_addr = self.0.parse().unwrap();
        let mut executor = InPlaceExecutor::new().expect("Cannot create Executor");
        let handle = executor.handle();
        let should_end = Arc::new(Mutex::new(vec![0u8]));
        let end = should_end.clone();
        //TODO: capacity should be 32 * 1024.
        let mut entry = Vec::with_capacity(32);

        data.read(&mut entry);
        let len = entry.len() * std::mem::size_of::<u8>();
        let c: &[u8] = unsafe {
            std::slice::from_raw_parts((entry).as_ptr() as *const u8,
                (entry).len() * std::mem::size_of::<u8>(),
            )
        };
        let v = Arc::new(c);

        let mut monitor = executor.spawn_monitor(TcpStream::connect(server_addr).and_then(move |stream| {
            println!("# CONNECTED: {}", server_addr);

            let (reader, writer) = (stream.clone(), stream);
            let in_stream = unsafe {
                vec![0; len].allow_partial().into_stream(*Arc::into_raw(v))
            };
            handle.spawn(in_stream.map_err(|e| e.into_error())
                .fold(writer, |writer, (mut buf, size)| {
                    buf.truncate(size);
                    writer.async_write_all(buf).map(|(w, _)| w).map_err(|e| e.into_error())
                })
                .then(|r| {
                    println!("# Writer finished: {:?}", r);
                    Ok(())
                }));

            let stream = vec![0; 256].allow_partial().into_stream(reader);
            stream.map_err(|e| e.into_error())
                .for_each(move |(mut buf, len)| {
                    buf.truncate(len);
                    println!("# Client received: {:?}", buf);
                    if buf[0] == 0xff {  /* Response is OK so we can exit. */
                        let mut end_loop = end.lock().unwrap();
                        end_loop[0] = 1;
                    }
                    Ok(())
                })
        }));

        while monitor.poll().unwrap().is_not_ready() {
            executor.run_once().unwrap();

            let end_loop = should_end.lock().unwrap();
            println!("Exit monitor loop? end_loop={}", end_loop[0]);
            if end_loop[0] == 1 {
                break;
            }
        }
        println!("# Disconnected");
    }

    fn bind(&self, data: Arc<MigrationDataFile>) {
        let server_addr = self.0.parse().expect("Invalid TCP bind address");

        let mut executor = ThreadPoolExecutor::new().expect("Cannot create Executor");
        let handle0 = executor.handle();
        let monitor = executor.spawn_monitor(TcpListener::bind(server_addr)
            .and_then(move |listener| {
                println!("# Start listening: {}: ", server_addr);

                listener.incoming().for_each(move |(client, addr)| {
                    println!("# CONNECTED: {}", addr);
                    let handle1 = handle0.clone();
                    let data1 = data.clone();

                    handle0.spawn(client.and_then(move |client| {
                            let (reader, writer) = (client.clone(), client);
                            let (tx, rx) = fibers::sync::mpsc::channel();

                            handle1.spawn(rx.map_err(|_| -> io::Error { unreachable!() })
                                .fold(writer, |writer, buf: Vec<u8>| {
                                    println!("# SEND: {} bytes", buf.len());
                                    writer.async_write_all(buf).map(|(w, _)| w).map_err(|e| e.into_error())
                                })
                                .then(|r| {
                                    println!("# Writer finished: {:?}", r);
                                    Ok(())
                                }));

                            let stream = vec![0;1024].allow_partial().into_stream(reader);
                            stream.map_err(|e| e.into_error())
                                .fold(tx, move |tx, (mut buf, len)| {
                                    buf.truncate(len);
                                    println!("# RECV: {} bytes", buf.len());
                                    println!("# Server received: {:?} ", buf);
                                    data1.write(&mut buf.clone(), true);

                                    // Sends response to the writer half.
                                    let ret = vec![0xffu8];  /* OK to make client exit */
                                    tx.send(ret).expect("Cannot send");
                                    Ok(tx) as io::Result<_>
                                })
                        })
                        .then(|r| {
                            println!("# Client finished: {:?}", r);
                            Ok(())
                        }));
                    Ok(())
                })
            }));
        let result = executor.run_fiber(monitor).expect("Execution failed");
        println!("# Listener finished: {:?}", result);
    }
}
