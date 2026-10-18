// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Engine and open tests against in-process fake NBD servers.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::slice;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use vmm_sys_util::tempdir::TempDir;

use super::conn::NbdConn;
use super::conn::tests::conn_from_unix;
use super::engine_sync::NbdSync;
use super::handshake::NbdExportInfo;
use super::handshake::tests::ServerHandshake;
use super::proto::*;
use super::{NbdDisk, NbdError, NbdOpenOptions};
use crate::async_io::{AsyncIo, AsyncIoCompletion, OwnedIoBuffer};
use crate::error::BlockResult;

const SIZE: usize = 1 << 20;

/// Behaviour knobs for the fake server.
#[derive(Clone, Default)]
struct ServerConfig {
    /// Collect this many requests before replying, then reply in reverse.
    batch: usize,
    /// Write replies one byte at a time.
    byte_by_byte: bool,
    /// Reply with this NBD error to requests touching this offset.
    fail_offset: Option<(u64, u32)>,
    /// Close the connection after this many requests.
    close_after: Option<usize>,
}

#[derive(Default)]
struct ServerLog {
    commands: Vec<NbdRequest>,
}

struct FakeServer {
    data: Arc<Mutex<Vec<u8>>>,
    log: Arc<Mutex<ServerLog>>,
    handle: Option<JoinHandle<()>>,
}

impl FakeServer {
    fn start(config: ServerConfig, info: NbdExportInfo) -> (Self, NbdConn) {
        let (client, server) = UnixStream::pair().unwrap();
        let data = Arc::new(Mutex::new((0..SIZE).map(|i| i as u8).collect::<Vec<_>>()));
        let log = Arc::new(Mutex::new(ServerLog::default()));
        let handle = {
            let data = Arc::clone(&data);
            let log = Arc::clone(&log);
            thread::spawn(move || serve(server, &config, &data, &log))
        };
        (
            FakeServer {
                data,
                log,
                handle: Some(handle),
            },
            conn_from_unix(client, info),
        )
    }

    /// Waits for the server to exit and returns the commands it received.
    fn commands(&mut self) -> Vec<u16> {
        self.join();
        self.log
            .lock()
            .unwrap()
            .commands
            .iter()
            .map(|r| r.command)
            .collect()
    }
}

impl FakeServer {
    fn join(&mut self) {
        if let Some(h) = self.handle.take() {
            h.join().unwrap();
        }
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.join();
    }
}

fn send_reply(s: &mut UnixStream, reply: &[u8], byte_by_byte: bool) -> io::Result<()> {
    if byte_by_byte {
        for b in reply {
            s.write_all(slice::from_ref(b))?;
        }
        Ok(())
    } else {
        s.write_all(reply)
    }
}

fn serve(mut s: UnixStream, config: &ServerConfig, data: &Mutex<Vec<u8>>, log: &Mutex<ServerLog>) {
    let mut pending = Vec::new();
    let mut handled = 0;
    loop {
        let mut header = [0u8; NBD_REQUEST_SIZE];
        if s.read_exact(&mut header).is_err() {
            return;
        }
        let req = NbdRequest::decode(&header).expect("bad request magic");
        log.lock().unwrap().commands.push(req);
        if req.command == NBD_CMD_DISC {
            return;
        }
        handled += 1;
        if config.close_after.is_some_and(|n| handled > n) {
            return;
        }

        let range = req.offset as usize..(req.offset + req.length as u64) as usize;
        let error = match config.fail_offset {
            Some((off, err)) if range.contains(&(off as usize)) => err,
            _ => NBD_SUCCESS,
        };
        let mut reply = NbdSimpleReply {
            error,
            cookie: req.cookie,
        }
        .encode()
        .to_vec();
        match req.command {
            NBD_CMD_WRITE => {
                let mut payload = vec![0u8; req.length as usize];
                s.read_exact(&mut payload).unwrap();
                if error == NBD_SUCCESS {
                    data.lock().unwrap()[range].copy_from_slice(&payload);
                }
            }
            NBD_CMD_READ if error == NBD_SUCCESS => {
                reply.extend_from_slice(&data.lock().unwrap()[range]);
            }
            NBD_CMD_WRITE_ZEROES | NBD_CMD_TRIM if error == NBD_SUCCESS => {
                data.lock().unwrap()[range].fill(0);
            }
            _ => {}
        }

        pending.push(reply);
        if pending.len() >= config.batch.max(1) {
            for reply in pending.drain(..).rev() {
                if send_reply(&mut s, &reply, config.byte_by_byte).is_err() {
                    return;
                }
            }
        }
    }
}

fn export_info(max_block: u32) -> NbdExportInfo {
    NbdExportInfo {
        size: SIZE as u64,
        flags: NBD_FLAG_HAS_FLAGS
            | NBD_FLAG_SEND_FLUSH
            | NBD_FLAG_SEND_TRIM
            | NBD_FLAG_SEND_WRITE_ZEROES,
        min_block: 512,
        opt_block: 4096,
        max_block,
    }
}

#[derive(Clone, Copy, Debug)]
enum Engine {
    Sync,
    #[cfg(feature = "io_uring")]
    Uring,
}

fn engines() -> Vec<Engine> {
    #[allow(unused_mut)]
    let mut v = vec![Engine::Sync];
    #[cfg(feature = "io_uring")]
    if super::engine_uring::supported() {
        v.push(Engine::Uring);
    }
    v
}

fn make_engine(engine: Engine, conn: NbdConn) -> Box<dyn AsyncIo> {
    match engine {
        Engine::Sync => Box::new(NbdSync::new(conn)),
        #[cfg(feature = "io_uring")]
        Engine::Uring => Box::new(super::engine_uring::NbdUring::new(conn).unwrap()),
    }
}

/// Waits until `n` completions are available and returns them.
fn wait_completions(io: &mut dyn AsyncIo, n: usize) -> Vec<AsyncIoCompletion> {
    let mut out = Vec::new();
    while out.len() < n {
        while let Some(c) = io.next_completed_request() {
            out.push(c);
        }
        if out.len() >= n {
            break;
        }
        let mut pfd = libc::pollfd {
            fd: io.notifier().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid pollfd for the duration of the call.
        let r = unsafe { libc::poll(&mut pfd, 1, 5000) };
        assert!(r > 0, "timed out waiting for NBD completions");
        let _ = io.notifier().read();
    }
    out
}

fn read(io: &mut dyn AsyncIo, offset: u64, len: usize, user_data: u64) {
    io.read_to_vec(
        offset as libc::off_t,
        OwnedIoBuffer::from_vec(vec![0; len]),
        user_data,
    )
    .unwrap();
}

fn pattern(offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len).map(|i| i as u8).collect()
}

#[test]
fn read_write_round_trip() {
    for engine in engines() {
        let (mut server, conn) = FakeServer::start(ServerConfig::default(), export_info(1 << 20));
        let mut io = make_engine(engine, conn);

        read(io.as_mut(), 4096, 8192, 1);
        let c = wait_completions(io.as_mut(), 1).pop().unwrap();
        assert_eq!((c.user_data, c.result), (1, 8192), "{engine:?}");
        assert_eq!(c.buffer.unwrap().as_slice(), pattern(4096, 8192));

        io.write_from_vec(0, OwnedIoBuffer::from_vec(vec![0xab; 1024]), 2)
            .unwrap();
        let c = wait_completions(io.as_mut(), 1).pop().unwrap();
        assert_eq!((c.user_data, c.result), (2, 1024), "{engine:?}");
        assert!(
            server.data.lock().unwrap()[..1024]
                .iter()
                .all(|b| *b == 0xab)
        );

        io.fsync(Some(3)).unwrap();
        io.write_zeroes(2048, 512, 4).unwrap();
        io.punch_hole(4096, 512, 5).unwrap();
        let mut done: Vec<_> = wait_completions(io.as_mut(), 3)
            .iter()
            .map(|c| (c.user_data, c.result))
            .collect();
        done.sort();
        assert_eq!(done, vec![(3, 0), (4, 0), (5, 0)], "{engine:?}");
        io.fsync(None).unwrap();

        drop(io);
        let commands = server.commands();
        assert_eq!(*commands.last().unwrap(), NBD_CMD_DISC, "{engine:?}");
        assert!(commands.contains(&NBD_CMD_FLUSH));
        assert!(commands.contains(&NBD_CMD_TRIM));
        assert!(commands.contains(&NBD_CMD_WRITE_ZEROES));
    }
}

#[test]
fn requests_are_split_at_max_payload() {
    for engine in engines() {
        let (mut server, conn) = FakeServer::start(ServerConfig::default(), export_info(4096));
        let mut io = make_engine(engine, conn);
        read(io.as_mut(), 0, 10240, 7);
        let c = wait_completions(io.as_mut(), 1).pop().unwrap();
        assert_eq!(c.result, 10240, "{engine:?}");
        assert_eq!(c.buffer.unwrap().as_slice(), pattern(0, 10240));
        drop(io);
        server.join();
        let reads = server
            .log
            .lock()
            .unwrap()
            .commands
            .iter()
            .filter(|r| r.command == NBD_CMD_READ)
            .map(|r| r.length)
            .collect::<Vec<_>>();
        assert_eq!(reads, vec![4096, 4096, 2048], "{engine:?}");
    }
}

#[test]
fn server_error_is_reported() {
    for engine in engines() {
        let config = ServerConfig {
            fail_offset: Some((8192, NBD_ENOSPC)),
            ..Default::default()
        };
        let (_server, conn) = FakeServer::start(config, export_info(4096));
        let mut io = make_engine(engine, conn);
        // The second chunk fails; the request reports that error.
        io.write_from_vec(4096, OwnedIoBuffer::from_vec(vec![1; 12288]), 1)
            .unwrap();
        let c = wait_completions(io.as_mut(), 1).pop().unwrap();
        assert_eq!(c.result, -libc::ENOSPC, "{engine:?}");
        // The connection stays usable.
        read(io.as_mut(), 0, 512, 2);
        let c = wait_completions(io.as_mut(), 1).pop().unwrap();
        assert_eq!(c.result, 512, "{engine:?}");
    }
}

#[test]
fn connection_loss_fails_requests() {
    for engine in engines() {
        let config = ServerConfig {
            close_after: Some(1),
            ..Default::default()
        };
        let (_server, conn) = FakeServer::start(config, export_info(1 << 20));
        let mut io = make_engine(engine, conn);
        read(io.as_mut(), 0, 512, 1);
        assert_eq!(wait_completions(io.as_mut(), 1)[0].result, 512);
        read(io.as_mut(), 0, 512, 2);
        assert_eq!(
            wait_completions(io.as_mut(), 1)[0].result,
            -libc::EIO,
            "{engine:?}"
        );
        // Later requests fail without touching the socket.
        read(io.as_mut(), 0, 512, 3);
        assert_eq!(wait_completions(io.as_mut(), 1)[0].result, -libc::EIO);
        assert!(io.fsync(None).is_err());
    }
}

#[test]
fn short_transfers() {
    for engine in engines() {
        let config = ServerConfig {
            byte_by_byte: true,
            ..Default::default()
        };
        let (_server, conn) = FakeServer::start(config, export_info(1 << 20));
        let mut io = make_engine(engine, conn);
        read(io.as_mut(), 512, 2048, 1);
        let c = wait_completions(io.as_mut(), 1).pop().unwrap();
        assert_eq!(c.result, 2048, "{engine:?}");
        assert_eq!(c.buffer.unwrap().as_slice(), pattern(512, 2048));
    }
}

#[cfg(feature = "io_uring")]
#[test]
fn out_of_order_replies() {
    if !super::engine_uring::supported() {
        return;
    }
    let config = ServerConfig {
        batch: 4,
        ..Default::default()
    };
    let (_server, conn) = FakeServer::start(config, export_info(1 << 20));
    let mut io = make_engine(Engine::Uring, conn);
    for i in 0..4u64 {
        read(io.as_mut(), i * 4096, 4096, i);
    }
    let mut completions = wait_completions(io.as_mut(), 4);
    // The server replied in reverse order.
    assert_eq!(completions[0].user_data, 3);
    completions.sort_by_key(|c| c.user_data);
    for (i, c) in completions.into_iter().enumerate() {
        assert_eq!(c.result, 4096);
        assert_eq!(c.buffer.unwrap().as_slice(), pattern(i * 4096, 4096));
    }
}

#[test]
fn no_flush_without_server_support() {
    for engine in engines() {
        let mut info = export_info(1 << 20);
        info.flags &= !NBD_FLAG_SEND_FLUSH;
        let (mut server, conn) = FakeServer::start(ServerConfig::default(), info);
        let mut io = make_engine(engine, conn);
        io.fsync(Some(1)).unwrap();
        assert_eq!(wait_completions(io.as_mut(), 1)[0].result, 0);
        io.fsync(None).unwrap();
        drop(io);
        assert_eq!(server.commands(), vec![NBD_CMD_DISC], "{engine:?}");
    }
}

#[test]
fn out_of_bounds_rejected() {
    for engine in engines() {
        let (_server, conn) = FakeServer::start(ServerConfig::default(), export_info(1 << 20));
        let mut io = make_engine(engine, conn);
        assert!(
            io.read_to_vec(
                (SIZE - 512) as libc::off_t,
                OwnedIoBuffer::from_vec(vec![0; 1024]),
                1
            )
            .is_err()
        );
    }
}

/// Opens an NBD disk with `num_queues` against a server advertising
/// `flags`, which accepts a single connection.
fn open_disk(flags: u16, num_queues: usize) -> BlockResult<NbdDisk> {
    let dir = TempDir::new_with_prefix("/tmp/ch-nbd").unwrap();
    let sock = dir.as_path().join("nbd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let handle = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let server = ServerHandshake {
            flags,
            size: SIZE as u64,
            export: "vol",
            support_go: true,
            block_size: Some((512, 4096, 1 << 20)),
        };
        server.run(&mut s).unwrap();
    });
    let uri = format!("nbd+unix:///vol?socket={}", sock.display());
    let disk = NbdDisk::open(&NbdOpenOptions {
        uri: &uri,
        readonly: false,
        use_io_uring: false,
        num_queues,
    });
    handle.join().unwrap();
    disk
}

#[test]
fn multiple_queues_need_multi_conn() {
    let flags = export_info(1 << 20).flags;
    open_disk(flags, 1).unwrap();
    open_disk(flags | NBD_FLAG_CAN_MULTI_CONN, 2).unwrap();

    let err = open_disk(flags, 2).unwrap_err();
    assert!(matches!(
        err.downcast_ref::<NbdError>(),
        Some(NbdError::MultiConnUnsupported(_, 2))
    ));
}
