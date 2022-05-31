use std::sync::{Arc, Mutex};
use std::cmp;
use std::io;
use std::io::{BufRead, BufReader};
use std::os::unix::net::{UnixStream,UnixListener};
use std::thread;
use std::time::{Duration, Instant};
use std::thread::sleep;
use std::str;
use std::io::prelude::*;
use std::io::Write;
use std::os::unix::io::{RawFd, AsRawFd};
use nix::unistd::{read, write};
use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag, recv, sendmsg, recvfrom, ControlMessage, MsgFlags };
use nix::sys::uio::IoVec;
use libc;

const TPM_TIS_BUFFER_MAX: usize = 4096;

type Result<T> = std::result::Result<T, Error>;

/// Copy data in `from` into `to`, until the shortest
/// of the two slices.
///
/// Return the number of bytes written.
fn byte_copy(from: &[u8], mut to: &mut [u8]) -> usize {
    to.write(from).unwrap()
}

#[derive(PartialEq)]
enum ChardevState {
    ChardevStateDisconnected,
    ChardevStateConnecting,
    ChardevStateConnected,
}

pub struct SocketCharDev {
    state: ChardevState,
    stream: Option<UnixStream>,
    write_msgfd: RawFd,
    /* Control Channel */
    ctrl_fd: RawFd,
    /* Command Channel */
    data_ioc: RawFd,
    chr_write_lock: Arc<Mutex<usize>>,
}

impl SocketCharDev {
    pub fn new() -> Self {
        Self {
            state: ChardevState::ChardevStateDisconnected,
            stream: None,
            write_msgfd: -1,
            ctrl_fd: -1,
            data_ioc: -1,
            chr_write_lock: Arc::new(Mutex::new(0))
        }
    }

    pub fn debugmessage(&mut self) {
        {
            let mut buf = (44 as u32).to_be_bytes();
            let iov = &[IoVec::from_slice(&buf)];
            let res = sendmsg(self.ctrl_fd, iov, &[ControlMessage::ScmRights(&[])], MsgFlags::empty(), None).expect("Error sending");
            let mut buf2: &mut [u8] = &mut [1 as u8; 4];
            println!("before: {:?}", buf2);
            let (n, s) = recvfrom(self.ctrl_fd, buf2).expect("Hello");
        }
    }

    pub fn connect(&mut self, socket_path: &str) -> isize {
        self.state = ChardevState::ChardevStateConnecting;

        let now = Instant::now();

        // Retry connecting for a full minute
        let err = loop {
            let err = match UnixStream::connect(socket_path) {
                Ok(s) => {
                    let fd = s.as_raw_fd();
                    self.ctrl_fd = fd;
                    self.stream = Some(s);
                    self.state = ChardevState::ChardevStateConnected;
             warn!("PPK: Connected to socket path : {:?}\n", socket_path);

                    return 0
                }
                Err(e) => e,
            };
            sleep(Duration::from_millis(100));

            if now.elapsed().as_secs() >= 60 {
                break err;
            }
        };
        
        // error!(
        //     "Failed connecting the backend after trying for 1 minute: {:?}",
        //     err
        // );
        -1
    }

    pub fn set_dataioc(&mut self, fd: RawFd) {
        self.data_ioc = fd;
    }

    pub fn set_msgfd(&mut self, fd: RawFd){
        self.write_msgfd = fd;
    }

    pub fn chr_sync_read(&self, buf: &mut [u8], len: usize) -> isize {
        if self.state != ChardevState::ChardevStateConnected {
            return 0
        }
        //SET BLOCKING
        warn!("sync read state connected");
        let size = recv(self.ctrl_fd, buf, MsgFlags::empty()).expect("char.rs: sync_read recvmsg error");
        warn!("success recv");
        size as isize
    }

    pub fn send_full(&self, buf: &mut [u8], len: usize) -> isize {
        let iov = &[IoVec::from_slice(buf)];
        let write_fd = self.write_msgfd;
        let write_vec = &[write_fd];
        let cmsgs = &[ControlMessage::ScmRights(write_vec)];
        warn!("send full message");

        sendmsg(self.ctrl_fd, iov, cmsgs, MsgFlags::empty(), None).expect("char.rs: ERROR ON send_full sendmsg") as isize
    }

    pub fn chr_write(&mut self, buf: &mut [u8], len:usize) -> isize {
        let mut res = 0;
        warn!("CHR_WRITE HAPPENED");

        if let Some(ref mut sock) = self.stream {
            // let guard = self.chr_write_lock.lock().unwrap();
            {
                res = match self.state {
                    ChardevState::ChardevStateConnected => {
                        warn!("State Connected");
                        let ret = self.send_full(buf, len);
                        /* free the written msgfds in any cases
                        * other than ret < 0 */
                        if ret >= 0 {
                            self.write_msgfd = 0;
                        }

                        // if (ret < 0 && errno != EAGAIN) {
                        //     if (tcp_chr_read_poll(chr) <= 0) {
                        //         /* Perform disconnect and return error. */
                        //         tcp_chr_disconnect_locked(chr);
                        //     } /* else let the read handler finish it properly */
                        // }

                        ret
                    }
                    _ => -1,
                };
            }
            warn!("WRITE SUCCESS");
            // std::mem::drop(guard);

            res
        } else {
            -1
        }
    }

    pub fn chr_read(&mut self, buf: &mut [u8], len: usize) -> isize {
        //Grab all response bytes so none is left behind
        warn!("CHR_READ HAPPENED");

        let mut newbuf: &mut [u8] = &mut [0; TPM_TIS_BUFFER_MAX];
        
        if let Some(ref mut sock) = self.stream {
            sock.read(&mut newbuf);
            byte_copy(&newbuf, buf);
            0
        } else {
            -1
        }
    }
}

pub struct CharBackend {
    pub chr: Option<SocketCharDev>,
    fe_open: bool,
}

impl CharBackend {
    pub fn new() -> Self {
        Self {
            chr: None,
            fe_open: false,
        }
    }

    pub fn chr_fe_init(&mut self) -> isize {
        let mut sockdev = SocketCharDev::new();
        warn!("PPK: chr_fe_init invoked\n");
        let res = sockdev.connect("/tmp/swtpm/swtpm-sock");
        self.chr = Some(sockdev);
        if res < 0 {
            return -1
        }
        
        self.fe_open = true;
        0
    }

    pub fn chr_fe_set_msgfd(&mut self, fd: RawFd) -> isize {
        if let Some(ref mut dev) = self.chr {
            dev.set_msgfd(fd);
            0
        } else {
            -1
        }
    }

    pub fn chr_fe_set_dataioc(&mut self, fd: RawFd) -> isize {
        if let Some(ref mut dev) = self.chr {
            dev.set_dataioc(fd);
            0
        } else {
            -1
        }
    }

    /**
     * qemu_chr_fe_write_all:
     * @buf: the data
     * @len: the number of bytes to send
     *
     * Write data to a character backend from the front end.  This function will
     * send data from the front end to the back end.  Unlike @chr_fe_write,
     * this function will block if the back end cannot consume all of the data
     * attempted to be written.  This function is thread-safe.
     *
     * Returns: the number of bytes consumed (0 if no associated Chardev)
     */
    pub fn chr_fe_write_all(&mut self, buf: &mut [u8], len: usize) -> isize {
        if let Some(ref mut dev) = self.chr {
            dev.chr_write(buf, len)
        } else {
            -1
        }
    }


    /**
     * chr_fe_read_all:
     * @buf: the data buffer
     * @len: the number of bytes to read
     *
     * Read data to a buffer from the back end.
     *
     * Returns: the number of bytes read (0 if no associated Chardev)
     */
    pub fn chr_fe_read_all(&mut self, mut buf: &mut [u8], len: usize) -> isize {
        if let Some(ref mut dev) = self.chr {
            warn!("Made it to sync");
            let (s,_) = recvfrom(dev.ctrl_fd, &mut buf).expect("char.rs: sync_read recvmsg error");
            s as isize
            // dev.chr_sync_read(&mut buf, len)
        } else {
            -1
        }
    }


}

pub enum Error {
    BindSocket()
}
