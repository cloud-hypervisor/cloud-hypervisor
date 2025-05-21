// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::File;
use std::io::Read;
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, result, thread};

#[cfg(target_arch = "aarch64")]
use devices::legacy::Pl011;
#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
use devices::legacy::Serial;
use libc::EFD_NONBLOCK;
use serial_buffer::SerialBuffer;
use thiserror::Error;
use vmm_sys_util::eventfd::EventFd;

use crate::console_devices::ConsoleOutput;

#[derive(Debug, Error)]
pub enum Error {
    /// Cannot clone File.
    #[error("Error cloning File")]
    FileClone(#[source] io::Error),

    /// Cannot create epoll context.
    #[error("Error creating epoll context")]
    Epoll(#[source] io::Error),

    /// Cannot handle the VM input stream.
    #[error("Error handling VM input")]
    ReadInput(#[source] io::Error),

    /// Cannot queue input to the serial device.
    #[error("Error queuing input to the serial device")]
    QueueInput(#[source] vmm_sys_util::errno::Error),

    /// Cannot flush output on the serial buffer.
    #[error("Error flushing serial device's output buffer")]
    FlushOutput(#[source] io::Error),

    /// Cannot make the file descriptor non-blocking.
    #[error("Error making input file descriptor non-blocking")]
    SetNonBlocking(#[source] io::Error),

    /// Cannot create EventFd.
    #[error("Error creating EventFd")]
    EventFd(#[source] io::Error),

    /// Cannot spawn SerialManager thread.
    #[error("Error spawning SerialManager thread")]
    SpawnSerialManager(#[source] io::Error),

    /// Cannot bind to Unix socket
    #[error("Error binding to socket")]
    BindUnixSocket(#[source] io::Error),

    /// Cannot accept connection from Unix socket
    #[error("Error accepting connection")]
    AcceptConnection(#[source] io::Error),

    /// Cannot clone the UnixStream
    #[error("Error cloning UnixStream")]
    CloneUnixStream(#[source] io::Error),

    /// Cannot shutdown the connection
    #[error("Error shutting down a connection")]
    ShutdownConnection(#[source] io::Error),

    /// Cannot remove the serial socket
    #[error("Error removing serial socket")]
    RemoveUnixSocket(#[source] io::Error),

    /// Cannot duplicate file descriptor
    #[error("Error duplicating file descriptor")]
    DupFd(#[source] io::Error),
}
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EpollDispatch {
    File = 0,
    Kill = 1,
    Socket = 2,
    Unknown,
}
const EPOLL_EVENTS_LEN: usize = 4;

impl From<u64> for EpollDispatch {
    fn from(v: u64) -> Self {
        use EpollDispatch::*;
        match v {
            0 => File,
            1 => Kill,
            2 => Socket,
            _ => Unknown,
        }
    }
}

pub struct SerialManager {
    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    serial: Arc<Mutex<Serial>>,
    #[cfg(target_arch = "aarch64")]
    serial: Arc<Mutex<Pl011>>,
    epoll_file: File,
    in_file: ConsoleOutput,
    kill_evt: EventFd,
    handle: Option<thread::JoinHandle<()>>,
    pty_write_out: Option<Arc<AtomicBool>>,
    socket_path: Option<PathBuf>,
}

impl SerialManager {
    pub fn new(
        #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))] serial: Arc<Mutex<Serial>>,
        #[cfg(target_arch = "aarch64")] serial: Arc<Mutex<Pl011>>,
        mut output: ConsoleOutput,
        socket: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        let mut socket_path: Option<PathBuf> = None;

        let in_fd = match output {
            ConsoleOutput::Pty(ref fd) => fd.as_raw_fd(),
            ConsoleOutput::Tty(_) => {
                // If running on an interactive TTY then accept input
                // SAFETY: trivially safe
                if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 } {
                    // SAFETY: STDIN_FILENO is a valid fd
                    let fd = unsafe { libc::dup(libc::STDIN_FILENO) };
                    if fd == -1 {
                        return Err(Error::DupFd(std::io::Error::last_os_error()));
                    }
                    // SAFETY: fd is valid and owned by us
                    let stdin_clone = unsafe { File::from_raw_fd(fd) };
                    // SAFETY: FFI calls with correct arguments
                    let ret = unsafe {
                        let mut flags = libc::fcntl(stdin_clone.as_raw_fd(), libc::F_GETFL);
                        flags |= libc::O_NONBLOCK;
                        libc::fcntl(stdin_clone.as_raw_fd(), libc::F_SETFL, flags)
                    };

                    if ret < 0 {
                        return Err(Error::SetNonBlocking(std::io::Error::last_os_error()));
                    }

                    output = ConsoleOutput::Tty(Arc::new(stdin_clone));
                    fd
                } else {
                    return Ok(None);
                }
            }
            ConsoleOutput::Socket(ref fd) => {
                if let Some(path_in_socket) = socket {
                    socket_path = Some(path_in_socket.clone());
                }
                fd.as_raw_fd()
            }
            _ => return Ok(None),
        };

        let epoll_fd = epoll::create(true).map_err(Error::Epoll)?;
        let kill_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            kill_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EpollDispatch::Kill as u64),
        )
        .map_err(Error::Epoll)?;

        let epoll_fd_data = if let ConsoleOutput::Socket(_) = output {
            EpollDispatch::Socket
        } else {
            EpollDispatch::File
        };

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            in_fd,
            epoll::Event::new(epoll::Events::EPOLLIN, epoll_fd_data as u64),
        )
        .map_err(Error::Epoll)?;

        let mut pty_write_out = None;
        if let ConsoleOutput::Pty(ref file) = output {
            let write_out = Arc::new(AtomicBool::new(false));
            pty_write_out = Some(write_out.clone());
            let writer = file.try_clone().map_err(Error::FileClone)?;
            let buffer = SerialBuffer::new(Box::new(writer), write_out);
            serial
                .as_ref()
                .lock()
                .unwrap()
                .set_out(Some(Box::new(buffer)));
        }

        // Use 'File' to enforce closing on 'epoll_fd'
        // SAFETY: epoll_fd is valid
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        Ok(Some(SerialManager {
            serial,
            epoll_file,
            in_file: output,
            kill_evt,
            handle: None,
            pty_write_out,
            socket_path,
        }))
    }

    // This function should be called when the other end of the PTY is
    // connected. It verifies if this is the first time it's been invoked
    // after the connection happened, and if that's the case it flushes
    // all output from the serial to the PTY. Otherwise, it's a no-op.
    fn trigger_pty_flush(
        #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))] serial: &Arc<Mutex<Serial>>,
        #[cfg(target_arch = "aarch64")] serial: &Arc<Mutex<Pl011>>,
        pty_write_out: Option<&Arc<AtomicBool>>,
    ) -> Result<()> {
        if let Some(pty_write_out) = &pty_write_out {
            if pty_write_out.load(Ordering::Acquire) {
                return Ok(());
            }

            pty_write_out.store(true, Ordering::Release);

            serial
                .lock()
                .unwrap()
                .flush_output()
                .map_err(Error::FlushOutput)?;
        }

        Ok(())
    }

    pub fn start_thread(&mut self, exit_evt: EventFd) -> Result<()> {
        // Don't allow this to be run if the handle exists
        if self.handle.is_some() {
            warn!("Tried to start multiple SerialManager threads, ignoring");
            return Ok(());
        }

        let epoll_fd = self.epoll_file.as_raw_fd();
        let in_file = self.in_file.clone();
        let serial = self.serial.clone();
        let pty_write_out = self.pty_write_out.clone();
        let mut reader: Option<UnixStream> = None;

        // In case of PTY, we want to be able to detect a connection on the
        // other end of the PTY. This is done by detecting there's no event
        // triggered on the epoll, which is the reason why we want the
        // epoll_wait() function to return after the timeout expired.
        // In case of TTY, we don't expect to detect such behavior, which is
        // why we can afford to block until an actual event is triggered.
        let timeout = if pty_write_out.is_some() { 500 } else { -1 };

        let thread = thread::Builder::new()
            .name("serial-manager".to_string())
            .spawn(move || {
                std::panic::catch_unwind(AssertUnwindSafe(move || {
                    let mut events =
                        [epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

                    loop {
                        let num_events = match epoll::wait(epoll_fd, timeout, &mut events[..]) {
                            Ok(res) => res,
                            Err(e) => {
                                if e.kind() == io::ErrorKind::Interrupted {
                                    // It's well defined from the epoll_wait() syscall
                                    // documentation that the epoll loop can be interrupted
                                    // before any of the requested events occurred or the
                                    // timeout expired. In both those cases, epoll_wait()
                                    // returns an error of type EINTR, but this should not
                                    // be considered as a regular error. Instead it is more
                                    // appropriate to retry, by calling into epoll_wait().
                                    continue;
                                } else {
                                    return Err(Error::Epoll(e));
                                }
                            }
                        };

                        if matches!(in_file, ConsoleOutput::Socket(_)) && num_events == 0 {
                            // This very specific case happens when the serial is connected
                            // to a PTY. We know EPOLLHUP is always present when there's nothing
                            // connected at the other end of the PTY. That's why getting no event
                            // means we can flush the output of the serial through the PTY.
                            Self::trigger_pty_flush(&serial, pty_write_out.as_ref())?;
                            continue;
                        }

                        for event in events.iter().take(num_events) {
                            let dispatch_event: EpollDispatch = event.data.into();
                            match dispatch_event {
                                EpollDispatch::Unknown => {
                                    let event = event.data;
                                    warn!("Unknown serial manager loop event: {}", event);
                                }
                                EpollDispatch::Socket => {
                                    // New connection request arrived.
                                    // Shutdown the previous connection, if any
                                    if let Some(previous_reader) = reader {
                                        previous_reader
                                            .shutdown(Shutdown::Both)
                                            .map_err(Error::AcceptConnection)?;
                                    }

                                    let ConsoleOutput::Socket(ref listener) = in_file else {
                                        unreachable!();
                                    };

                                    // Events on the listening socket will be connection requests.
                                    // Accept them, create a reader and a writer.
                                    let (unix_stream, _) =
                                        listener.accept().map_err(Error::AcceptConnection)?;
                                    let writer =
                                        unix_stream.try_clone().map_err(Error::CloneUnixStream)?;
                                    reader = Some(
                                        unix_stream.try_clone().map_err(Error::CloneUnixStream)?,
                                    );

                                    epoll::ctl(
                                        epoll_fd,
                                        epoll::ControlOptions::EPOLL_CTL_ADD,
                                        unix_stream.into_raw_fd(),
                                        epoll::Event::new(
                                            epoll::Events::EPOLLIN,
                                            EpollDispatch::File as u64,
                                        ),
                                    )
                                    .map_err(Error::Epoll)?;
                                    serial.lock().unwrap().set_out(Some(Box::new(writer)));
                                }
                                EpollDispatch::File => {
                                    if event.events & libc::EPOLLIN as u32 != 0 {
                                        let mut input = [0u8; 64];
                                        let count = match &in_file {
                                            ConsoleOutput::Socket(_) => {
                                                if let Some(mut serial_reader) = reader.as_ref() {
                                                    let count = serial_reader
                                                        .read(&mut input)
                                                        .map_err(Error::ReadInput)?;
                                                    if count == 0 {
                                                        info!("Remote end closed serial socket");
                                                        serial_reader
                                                            .shutdown(Shutdown::Both)
                                                            .map_err(Error::ShutdownConnection)?;
                                                        reader = None;
                                                        serial
                                                            .as_ref()
                                                            .lock()
                                                            .unwrap()
                                                            .set_out(None);
                                                    }
                                                    count
                                                } else {
                                                    0
                                                }
                                            }
                                            ConsoleOutput::Pty(file) | ConsoleOutput::Tty(file) => {
                                                (&**file)
                                                    .read(&mut input)
                                                    .map_err(Error::ReadInput)?
                                            }
                                            _ => unreachable!(),
                                        };

                                        // Replace "\n" with "\r" to deal with Windows SAC (#1170)
                                        if count == 1 && input[0] == 0x0a {
                                            input[0] = 0x0d;
                                        }

                                        serial
                                            .as_ref()
                                            .lock()
                                            .unwrap()
                                            .queue_input_bytes(&input[..count])
                                            .map_err(Error::QueueInput)?;
                                    }
                                    if event.events & libc::EPOLLHUP as u32 != 0 {
                                        if let Some(pty_write_out) = &pty_write_out {
                                            pty_write_out.store(false, Ordering::Release);
                                        }
                                        // It's really important to sleep here as this will prevent
                                        // the current thread from consuming 100% of the CPU cycles
                                        // when waiting for someone to connect to the PTY.
                                        std::thread::sleep(std::time::Duration::from_millis(500));
                                    } else {
                                        // If the EPOLLHUP flag is not up on the associated event, we
                                        // can assume the other end of the PTY is connected and therefore
                                        // we can flush the output of the serial to it.
                                        Self::trigger_pty_flush(&serial, pty_write_out.as_ref())?;
                                    }
                                }
                                EpollDispatch::Kill => {
                                    info!("KILL_EVENT received, stopping epoll loop");
                                    return Ok(());
                                }
                            }
                        }
                    }
                }))
                .map_err(|_| {
                    error!("serial-manager thread panicked");
                    exit_evt.write(1).ok()
                })
                .ok();
            })
            .map_err(Error::SpawnSerialManager)?;
        self.handle = Some(thread);
        Ok(())
    }
}

impl Drop for SerialManager {
    fn drop(&mut self) {
        self.kill_evt.write(1).ok();
        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
        if let ConsoleOutput::Socket(_) = self.in_file {
            if let Some(socket_path) = self.socket_path.as_ref() {
                std::fs::remove_file(socket_path.as_os_str())
                    .map_err(Error::RemoveUnixSocket)
                    .ok();
            }
        }
    }
}
