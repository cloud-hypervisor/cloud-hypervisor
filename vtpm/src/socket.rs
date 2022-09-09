// Copyright © 2022, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use crate::tpm_ioctl::TPM_CRB_BUFFER_MAX;
use anyhow::anyhow;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use nix::sys::uio::IoVec;
use std::io::Read;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread::sleep;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TPMSocError {
    #[error("Cannot connect to TPM Socket even after retrying for 10 secs")]
    ConnectToTPMSocket(#[source] anyhow::Error),
    #[error("Failed to read from TPM socket")]
    ReadTPMSoc(#[source] anyhow::Error),
    #[error("Failed to write to TPM socket")]
    WriteTPMSocket(#[source] anyhow::Error),
}
type Result<T> = anyhow::Result<T, TPMSocError>;

#[derive(PartialEq)]
enum SocDevState {
    SocDevStateDisconnected,
    SocDevStateConnecting,
    SocDevStateConnected,
}

pub struct SocketDev {
    state: SocDevState,
    stream: Option<UnixStream>,
    // Fd sent to swtpm process for Data Channel
    write_msgfd: RawFd,
    // Data Channel used by Cloud-Hypervisor
    data_fd: RawFd,
    // Control Channel used by Cloud-Hypervisor
    ctrl_fd: RawFd,
}

impl SocketDev {
    pub fn new() -> Self {
        Self {
            state: SocDevState::SocDevStateDisconnected,
            stream: None,
            write_msgfd: -1,
            ctrl_fd: -1,
            data_fd: -1,
        }
    }

    pub fn init(&mut self, path: String) -> Result<()> {
        let _ = self.connect(&path)?;
        Ok(())
    }

    pub fn connect(&mut self, socket_path: &str) -> Result<()> {
        self.state = SocDevState::SocDevStateConnecting;

        let now = Instant::now();

        // Retry connecting for a full minute
        loop {
            match UnixStream::connect(socket_path) {
                Ok(s) => {
                    let fd = s.as_raw_fd();
                    self.ctrl_fd = fd;
                    self.stream = Some(s);
                    self.state = SocDevState::SocDevStateConnected;
                    debug!("Connected to vTPM socket path : {:?}", socket_path);
                    return Ok(());
                }
                Err(_e) => {}
            };
            sleep(Duration::from_millis(1000));

            if now.elapsed().as_secs() >= 10 {
                break;
            }
        }
        Err(TPMSocError::ConnectToTPMSocket(anyhow!(
            "Failed to connect to vTPM Socket"
        )))
    }

    pub fn set_datafd(&mut self, fd: RawFd) {
        self.data_fd = fd;
    }

    pub fn set_msgfd(&mut self, fd: RawFd) {
        self.write_msgfd = fd;
    }

    pub fn send_full(&self, buf: &mut [u8], _len: usize) -> Result<usize> {
        let iov = &[IoVec::from_slice(buf)];
        let write_fd = self.write_msgfd;
        let write_vec = &[write_fd];
        let cmsgs = &[ControlMessage::ScmRights(write_vec)];

        // Send Ancillary data, along with cmds and data
        let size = sendmsg(self.ctrl_fd, iov, cmsgs, MsgFlags::empty(), None).map_err(|e| {
            TPMSocError::WriteTPMSocket(anyhow!(
                "Failed to write to vTPM Socket. Error Code {:?}",
                e
            ))
        })?;
        Ok(size as usize)
    }

    pub fn write(&mut self, buf: &mut [u8], len: usize) -> Result<usize> {
        if self.stream.is_none() {
            return Err(TPMSocError::WriteTPMSocket(anyhow!(
                "Stream for TPM Socket was not initialized"
            )));
        }
        let res = match self.state {
            SocDevState::SocDevStateConnected => {
                let ret = self.send_full(buf, len)?;
                // swtpm will receive data Fd after a successful send
                // Reset cached write_msgfd after a successful send
                // Ideally, write_msgfd is reset after first Ctrl Command
                if ret > 0 && self.write_msgfd != 0 {
                    self.write_msgfd = 0;
                }
                ret
            }
            _ => {
                return Err(TPMSocError::WriteTPMSocket(anyhow!(
                    "TPM Socket was not in Connected State"
                )))
            }
        };
        Ok(res)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut newbuf: &mut [u8] = &mut [0; TPM_CRB_BUFFER_MAX];

        if self.stream.is_none() {
            return Err(TPMSocError::ReadTPMSoc(anyhow!(
                "Stream for TPM Socket was not initialized"
            )));
        }
        let mut sock = self.stream.as_ref().unwrap();
        let size: usize = sock.read(&mut newbuf).map_err(|e| {
            TPMSocError::ReadTPMSoc(anyhow!(
                "Failed to read from vTPM Socket. Error Code {:?}",
                e
            ))
        })?;
        buf[0..size].clone_from_slice(&newbuf[0..size]);
        Ok(size)
    }
}
