// Copyright © 2022, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::socket::SocketDev;
use crate::{Commands, MemberType, Ptm, PtmCap, PtmEst, PtmInit, PtmResult, PtmSetBufferSize};
use crate::{TPM_CRB_BUFFER_MAX, TPM_SUCCESS};
use anyhow::anyhow;
use libc::c_void;
use libc::{sockaddr_storage, socklen_t};
use std::convert::TryInto;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::{mem, ptr};
use thiserror::Error;

const TPM_REQ_HDR_SIZE: usize = 10;

/* capability flags returned by PTM_GET_CAPABILITY */
const PTM_CAP_INIT: u64 = 1;
const PTM_CAP_SHUTDOWN: u64 = 1 << 1;
const PTM_CAP_GET_TPMESTABLISHED: u64 = 1 << 2;
const PTM_CAP_SET_LOCALITY: u64 = 1 << 3;
const PTM_CAP_CANCEL_TPM_CMD: u64 = 1 << 5;
const PTM_CAP_RESET_TPMESTABLISHED: u64 = 1 << 7;
const PTM_CAP_STOP: u64 = 1 << 10;
const PTM_CAP_SET_DATAFD: u64 = 1 << 12;
const PTM_CAP_SET_BUFFERSIZE: u64 = 1 << 13;

///Check if the input command is selftest
///
pub fn is_selftest(input: &[u8]) -> bool {
    if input.len() >= TPM_REQ_HDR_SIZE {
        let ordinal: &[u8; 4] = input[6..6 + 4]
            .try_into()
            .expect("slice with incorrect length");

        return u32::from_ne_bytes(*ordinal).to_be() == 0x143;
    }
    false
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not initialize emulator's backend: {0}")]
    InitializeEmulator(#[source] anyhow::Error),
    #[error("Failed to create data fd to pass to swtpm: {0}")]
    PrepareDataFd(#[source] anyhow::Error),
    #[error("Failed to run Control Cmd: {0}")]
    RunControlCmd(#[source] anyhow::Error),
    #[error("Emulator doesn't implement min required capabilities: {0}")]
    CheckCaps(#[source] anyhow::Error),
    #[error("Emulator failed to deliver request: {0}")]
    DeliverRequest(#[source] anyhow::Error),
    #[error("Emulator failed to send/receive msg on data fd: {0}")]
    SendReceive(#[source] anyhow::Error),
    #[error("Incorrect response to Self Test: {0}")]
    SelfTest(#[source] anyhow::Error),
}

type Result<T> = anyhow::Result<T, Error>;

pub struct BackendCmd<'a> {
    // This buffer is used for both input and output.
    // When used for input, the length of the data is input_len.
    pub buffer: &'a mut [u8],
    pub input_len: usize,
}

pub struct Emulator {
    caps: PtmCap, /* capabilities of the TPM */
    control_socket: SocketDev,
    data_fd: RawFd,
    established_flag_cached: bool,
    established_flag: bool,
}

impl Emulator {
    /// Create Emulator Instance
    ///
    /// # Arguments
    ///
    /// * `path` - A path to the Unix Domain Socket swtpm is listening on
    ///
    pub fn new(path: String) -> Result<Self> {
        if !Path::new(&path).exists() {
            return Err(Error::InitializeEmulator(anyhow!(
                "The input TPM Socket path: {:?} does not exist",
                path
            )));
        }
        let mut socket = SocketDev::new();
        socket.init(path).map_err(|e| {
            Error::InitializeEmulator(anyhow!("Failed while initializing tpm emulator: {:?}", e))
        })?;

        let mut emulator = Self {
            caps: 0,
            control_socket: socket,
            data_fd: -1,
            established_flag_cached: false,
            established_flag: false,
        };

        emulator.prepare_data_fd()?;

        emulator.probe_caps()?;
        if !emulator.check_caps() {
            return Err(Error::InitializeEmulator(anyhow!(
                "Required capabilities not supported by tpm backend"
            )));
        }

        if !emulator.get_established_flag() {
            return Err(Error::InitializeEmulator(anyhow!(
                "TPM not in established state"
            )));
        }

        Ok(emulator)
    }

    /// Create socketpair, assign one socket/FD as data_fd to Control Socket
    /// The other socket/FD will be assigned to msg_fd, which will be sent to swtpm
    /// via CmdSetDatafd control command
    fn prepare_data_fd(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        let mut fds = [-1, -1];
        // SAFETY: FFI calls and return value of the unsafe call is checked
        unsafe {
            let ret = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr());
            if ret == -1 {
                return Err(Error::PrepareDataFd(anyhow!(
                    "Failed to prepare data fd for tpm emulator. Error Code {:?}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        self.control_socket.set_msgfd(fds[1]);
        debug!("data fd to be configured in swtpm = {:?}", fds[1]);
        self.run_control_cmd(Commands::CmdSetDatafd, &mut res, 0, mem::size_of::<u32>())?;
        debug!("data fd in cloud-hypervisor = {:?}", fds[0]);
        self.data_fd = fds[0];

        // SAFETY: FFI calls and return value of the unsafe call is checked
        unsafe {
            let tv = net_gen::iff::timeval {
                tv_sec: 0,
                tv_usec: 100000, // Set recv timeout to 100ms
            };
            let ret = net_gen::setsockopt(
                fds[0],
                net_gen::iff::SOL_SOCKET as i32,
                net_gen::iff::SO_RCVTIMEO as i32,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<net_gen::iff::timeval>() as u32,
            );
            if ret == -1 {
                return Err(Error::PrepareDataFd(anyhow!(
                    "Failed to set receive timeout on data fd socket. Error Code {:?}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        self.control_socket.set_datafd(fds[0]);
        Ok(())
    }

    /// Gather TPM Capabilities and cache them in Emulator
    ///
    fn probe_caps(&mut self) -> Result<()> {
        let mut caps: u64 = 0;
        self.run_control_cmd(
            Commands::CmdGetCapability,
            &mut caps,
            0,
            mem::size_of::<u64>(),
        )?;
        self.caps = caps;
        Ok(())
    }

    /// Check if minimum set of capabitlies are supported
    fn check_caps(&mut self) -> bool {
        /* min. required capabilities for TPM 2.0*/
        let caps: PtmCap = PTM_CAP_INIT
            | PTM_CAP_SHUTDOWN
            | PTM_CAP_GET_TPMESTABLISHED
            | PTM_CAP_SET_LOCALITY
            | PTM_CAP_RESET_TPMESTABLISHED
            | PTM_CAP_SET_DATAFD
            | PTM_CAP_STOP
            | PTM_CAP_SET_BUFFERSIZE;

        if (self.caps & caps) != caps {
            return false;
        }
        true
    }

    ///
    /// # Arguments
    ///
    /// * `cmd` - Control Command to run
    /// * `msg` - Optional msg to be sent along with Control Command
    /// * `msg_len_in` - len of 'msg' in bytes, if passed
    /// * `msg_len_out` - length of expected output from Control Command in bytes
    ///
    fn run_control_cmd(
        &mut self,
        cmd: Commands,
        msg: &mut dyn Ptm,
        msg_len_in: usize,
        msg_len_out: usize,
    ) -> Result<()> {
        debug!("Control Cmd to send : {:02X?}", cmd);

        let cmd_no = (cmd as u32).to_be_bytes();
        let n = mem::size_of::<u32>() + msg_len_in;

        let converted_req = msg.ptm_to_request();
        debug!("converted request: {:02X?}", converted_req);

        let mut buf = Vec::<u8>::with_capacity(n);

        buf.extend(cmd_no);
        buf.extend(converted_req);
        debug!("full Control request {:02X?}", buf);

        let written = self.control_socket.write(&buf).map_err(|e| {
            Error::RunControlCmd(anyhow!(
                "Failed while running {:02X?} Control Cmd. Error: {:?}",
                cmd,
                e
            ))
        })?;

        if written < buf.len() {
            return Err(Error::RunControlCmd(anyhow!(
                "Truncated write while running {:02X?} Control Cmd",
                cmd,
            )));
        }

        // The largest response is 16 bytes so far.
        if msg_len_out > 16 {
            return Err(Error::RunControlCmd(anyhow!(
                "Response size is too large for Cmd {:02X?}, max 16 wanted {}",
                cmd,
                msg_len_out
            )));
        }

        let mut output = [0u8; 16];

        // Every Control Cmd gets atleast a result code in response. Read it
        let read_size = self.control_socket.read(&mut output).map_err(|e| {
            Error::RunControlCmd(anyhow!(
                "Failed while reading response for Control Cmd: {:02X?}. Error: {:?}",
                cmd,
                e
            ))
        })?;

        if msg_len_out != 0 {
            msg.update_ptm_with_response(&output[0..read_size])
                .map_err(|e| {
                    Error::RunControlCmd(anyhow!(
                        "Failed while converting response of Control Cmd: {:02X?} to PTM. Error: {:?}",
                        cmd,
                        e
                    ))
                })?;
        } else {
            // No response expected, only handle return code
            msg.set_member_type(MemberType::Response);
        }

        if msg.get_result_code() != TPM_SUCCESS {
            return Err(Error::RunControlCmd(anyhow!(
                "Control Cmd returned error code : {:?}",
                msg.get_result_code()
            )));
        }
        debug!("Control Cmd Response : {:02X?}", &output[0..read_size]);
        Ok(())
    }

    pub fn get_established_flag(&mut self) -> bool {
        let mut est: PtmEst = PtmEst::new();

        if self.established_flag_cached {
            return self.established_flag;
        }

        if let Err(e) = self.run_control_cmd(
            Commands::CmdGetTpmEstablished,
            &mut est,
            0,
            2 * mem::size_of::<u32>(),
        ) {
            error!(
                "Failed to run CmdGetTpmEstablished Control Cmd. Error: {:?}",
                e
            );
            return false;
        }

        self.established_flag_cached = true;
        self.established_flag = est.resp.bit == 0;

        self.established_flag
    }

    /// Function to write to data socket and read the response from it
    pub fn deliver_request(&mut self, cmd: &mut BackendCmd) -> Result<()> {
        // SAFETY: type "sockaddr_storage" is valid with an all-zero byte-pattern value
        let mut addr: sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<sockaddr_storage>() as socklen_t;
        let isselftest = is_selftest(&cmd.buffer[0..cmd.input_len]);

        debug!(
            "Send cmd: {:02X?}  of len {:?} on data_ioc ",
            cmd.buffer, cmd.input_len
        );

        let data_vecs = [libc::iovec {
            iov_base: cmd.buffer.as_ptr() as *mut libc::c_void,
            iov_len: cmd.input_len,
        }; 1];

        // SAFETY: all zero values from the unsafe method are updated before usage
        let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };
        msghdr.msg_name = ptr::null_mut();
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = data_vecs.as_ptr() as *mut libc::iovec;
        msghdr.msg_iovlen = data_vecs.len() as _;
        msghdr.msg_control = ptr::null_mut();
        msghdr.msg_controllen = 0;
        msghdr.msg_flags = 0;
        // SAFETY: FFI call and the return value of the unsafe method is checked
        unsafe {
            let ret = libc::sendmsg(self.data_fd, &msghdr, 0);
            if ret == -1 {
                return Err(Error::SendReceive(anyhow!(
                    "Failed to send tpm command over Data FD. Error Code {:?}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        let output_len;
        // SAFETY: FFI calls and return value from unsafe method is checked
        unsafe {
            let ret = libc::recvfrom(
                self.data_fd,
                cmd.buffer.as_mut_ptr() as *mut c_void,
                cmd.buffer.len(),
                0,
                &mut addr as *mut libc::sockaddr_storage as *mut libc::sockaddr,
                &mut len as *mut socklen_t,
            );
            if ret == -1 {
                return Err(Error::SendReceive(anyhow!(
                    "Failed to receive response for tpm command over Data FD. Error Code {:?}",
                    std::io::Error::last_os_error()
                )));
            }
            output_len = ret as usize;
        }
        debug!(
            "response = {:02X?} len = {:?} selftest = {:?}",
            cmd.buffer, output_len, isselftest
        );

        if isselftest && output_len < 10 {
            return Err(Error::SelfTest(anyhow!(
                "Self test response should have 10 bytes. Only {:?} returned",
                output_len
            )));
        }

        Ok(())
    }

    pub fn cancel_cmd(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        // Check if emulator implements Cancel Cmd
        if (self.caps & PTM_CAP_CANCEL_TPM_CMD) != PTM_CAP_CANCEL_TPM_CMD {
            return Err(Error::CheckCaps(anyhow!(
                "Emulator does not implement 'Cancel Command' Capability"
            )));
        }
        self.run_control_cmd(
            Commands::CmdCancelTpmCmd,
            &mut res,
            0,
            mem::size_of::<u32>(),
        )?;
        Ok(())
    }

    /// Configure buffersize to use while communicating with swtpm
    fn set_buffer_size(&mut self, wantedsize: usize) -> Result<usize> {
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new(wantedsize as u32);

        self.stop_tpm()?;

        self.run_control_cmd(
            Commands::CmdSetBufferSize,
            &mut psbs,
            mem::size_of::<u32>(),
            4 * mem::size_of::<u32>(),
        )?;

        Ok(psbs.get_bufsize() as usize)
    }

    pub fn startup_tpm(&mut self, buffersize: usize) -> Result<()> {
        let mut init: PtmInit = PtmInit::new();

        if buffersize != 0 {
            let actual_size = self.set_buffer_size(buffersize)?;
            debug!("set tpm buffersize to {:?} during Startup", actual_size);
        }

        self.run_control_cmd(
            Commands::CmdInit,
            &mut init,
            mem::size_of::<u32>(),
            mem::size_of::<u32>(),
        )?;

        Ok(())
    }

    fn stop_tpm(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        self.run_control_cmd(Commands::CmdStop, &mut res, 0, mem::size_of::<u32>())?;

        Ok(())
    }

    pub fn get_buffer_size(&mut self) -> usize {
        self.set_buffer_size(0).unwrap_or(TPM_CRB_BUFFER_MAX)
    }
}
