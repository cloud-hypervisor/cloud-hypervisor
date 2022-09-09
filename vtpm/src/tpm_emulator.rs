// Copyright © 2022, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::socket::SocketDev;
use crate::tpm_ioctl::{
    Commands, MemberType, Ptm, PtmCap, PtmEst, PtmInit, PtmResult, PtmSetBufferSize,
};
use crate::tpm_ioctl::{TPM_CRB_BUFFER_MAX, TPM_SUCCESS};
use anyhow::anyhow;
use nix::sys::socket::{
    recvfrom, sendmsg, socketpair, AddressFamily, MsgFlags, SockFlag, SockType,
};
use nix::sys::uio::IoVec;
use std::convert::TryInto;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;
use thiserror::Error;

const TPM_REQ_HDR_SIZE:usize = 10;

/* capability flags returned by PTM_GET_CAPABILITY */
const PTM_CAP_INIT:u64 = 1;
const PTM_CAP_SHUTDOWN:u64 = 1 << 1;
const PTM_CAP_GET_TPMESTABLISHED:u64 = 1 << 2;
const PTM_CAP_SET_LOCALITY:u64 = 1 << 3;
const PTM_CAP_CANCEL_TPM_CMD:u64 = 1 << 5;
const PTM_CAP_RESET_TPMESTABLISHED:u64 = 1 << 7;
const PTM_CAP_STOP:u64 = 1 << 10;
const PTM_CAP_SET_DATAFD:u64 = 1 << 12;
const PTM_CAP_SET_BUFFERSIZE:u64 = 1 << 13;

///Check if the input command is selftest
///
pub fn tpm_util_is_selftest(input: Vec<u8>, in_len: usize) -> bool {
    if in_len >= TPM_REQ_HDR_SIZE {
        let ordinal: &[u8; 4] = input[6..6 + 4]
            .try_into()
            .expect("tpm_util_is_selftest: slice with incorrect length");

        return u32::from_ne_bytes(*ordinal).to_be() == 0x143;
    }
    false
}

#[derive(Error, Debug)]
pub enum TPMEmuError {
    #[error("Input socket path for TPM Emulator does not exist")]
    TPMSocketPathExists(),
    #[error("Could not initialize TPM Emulator Backend")]
    InitializeTPMEmulator(#[source] anyhow::Error),
    #[error("Failed to create data fd to pass to swtpm")]
    PrepareDataFd(#[source] anyhow::Error),
    #[error("Failed to run Ctrl Cmd: {0}")]
    RunCtrlCmd(#[source] anyhow::Error),
    #[error("TPM Emulator doesn't implement min required capabilities: {0}")]
    CheckCaps(#[source] anyhow::Error),
    #[error("TPM Emulator failed to deliver request: {0}")]
    DeliverRequest(#[source] anyhow::Error),
    #[error("TPM Emulator failed to send/receive msg on data fd: {0}")]
    SendReceive(#[source] anyhow::Error),
}

type Result<T> = anyhow::Result<T, TPMEmuError>;

#[derive(Clone)]
pub struct TPMBackendCmd {
    pub locty: u8,
    pub input: Vec<u8>,
    pub input_len: usize,
    pub output: Vec<u8>,
    pub output_len: usize,
    pub selftest_done: bool,
}

pub struct TPMEmulator {
    had_startup_error: bool,
    cmd: Option<TPMBackendCmd>,
    caps: PtmCap, /* capabilities of the TPM */
    ctrl_soc: SocketDev,
    data_ioc: RawFd,
    established_flag_cached: bool,
    established_flag: bool,
}

impl TPMEmulator {
    /// Create TPMEmulator Instance
    ///
    /// # Arguments
    ///
    /// * `path` - A path to the Unix Domain Socket swtpm is listening on
    ///
    pub fn new(path: String) -> Result<Self> {
        if !Path::new(&path).exists() {
            return Err(TPMEmuError::InitializeTPMEmulator(anyhow!(
                "The input TPM Socket path: {:?} does not exist",
                path
            )));
        }
        let mut tpm_soc = SocketDev::new();
        tpm_soc.init(path).map_err(|e| {
            TPMEmuError::InitializeTPMEmulator(anyhow!(
                "Failed while initializing TPM Emulator: {:?}",
                e
            ))
        })?;

        let mut tmp_emu = Self {
            had_startup_error: false,
            cmd: None,
            caps: 0,
            ctrl_soc: tpm_soc,
            data_ioc: -1,
            established_flag_cached: false,
            established_flag: false,
        };

        tmp_emu.tpm_emulator_prepare_data_fd()?;

        tmp_emu.tpm_emulator_probe_caps()?;
        if !tmp_emu.tpm_emulator_check_caps() {
            tmp_emu.had_startup_error = true;
        }

        if !tmp_emu.get_tpm_established_flag() {
            tmp_emu.had_startup_error = true;
        }

        Ok(tmp_emu)
    }

    /// Create socketpair, assign one socket/FD as data_fd to ctrl Socket
    /// The other socket/FD will be assigned to msg_fd, which will be sent to swtpm
    /// via CmdSetDatafd command
    fn tpm_emulator_prepare_data_fd(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        let (fd1, fd2) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .map_err(|e| {
            TPMEmuError::PrepareDataFd(anyhow!(
                "Failed to prepare data fd for TPM Emulator. Error:  {:?}",
                e
            ))
        })?;

        self.ctrl_soc.set_msgfd(fd2);
        debug!("tpm_emulator: msg_fd to be configured in swtpm = {:?}", fd2);
        self.tpm_emulator_ctrlcmd(Commands::CmdSetDatafd, &mut res, 0, mem::size_of::<u32>())?;
        debug!("tpm_emulator: data fd in cloud-hypervisor = {:?}", fd1);
        self.data_ioc = fd1;
        self.ctrl_soc.set_datafd(fd1);
        Ok(())
    }

    /// Gather TPM Capabilities and cache them in TPM Emulator
    ///
    fn tpm_emulator_probe_caps(&mut self) -> Result<()> {
        let mut caps: u64 = 0;
        self.tpm_emulator_ctrlcmd(
            Commands::CmdGetCapability,
            &mut caps,
            0,
            mem::size_of::<u64>(),
        )?;
        self.caps = caps;
        debug!("tpm_emulator: set tpm capabilities to {:#X}", self.caps);
        Ok(())
    }

    /// Check if minimum set of capabitlies are supported
    fn tpm_emulator_check_caps(&mut self) -> bool {
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
    /// * `cmd` - TPM Ctrl Command to run
    /// * `msg` - Optional msg to be sent along with Ctrl Command
    /// * `msg_len_in` - len of 'msg' in bytes, if passed
    /// * `msg_len_out` - expected length of output from Ctrl Command in bytes
    ///
    fn tpm_emulator_ctrlcmd<'a>(
        &mut self,
        cmd: Commands,
        msg: &'a mut dyn Ptm,
        msg_len_in: usize,
        msg_len_out: usize,
    ) -> Result<()> {
        debug!("tpm_emulator: Ctrl Cmd to send : {:02X?}", cmd);

        let cmd_no = (cmd as u32).to_be_bytes();
        let n: isize = (mem::size_of::<u32>() + msg_len_in) as isize;

        let converted_req = msg.ptm_to_request();
        debug!("tpm_emulator: converted request: {:02X?}", converted_req);

        let mut buf = Vec::<u8>::with_capacity(n as usize);

        buf.extend(cmd_no);
        buf.extend(converted_req);
        debug!("tpm_emulator: full Control request {:02X?}", buf);

        let _res = self.ctrl_soc.write(&mut buf, n as usize).map_err(|e| {
            TPMEmuError::RunCtrlCmd(anyhow!(
                "Failed while running {:02X?} TPM Ctrl Cmd. Error: {:?}",
                cmd,
                e
            ))
        })?;

        let mut output = [0 as u8; TPM_CRB_BUFFER_MAX];

        //Every Ctrl Cmd gets atleast tpm result code in response. Read it
        let read_size = self.ctrl_soc.read(&mut output).map_err(|e| {
            TPMEmuError::RunCtrlCmd(anyhow!(
                "Failed while reading response for Ctrl Cmd: {:02X?}. Error: {:?}",
                cmd,
                e
            ))
        })?;

        if msg_len_out != 0 {
            msg.update_ptm_with_response(&output[0..read_size]).map_err(|e| {
                TPMEmuError::RunCtrlCmd(anyhow!(
                    "Failed while converting response of Ctrl Cmd: {:02X?} to PTM. Error: {:?}",
                    cmd,
                    e
                ))
            })?;
        } else {
            // No response expected, only handle return code
            msg.set_memb_type(MemberType::Response);
        }

        if msg.get_result_code() != TPM_SUCCESS {
            return Err(TPMEmuError::RunCtrlCmd(anyhow!(
                "Ctrl Cmd returned error code : {:?}",
                msg.get_result_code()
            )));
        }
        debug!("tpm_emulator: Ctrl Cmd Response : {:02X?}", &output[0..read_size]);
        Ok(())
    }

    pub fn get_tpm_established_flag(&mut self) -> bool {
        let mut est: PtmEst = PtmEst::new();

        if self.established_flag_cached {
            debug!("tpm_emulator: established_flag already cached");
            return self.established_flag;
        }

        match self.tpm_emulator_ctrlcmd(
            Commands::CmdGetTpmEstablished,
            &mut est,
            0,
            2 * mem::size_of::<u32>(),
        ) {
            Err(e) => {
                error!(
                    "Failed to run CmdGetTpmEstablished Ctrl Cmd. Error: {:?}",
                    e
                );
                return false;
            }
            _ => {}
        }

        self.established_flag_cached = true;
        if est.resp.bit != 0 {
            self.established_flag = true;
            return true;
        } else {
            self.established_flag = false;
            return false;
        }
    }

    /// Function to write to data socket and read the response from it
    fn unix_tx_bufs(&mut self) -> Result<()> {
        let is_selftest: bool;

        if let Some(ref mut cmd) = self.cmd {
            cmd.selftest_done = false;
            is_selftest = tpm_util_is_selftest(cmd.input.to_vec(), cmd.input_len);

            debug!("tpm_emulator: Send cmd: {:02X?}  of len {:?} on data_ioc ", cmd.input, cmd.input_len);

            let iov = &[IoVec::from_slice(cmd.input.as_slice())];
            let _ret = sendmsg(self.data_ioc, iov, &[], MsgFlags::empty(), None).map_err(|e| {
                TPMEmuError::SendReceive(anyhow!(
                    "Failed to send TPM command over Data FD. Error Code: {:?}",
                    e
                ))
            })?;
            cmd.output.fill(0);
            let (size, _) = recvfrom(self.data_ioc, &mut cmd.output).map_err(|e| {
                TPMEmuError::SendReceive(anyhow!(
                    "Failed to receive response for TPM command over Data FD. Erro Code: {:?}",
                    e
                ))
            })?;
            cmd.output_len = size;
            debug!("tpm_emulator: response = {:02X?} len = {:?} selftest = {:?}", cmd.output, cmd.output_len, is_selftest);

            if is_selftest {
                let errcode: &[u8; 4] = cmd.output[6..6 + 4]
                    .try_into()
                    .expect("tpm_util_is_selftest: slice with incorrect length");
                cmd.selftest_done = u32::from_ne_bytes(*errcode).to_be() == 0;
            }
        }

        Ok(())
    }

    pub fn deliver_request(&mut self, in_cmd: &mut TPMBackendCmd) -> Result<Vec<u8>> {
        if !self.cmd.is_none() {
            //previous request did not finish cleanly
           return Err(TPMEmuError::DeliverRequest(anyhow!(
                "Cannot deliver tpm Request, as previous cmd was not completed."
            )));
        }
        self.cmd = Some(in_cmd.clone());

        self.unix_tx_bufs()?;

        let output = self.cmd.as_ref().unwrap().output.clone();
        in_cmd.output.fill(0);
        in_cmd.output.clone_from(&output);

        self.tpm_backend_request_completed();
        return Ok(output);
    }

    pub fn tpm_backend_request_completed(&mut self) {
        self.cmd = None;
    }

    pub fn cancel_cmd(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        // Check if emulator implements Cancel Cmd
        if (self.caps & PTM_CAP_CANCEL_TPM_CMD) != PTM_CAP_CANCEL_TPM_CMD {
            return Err(TPMEmuError::CheckCaps(anyhow!(
                "Emulator does not implement 'Cancel Command' Capability"
            )));
        }
        self.tpm_emulator_ctrlcmd(
            Commands::CmdCancelTpmCmd,
            &mut res,
            0,
            mem::size_of::<u32>(),
        )?;
        Ok(())
    }

    /// Configure buffersize to use while communicating with swtpm
    fn tpm_emulator_set_buffer_size(
        &mut self,
        wantedsize: usize,
        actualsize: &mut usize,
    ) -> Result<()> {
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new(wantedsize as u32);

        self.tpm_emulator_stop_tpm()?;

        self.tpm_emulator_ctrlcmd(
            Commands::CmdSetBufferSize,
            &mut psbs,
            mem::size_of::<u32>(),
            4 * mem::size_of::<u32>(),
        )?;

        *actualsize = psbs.get_bufsize() as usize;

        Ok(())
    }

    pub fn tpm_emulator_startup_tpm(&mut self, buffersize: usize) -> Result<()> {
        let mut init: PtmInit = PtmInit::new();

        let mut actual_size: usize = 0;

        if buffersize != 0 {
            self.tpm_emulator_set_buffer_size(buffersize, &mut actual_size)?;
            debug!("tpm_emulator: set tpm buffersize to {:?} during Startup",
                buffersize
            );
        }

        self.tpm_emulator_ctrlcmd(
            Commands::CmdInit,
            &mut init,
            mem::size_of::<u32>(),
            mem::size_of::<u32>(),
        )?;

        Ok(())
    }

    fn tpm_emulator_stop_tpm(&mut self) -> Result<()> {
        let mut res: PtmResult = 0;

        self.tpm_emulator_ctrlcmd(Commands::CmdStop, &mut res, 0, mem::size_of::<u32>())?;

        Ok(())
    }

    pub fn get_buffer_size(&mut self) -> Result<usize> {
        let mut curr_buf_size: usize = 0;

        match self.tpm_emulator_set_buffer_size(0, &mut curr_buf_size) {
            Err(_) => {
                return Ok(TPM_CRB_BUFFER_MAX);
            }
            _ => return Ok(curr_buf_size),
        }
    }
}
