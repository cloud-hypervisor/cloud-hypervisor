// Copyright © 2022, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use std::convert::TryInto;
use thiserror::Error;

pub const TPM_CRB_BUFFER_MAX: usize = 3968; // 0x1_000 - 0x80
pub const TPM_SUCCESS:u32 = 0x0;

/*
 * Structures required to process Request and Responses of Control commands
 * used by control channel over UNIX socket interface
 *
 * All messages contain big-endian data.
 *
 * Reference: https://github.com/stefanberger/swtpm/blob/master/man/man3/swtpm_ioctls.pod
 */
#[derive(Debug, Clone, Copy)]
pub enum Commands {
    CmdGetCapability = 1,
    CmdInit,                // 2
    CmdShutdown,            // 3
    CmdGetTpmEstablished,   // 4
    CmdSetLocality,         // 5
    CmdHashStart,           // 6
    CmdHashData,            // 7
    CmdHashEnd,             // 8
    CmdCancelTpmCmd,        // 9
    CmdStoreVolatile,       // 10
    CmdResetTpmEstablished, // 11
    CmdGetStateBlob,        // 12
    CmdSetStateBlob,        // 13
    CmdStop,                // 14
    CmdGetConfig,           // 15
    CmdSetDatafd,           // 16
    CmdSetBufferSize,       // 17
}

#[derive(Error, Debug)]
pub enum TPMIocError {
    #[error("Failed converting buf to PTM : {0}")]
    ConvertToPtm(#[source] anyhow::Error),
}
type Result<T> = anyhow::Result<T, TPMIocError>;

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum MemberType {
    Request,
    Response,
    Error,
    Cap,
}

pub trait Ptm {
    // Get Member Type
    fn get_memb_type(&self) -> MemberType;

    // Set Member Type
    fn set_memb_type(&mut self, mem: MemberType);

    // Convert PTM Request to bytes to be sent to TPM
    fn ptm_to_request(&self) -> Vec<u8>;

    // Update PTM from TPM's reponse
    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()>;

    // Update tpm result
    fn set_res(&mut self, res: u32);

    fn get_result_code(&self) -> u32;
}

/*
 * Every response for a TPM Control Command execution must hold TPM return
 * code (PtmResult) as its first element.
 * Based on the type of input Control Command additional data could be
 * appended to the response.
 */
pub type PtmResult = u32;

impl Ptm for PtmResult {
    fn ptm_to_request(&self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_memb_type(&self) -> MemberType {
        MemberType::Response
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() < 4 {
            return Err(TPMIocError::ConvertToPtm(anyhow!(
                "PtmRes buffer is of insufficient length. Buffer length should be atleast 4"
            )));
        }

        *self = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        Ok(())
    }

    fn set_memb_type(&mut self, _mem: MemberType) {}

    fn set_res(&mut self, res: u32) {
        *self = res;
    }

    fn get_result_code(&self) -> u32 {
        return *self;
    }
}

/* GET_CAPABILITY Response */
pub type PtmCap = u64;
impl Ptm for PtmCap {
    fn ptm_to_request(&self) -> Vec<u8> {
        //TPM's GetCapability call doesn't need any supporting message
        // Return an empty Buffer
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_memb_type(&self) -> MemberType {
        MemberType::Cap
    }

    fn update_ptm_with_response(&mut self, mut buf: &[u8]) -> Result<()> {
        let buf_len = buf.len();
        if buf_len != 8 {
            return Err(TPMIocError::ConvertToPtm(anyhow!(
                "Response for GetCapability cmd is of incorrect length: {:?}. Response buffer should be 8 bytes long",
            buf_len)));
        }
        *self = buf.read_u64::<BigEndian>().unwrap();
        Ok(())
    }

    fn set_memb_type(&mut self, _mem: MemberType) {}

    fn set_res(&mut self, _res: u32) {}

    fn get_result_code(&self) -> u32 {
        return ((*self) >> 32) as u32;
    }
}

/* GET_TPMESTABLISHED Reponse */
#[derive(Debug)]
pub struct PtmEstResp {
    pub bit: u8,
}

#[derive(Debug)]
pub struct PtmEst {
    member: MemberType,
    pub resp: PtmEstResp,
    pub tpm_result: PtmResult,
}

impl PtmEst {
    pub fn new() -> Self {
        Self {
            member: MemberType::Response,
            tpm_result: 0,
            resp: PtmEstResp { bit: 0 },
        }
    }
}

impl Ptm for PtmEst {
    fn ptm_to_request(&self) -> Vec<u8> {
        //TPM's GetTpmEstablished call doesn't need any supporting message
        // Return an empty Buffer
        let buf: Vec<u8> = Vec::<u8>::new();
        buf
    }

    fn get_memb_type(&self) -> MemberType {
        self.member
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() < 5 {
            return Err(TPMIocError::ConvertToPtm(anyhow!(
                "Response for GetTpmEstablished cmd is of incorrect length. Response buffer should be 5 bytes long"
            )));
        }
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        let bit = &buf[4];
        self.resp.bit = *bit;
        Ok(())
    }

    fn set_memb_type(&mut self, _mem: MemberType) {}

    fn set_res(&mut self, res: u32) {
        self.tpm_result = res
    }

    fn get_result_code(&self) -> u32 {
        return self.tpm_result;
    }
}

/* INIT Response */

#[derive(Debug)]
pub struct PtmInit {
    pub member: MemberType,
    /* request */
    pub init_flags: u32,
    /* response */
    pub tpm_result: PtmResult,
}

impl PtmInit {
    pub fn new() -> Self {
        Self {
            member: MemberType::Request,
            init_flags: 0,
            tpm_result: 0,
        }
    }
}

impl Ptm for PtmInit {
    fn ptm_to_request(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.init_flags.to_be_bytes());
        buf
    }

    fn get_memb_type(&self) -> MemberType {
        self.member
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() != 4 {
            return Err(TPMIocError::ConvertToPtm(anyhow!(
                "Response for Init cmd is of incorrect length. Response buffer should be 4 bytes long"
            )));
        }
        self.set_memb_type(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());
        Ok(())
    }

    fn set_memb_type(&mut self, mem: MemberType) {
        self.member = mem
    }

    fn set_res(&mut self, res: u32) {
        self.tpm_result = res
    }

    fn get_result_code(&self) -> u32 {
        return self.tpm_result;
    }
}

/*
 * PTM_SET_BUFFERSIZE: Set the buffer size to be used by the TPM.
 * A 0 on input queries for the current buffer size. Any other
 * number will try to set the buffer size. The returned number is
 * the buffer size that will be used, which can be larger than the
 * requested one, if it was below the minimum, or smaller than the
 * requested one, if it was above the maximum.
 *
 * SET_BUFFERSIZE Response
 */
#[derive(Debug)]
pub struct PtmSBSReq {
    buffersize: u32,
}

#[derive(Debug)]
pub struct PtmSBSResp {
    bufsize: u32,
    minsize: u32,
    maxsize: u32,
}

#[derive(Debug)]
pub struct PtmSetBufferSize {
    pub mem: MemberType,
    /* request */
    pub req: PtmSBSReq,
    /* response */
    pub resp: PtmSBSResp,
    pub tpm_result: PtmResult,
}

impl PtmSetBufferSize {
    pub fn new(req_buffsize: u32) -> Self {
        Self {
            mem: MemberType::Request,
            req: PtmSBSReq {
                buffersize: req_buffsize,
            },
            resp: PtmSBSResp {
                bufsize: 0,
                minsize: 0,
                maxsize: 0,
            },
            tpm_result: 0,
        }
    }
    pub fn get_bufsize(&self) -> u32{
        return self.resp.bufsize;
    }
}

impl Ptm for PtmSetBufferSize {
    fn ptm_to_request(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::<u8>::new();
        buf.extend_from_slice(&self.req.buffersize.to_be_bytes());
        buf
    }

    fn get_memb_type(&self) -> MemberType {
        self.mem
    }

    fn update_ptm_with_response(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() != 16 {
            return Err(TPMIocError::ConvertToPtm(anyhow!(
                "Response for CmdSetBufferSize cmd is of incorrect length. Response buffer should be 16 bytes long"
            )));
        }
        self.set_memb_type(MemberType::Response);
        let mut res = &buf[0..4];
        self.set_res(res.read_u32::<BigEndian>().unwrap());

        let mut bufsize = &buf[4..8];
        self.resp.bufsize = bufsize.read_u32::<BigEndian>().unwrap();

        let mut minsize = &buf[8..12];
        self.resp.minsize = minsize.read_u32::<BigEndian>().unwrap();

        let mut maxsize = &buf[12..16];
        self.resp.maxsize = maxsize.read_u32::<BigEndian>().unwrap();

        Ok(())
    }

    fn set_memb_type(&mut self, mem: MemberType) {
        self.mem = mem
    }

    fn set_res(&mut self, res: u32) {
        self.tpm_result = res
    }

    fn get_result_code(&self) -> u32 {
        return self.tpm_result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ptmresult() -> Result<()> {
        debug!("PtmResult Testing");
        let buf: &[u8] = &[0, 0, 0, 1];
        let mut result_code: PtmResult = 0;
        result_code.update_ptm_with_response(buf)?;
        assert_eq!(result_code.get_result_code(), 0x1);
        Ok(())
    }
    #[test]
    fn test_ptmcap() -> Result<()> {
        debug!("PtmCap Testing");
        let mut cap: PtmCap = 0x0;
        let buf: &[u8] = &[0, 0, 0, 0xE, 0, 0, 0xFF, 0xFF];
        cap.update_ptm_with_response(&buf)?;
        assert_eq!(cap.get_result_code(), 0xE);
        Ok(())
    }
    #[test]
    fn test_ptmest() -> Result<()> {
        debug!("PtmEst Testing");
        let mut est: PtmEst = PtmEst::new();
        let buf: &[u8] = &[0, 0, 0xE, 0, 0xC, 0, 1, 1];
        est.update_ptm_with_response(buf)?;
        assert_eq!(est.get_result_code(), 0xE00);
        assert_eq!(est.resp.bit, 0xC);
        Ok(())
    }
    #[test]
    /*PtmInit Testing */
    fn test_ptminit() -> Result<()> {
        debug!("PtmInit Testing");
        let mut init: PtmInit = PtmInit::new();
        init.init_flags = 0x1;
        let buf = init.ptm_to_request();
        assert_eq!(buf, [0x0, 0x0, 0x0, 0x1]);
        let response_buf: &[u8] = &[0, 0, 0xE, 0];
        init.update_ptm_with_response(response_buf)?;
        assert_eq!(init.get_result_code(), 0xE00);
        Ok(())
    }
    #[test]
    /* PtmSetBufferSize Testing */
    fn test_ptmsetbuffersize() -> Result<()> {
        debug!("PtmSetBufferSize Testing");
        let mut psbs: PtmSetBufferSize = PtmSetBufferSize::new(1024);
        // Member type should be Request after initialization
        assert_eq!(psbs.get_memb_type(), MemberType::Request);
        let buf: &[u8] = &[
            0, 0x12, 0x34, 0x56, 0, 0, 0, 0xA, 0, 0, 0, 0xB, 0, 0, 0, 0xC,
        ];
        psbs.update_ptm_with_response(&buf)?;
        assert_eq!(psbs.get_memb_type(), MemberType::Response);
        assert_eq!(psbs.get_result_code(), 0x123456);
        assert_eq!(psbs.resp.bufsize, 0xA);
        assert_eq!(psbs.resp.minsize, 0xB);
        assert_eq!(psbs.resp.maxsize, 0xC);
        Ok(())
    }
}
