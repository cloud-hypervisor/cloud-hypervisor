// Copyright © 2022, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::cmp;
use std::path::Path;
use std::sync::{Arc, Barrier};

use anyhow::anyhow;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::layout::{TPM_SIZE, TPM_START};
#[cfg(target_arch = "x86_64")]
use arch::x86_64::layout::{TPM_SIZE, TPM_START};
use log::{debug, error};
use thiserror::Error;
use tpm::TPM_CRB_BUFFER_MAX;
use tpm::emulator::{BackendCmd, Emulator};
use vm_device::BusDevice;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Emulator doesn't implement min required capabilities")]
    CheckCaps(#[source] anyhow::Error),
    #[error("Failed to initialize tpm")]
    Init(#[source] anyhow::Error),
}
type Result<T> = anyhow::Result<T, Error>;

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum LocStateFields {
    TpmEstablished,
    LocAssigned,
    ActiveLocality,
    Reserved,
    TpmRegValidSts,
}

#[derive(Copy, Clone)]
enum LocStsFields {
    Granted,
    BeenSeized,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum IntfIdFields {
    InterfaceType,
    InterfaceVersion,
    CapLocality,
    CapCRBIdleBypass,
    Reserved1,
    CapDataXferSizeSupport,
    CapFIFO,
    CapCRB,
    CapIFRes,
    InterfaceSelector,
    IntfSelLock,
    Reserved2,
    Rid,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
enum IntfId2Fields {
    Vid,
    Did,
}

#[derive(Copy, Clone)]
enum CtrlStsFields {
    TpmSts,
    TpmIdle,
}

#[derive(Copy, Clone)]
enum CrbRegister {
    LocState(LocStateFields),
    LocSts(LocStsFields),
    IntfId(IntfIdFields),
    IntfId2(IntfId2Fields),
    CtrlSts(CtrlStsFields),
}

/* crb 32-bit registers */
const CRB_LOC_STATE: u32 = 0x0;
//Register Fields
// Field => (base, offset, length)
// base:   starting position of the register
// offset: lowest bit in the bit field numbered from 0
// length: length of the bit field
const fn get_crb_loc_state_field(f: LocStateFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        LocStateFields::TpmEstablished => (0, 1),
        LocStateFields::LocAssigned => (1, 1),
        LocStateFields::ActiveLocality => (2, 3),
        LocStateFields::Reserved => (5, 2),
        LocStateFields::TpmRegValidSts => (7, 1),
    };

    (CRB_LOC_STATE, offset, len)
}

const CRB_LOC_CTRL: u32 = 0x08;
const CRB_LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
const CRB_LOC_CTRL_RELINQUISH: u32 = 1 << 1;
const CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT: u32 = 1 << 3;
const CRB_LOC_STS: u32 = 0x0C;

const fn get_crb_loc_sts_field(f: LocStsFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        LocStsFields::Granted => (0, 1),
        LocStsFields::BeenSeized => (1, 1),
    };

    (CRB_LOC_STS, offset, len)
}

const CRB_INTF_ID: u32 = 0x30;
const fn get_crb_intf_id_field(f: IntfIdFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        IntfIdFields::InterfaceType => (0, 4),
        IntfIdFields::InterfaceVersion => (4, 4),
        IntfIdFields::CapLocality => (8, 1),
        IntfIdFields::CapCRBIdleBypass => (9, 1),
        IntfIdFields::Reserved1 => (10, 1),
        IntfIdFields::CapDataXferSizeSupport => (11, 2),
        IntfIdFields::CapFIFO => (13, 1),
        IntfIdFields::CapCRB => (14, 1),
        IntfIdFields::CapIFRes => (15, 2),
        IntfIdFields::InterfaceSelector => (17, 2),
        IntfIdFields::IntfSelLock => (19, 1),
        IntfIdFields::Reserved2 => (20, 4),
        IntfIdFields::Rid => (24, 8),
    };

    (CRB_INTF_ID, offset, len)
}

const CRB_INTF_ID2: u32 = 0x34;
const fn get_crb_intf_id2_field(f: IntfId2Fields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        IntfId2Fields::Vid => (0, 16),
        IntfId2Fields::Did => (16, 16),
    };

    (CRB_INTF_ID2, offset, len)
}

const CRB_CTRL_REQ: u32 = 0x40;
const CRB_CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CRB_CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CRB_CTRL_STS: u32 = 0x44;
const fn get_crb_ctrl_sts_field(f: CtrlStsFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        CtrlStsFields::TpmSts => (0, 1),
        CtrlStsFields::TpmIdle => (1, 1),
    };

    (CRB_CTRL_STS, offset, len)
}
const CRB_CTRL_CANCEL: u32 = 0x48;
const CRB_CANCEL_INVOKE: u32 = 1 << 0;
const CRB_CTRL_START: u32 = 0x4C;
const CRB_START_INVOKE: u32 = 1 << 0;
const CRB_CTRL_CMD_LADDR: u32 = 0x5C;
const CRB_CTRL_CMD_HADDR: u32 = 0x60;
const CRB_CTRL_RSP_SIZE: u32 = 0x64;
const CRB_CTRL_RSP_ADDR: u32 = 0x68;
const CRB_DATA_BUFFER: u32 = 0x80;

const TPM_CRB_NO_LOCALITY: u32 = 0xff;

const TPM_CRB_ADDR_BASE: u32 = TPM_START.0 as u32;
const TPM_CRB_ADDR_SIZE: usize = TPM_SIZE as usize;

const TPM_CRB_R_MAX: usize = CRB_DATA_BUFFER as usize;

// CRB Protocol details
const CRB_INTF_TYPE_CRB_ACTIVE: u32 = 0b1;
const CRB_INTF_VERSION_CRB: u32 = 0b1;
const CRB_INTF_CAP_LOCALITY_0_ONLY: u32 = 0b0;
const CRB_INTF_CAP_IDLE_FAST: u32 = 0b0;
const CRB_INTF_CAP_XFER_SIZE_64: u32 = 0b11;
const CRB_INTF_CAP_FIFO_NOT_SUPPORTED: u32 = 0b0;
const CRB_INTF_CAP_CRB_SUPPORTED: u32 = 0b1;
const CRB_INTF_IF_SELECTOR_CRB: u32 = 0b1;
const PCI_VENDOR_ID_IBM: u32 = 0x1014;
const CRB_CTRL_CMD_SIZE_REG: u32 = 0x58;
const CRB_CTRL_CMD_SIZE: usize = TPM_CRB_ADDR_SIZE - CRB_DATA_BUFFER as usize;

// Returns (register base, offset, len)
const fn get_field(reg: CrbRegister) -> (u32, u32, u32) {
    match reg {
        CrbRegister::LocState(f) => get_crb_loc_state_field(f),
        CrbRegister::LocSts(f) => get_crb_loc_sts_field(f),
        CrbRegister::IntfId(f) => get_crb_intf_id_field(f),
        CrbRegister::IntfId2(f) => get_crb_intf_id2_field(f),
        CrbRegister::CtrlSts(f) => get_crb_ctrl_sts_field(f),
    }
}

// Set a particular field in a Register
fn set_reg_field(regs: &mut [u32; TPM_CRB_R_MAX], reg: CrbRegister, value: u32) {
    let (base, offset, len) = get_field(reg);
    let mask = (!(0_u32) >> (32 - len)) << offset;
    regs[base as usize] = (regs[base as usize] & !mask) | ((value << offset) & mask);
}

// Get the value of a particular field in a Register
const fn get_reg_field(regs: &[u32; TPM_CRB_R_MAX], reg: CrbRegister) -> u32 {
    let (base, offset, len) = get_field(reg);
    let mask = (!(0_u32) >> (32 - len)) << offset;
    (regs[base as usize] & mask) >> offset
}

fn locality_from_addr(addr: u32) -> u8 {
    (addr >> 12) as u8
}

fn update_reg(regs: &mut [u32; TPM_CRB_R_MAX], offset: u32, data: &[u8]) -> u32 {
    let reg_offset = (offset & !0x3) as usize;
    let byte_offset = (offset & 0x3) as usize;
    let mut input = [0; 4];

    input[..data.len()].copy_from_slice(data);
    let value = u32::from_le_bytes(input);
    let mask = (u32::MAX >> (32 - data.len() * 8)) << (byte_offset * 8);

    regs[reg_offset] = (regs[reg_offset] & !mask) | ((value << (byte_offset * 8)) & mask);
    regs[reg_offset]
}

fn read_reg_value(value: u32, offset: u32) -> u32 {
    let byte_offset = (offset & 0x3) as usize;

    value >> (byte_offset * 8)
}

#[cfg(test)]
fn read_reg(regs: &[u32; TPM_CRB_R_MAX], offset: u32) -> u32 {
    let reg_offset = (offset & !0x3) as usize;

    read_reg_value(regs[reg_offset], offset)
}

fn complete_request(regs: &mut [u32; TPM_CRB_R_MAX], success: bool) {
    regs[CRB_CTRL_START as usize] &= !CRB_START_INVOKE;
    if !success {
        set_reg_field(regs, CrbRegister::CtrlSts(CtrlStsFields::TpmSts), 1);
    }
}

fn data_buffer_range(offset: u32, len: usize, buffer_len: usize) -> Option<std::ops::Range<usize>> {
    let end_offset = offset.checked_add(len as u32)?;
    let buffer_end = CRB_DATA_BUFFER.checked_add(buffer_len as u32)?;

    if offset >= CRB_DATA_BUFFER && end_offset <= buffer_end {
        let start = (offset - CRB_DATA_BUFFER) as usize;
        Some(start..start + len)
    } else {
        None
    }
}

pub struct Tpm {
    emulator: Emulator,
    regs: [u32; TPM_CRB_R_MAX],
    backend_buff_size: usize,
    data_buff: [u8; TPM_CRB_BUFFER_MAX],
    data_buff_len: usize,
}

impl Tpm {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let emulator = Emulator::new(path)
            .map_err(|e| Error::Init(anyhow!("Failed while initializing tpm Emulator: {e:?}")))?;
        let mut tpm = Tpm {
            emulator,
            regs: [0; TPM_CRB_R_MAX],
            backend_buff_size: TPM_CRB_BUFFER_MAX,
            data_buff: [0; TPM_CRB_BUFFER_MAX],
            data_buff_len: 0,
        };
        tpm.reset()?;
        Ok(tpm)
    }

    fn get_active_locality(&mut self) -> u32 {
        if get_reg_field(
            &self.regs,
            CrbRegister::LocState(LocStateFields::LocAssigned),
        ) == 0
        {
            return TPM_CRB_NO_LOCALITY;
        }
        get_reg_field(
            &self.regs,
            CrbRegister::LocState(LocStateFields::ActiveLocality),
        )
    }

    fn request_completed(&mut self, success: bool) {
        complete_request(&mut self.regs, success);
    }

    fn reset(&mut self) -> Result<()> {
        let cur_buff_size = self.emulator.get_buffer_size();
        self.regs = [0; TPM_CRB_R_MAX];
        set_reg_field(
            &mut self.regs,
            CrbRegister::LocState(LocStateFields::TpmRegValidSts),
            1,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
            1,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceType),
            CRB_INTF_TYPE_CRB_ACTIVE,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceVersion),
            CRB_INTF_VERSION_CRB,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapLocality),
            CRB_INTF_CAP_LOCALITY_0_ONLY,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapCRBIdleBypass),
            CRB_INTF_CAP_IDLE_FAST,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapDataXferSizeSupport),
            CRB_INTF_CAP_XFER_SIZE_64,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapFIFO),
            CRB_INTF_CAP_FIFO_NOT_SUPPORTED,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapCRB),
            CRB_INTF_CAP_CRB_SUPPORTED,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceSelector),
            CRB_INTF_IF_SELECTOR_CRB,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::Rid),
            0b0000,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId2(IntfId2Fields::Vid),
            PCI_VENDOR_ID_IBM,
        );

        self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = CRB_CTRL_CMD_SIZE as u32;
        self.regs[CRB_CTRL_CMD_LADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;
        self.regs[CRB_CTRL_RSP_SIZE as usize] = CRB_CTRL_CMD_SIZE as u32;
        self.regs[CRB_CTRL_RSP_ADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;

        self.backend_buff_size = cmp::min(cur_buff_size, TPM_CRB_BUFFER_MAX);

        if let Err(e) = self.emulator.startup_tpm(self.backend_buff_size) {
            return Err(Error::Init(anyhow!(
                "Failed while running Startup TPM. Error: {e:?}"
            )));
        }
        Ok(())
    }
}

impl BusDevice for Tpm {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let mut offset: u32 = offset as u32;
        let read_len: usize = data.len();

        if let Some(range) = data_buffer_range(offset, read_len, self.data_buff.len()) {
            // Read from Data Buffer
            data[..].clone_from_slice(&self.data_buff[range]);
        } else {
            offset &= 0xff;
            let reg_offset = offset & !0x3;
            let mut val = self.regs[reg_offset as usize];

            // Per the TCG PC Client Platform TPM Profile (PTP) spec, bit 0
            // of TPM_LOC_STATE_x is `tpmEstablished`. Reflect the live value
            // from the backend rather than the (zero-initialised) shadow.
            if reg_offset == CRB_LOC_STATE && self.emulator.get_established_bit() {
                val |= 0x1;
            }
            val = read_reg_value(val, offset);

            if data.len() <= 4 {
                data.clone_from_slice(val.to_ne_bytes()[0..read_len].as_ref());
            } else {
                error!(
                    "Invalid tpm read: offset {:#X}, data length {:?}",
                    offset,
                    data.len()
                );
            }
        }
        debug!(
            "MMIO Read: offset {:#X} len {:?} val = {:02X?}  ",
            offset,
            data.len(),
            data
        );
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        debug!(
            "MMIO Write: offset {:#X} len {:?} input data {:02X?}",
            offset,
            data.len(),
            data
        );
        let mut offset: u32 = offset as u32;
        if offset < CRB_DATA_BUFFER {
            offset &= 0xff;
        }
        let locality = locality_from_addr(offset) as u32;
        let write_len = data.len();

        if let Some(range) = data_buffer_range(offset, write_len, self.data_buff.len()) {
            let start = range.start;
            if start == 0 {
                // If filling data_buff at index 0, reset length to 0
                self.data_buff_len = 0;
                self.data_buff.fill(0);
            }
            self.data_buff[range].clone_from_slice(data);
            self.data_buff_len += data.len();
        } else {
            // Ctrl Commands that take more than 4 bytes as input are not yet supported
            // CTRL_RSP_ADDR usually gets 8 byte write request. Last 4 bytes are zeros.
            if write_len > 4 && offset != CRB_CTRL_RSP_ADDR {
                error!(
                    "Invalid tpm write: offset {:#X}, data length {}",
                    offset,
                    data.len()
                );
                return None;
            }

            let write_offset = offset;
            let reg_data_len = cmp::min(write_len, 4 - (offset as usize & 0x3));
            let mut input = [0; 4];
            input[..reg_data_len].copy_from_slice(&data[..reg_data_len]);
            let v = u32::from_le_bytes(input) << ((offset & 0x3) * 8);
            offset &= !0x3;

            match offset {
                CRB_CTRL_CMD_SIZE_REG => {
                    update_reg(&mut self.regs, write_offset, &data[..reg_data_len]);
                }
                CRB_CTRL_CMD_LADDR => {
                    update_reg(&mut self.regs, write_offset, &data[..reg_data_len]);
                }
                CRB_CTRL_CMD_HADDR => {
                    update_reg(&mut self.regs, write_offset, &data[..reg_data_len]);
                }
                CRB_CTRL_RSP_SIZE => {
                    update_reg(&mut self.regs, write_offset, &data[..reg_data_len]);
                }
                CRB_CTRL_RSP_ADDR => {
                    update_reg(&mut self.regs, write_offset, &data[..reg_data_len]);
                }
                CRB_CTRL_REQ => match v {
                    CRB_CTRL_REQ_CMD_READY => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
                            0,
                        );
                    }
                    CRB_CTRL_REQ_GO_IDLE => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
                            1,
                        );
                    }
                    _ => {
                        error!("Invalid value passed to CTRL_REQ register");
                        return None;
                    }
                },
                CRB_CTRL_CANCEL => {
                    if v == CRB_CANCEL_INVOKE
                        && (self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE != 0)
                        && let Err(e) = self.emulator.cancel_cmd()
                    {
                        error!("Failed to run cancel command. Error: {e:?}");
                    }
                }
                CRB_CTRL_START => {
                    if v == CRB_START_INVOKE
                        && ((self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE) == 0)
                        && self.get_active_locality() == locality
                    {
                        self.regs[CRB_CTRL_START as usize] |= CRB_START_INVOKE;

                        let mut cmd = BackendCmd {
                            buffer: &mut self.data_buff,
                            input_len: cmp::min(self.data_buff_len, TPM_CRB_BUFFER_MAX),
                        };

                        let status = self.emulator.deliver_request(&mut cmd).is_ok();

                        self.request_completed(status);
                    }
                }
                CRB_LOC_CTRL => {
                    debug!("CRB_LOC_CTRL locality to write = {locality:?} val = {v:?}");
                    match v {
                        CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT => {}
                        CRB_LOC_CTRL_RELINQUISH => {
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocState(LocStateFields::LocAssigned),
                                0,
                            );
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocSts(LocStsFields::Granted),
                                0,
                            );
                        }
                        CRB_LOC_CTRL_REQUEST_ACCESS => {
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocSts(LocStsFields::Granted),
                                1,
                            );
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocSts(LocStsFields::BeenSeized),
                                0,
                            );
                            set_reg_field(
                                &mut self.regs,
                                CrbRegister::LocState(LocStateFields::LocAssigned),
                                1,
                            );
                        }
                        _ => {
                            error!("Invalid value to write in CRB_LOC_CTRL {v:#X} ");
                        }
                    }
                }
                _ => {
                    error!(
                        "Invalid tpm write: offset {:#X}, data length {:?}",
                        offset,
                        data.len()
                    );
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_set_get_reg_field() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        set_reg_field(&mut regs, CrbRegister::IntfId(IntfIdFields::Rid), 0xAC);
        assert_eq!(
            get_reg_field(&regs, CrbRegister::IntfId(IntfIdFields::Rid)),
            0xAC,
            concat!("Test: ", stringify!(set_get_reg_field))
        );
    }

    #[test]
    fn test_update_reg_partial_write() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];

        update_reg(&mut regs, CRB_CTRL_CMD_SIZE_REG, &[0x78, 0x56, 0x34, 0x12]);
        update_reg(&mut regs, CRB_CTRL_CMD_SIZE_REG + 1, &[0xaa]);

        assert_eq!(regs[CRB_CTRL_CMD_SIZE_REG as usize], 0x1234_aa78);
    }

    #[test]
    fn test_update_reg_preserves_untouched_byte_lanes() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        regs[CRB_CTRL_CMD_LADDR as usize] = 0x1122_3344;

        update_reg(&mut regs, CRB_CTRL_CMD_LADDR + 1, &[0xaa, 0xbb]);

        assert_eq!(regs[CRB_CTRL_CMD_LADDR as usize], 0x11bb_aa44);
    }

    #[test]
    fn test_read_reg_partial_read_uses_byte_offset() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        regs[CRB_CTRL_CMD_SIZE_REG as usize] = 0x1234_5678;

        assert_eq!(read_reg(&regs, CRB_CTRL_CMD_SIZE_REG + 1) as u8, 0x56);
        assert_eq!(read_reg(&regs, CRB_CTRL_CMD_SIZE_REG + 2) as u16, 0x1234);
        assert_eq!(read_reg_value(0x1, CRB_LOC_STATE + 1) as u8, 0);
    }

    #[test]
    fn test_complete_request_preserves_reserved_bits() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        regs[CRB_CTRL_START as usize] = 0xffff_fffe | CRB_START_INVOKE;

        complete_request(&mut regs, true);

        assert_eq!(regs[CRB_CTRL_START as usize], 0xffff_fffe);
    }

    #[test]
    fn test_complete_request_sets_error_status_on_failure() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        regs[CRB_CTRL_START as usize] = CRB_START_INVOKE;

        complete_request(&mut regs, false);

        assert_eq!(regs[CRB_CTRL_START as usize], 0);
        assert_eq!(
            get_reg_field(&regs, CrbRegister::CtrlSts(CtrlStsFields::TpmSts)),
            1
        );
    }

    #[test]
    fn test_data_buffer_range_accepts_exact_end_access() {
        let start = (TPM_CRB_BUFFER_MAX - 4)..TPM_CRB_BUFFER_MAX;

        assert_eq!(
            data_buffer_range(
                CRB_DATA_BUFFER + TPM_CRB_BUFFER_MAX as u32 - 4,
                4,
                TPM_CRB_BUFFER_MAX
            ),
            Some(start)
        );
        assert_eq!(
            data_buffer_range(
                CRB_DATA_BUFFER + TPM_CRB_BUFFER_MAX as u32 - 3,
                4,
                TPM_CRB_BUFFER_MAX
            ),
            None
        );
    }
}
