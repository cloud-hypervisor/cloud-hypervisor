// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use std::sync::Arc;
use std::{io, result};

use log::{debug, error};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_device::interrupt::{
    InterruptIndex, InterruptSourceConfig, InterruptSourceGroup, MsiIrqSourceConfig,
};
use vm_migration::{MigratableError, Pausable, Snapshot, Snapshottable};

// MSI control masks
const MSI_CTL_ENABLE: u16 = 0x1;
const MSI_CTL_MULTI_MSG_CAPABLE: u16 = 0xe;
const MSI_CTL_MULTI_MSG_ENABLE: u16 = 0x70;
const MSI_CTL_64_BITS: u16 = 0x80;
const MSI_CTL_PER_VECTOR: u16 = 0x100;

// Largest "Multiple Message Capable" and "Multiple Message Enable" encoding
// defined by the PCI specification: 2^5, i.e. 32 vectors.
const MSI_MULTI_MSG_ENC_MAX: u16 = 0b101;

// MSI message offsets
const MSI_MSG_CTL_OFFSET: u64 = 0x2;
const MSI_MSG_ADDR_LO_OFFSET: u64 = 0x4;

// MSI message masks
const MSI_MSG_ADDR_LO_MASK: u32 = 0xffff_fffc;

/// Number of vectors the driver has requested, taken from the "Multiple
/// Message Enable" field. Reserved encodings are read as the architectural
/// maximum.
pub fn msi_num_enabled_vectors(msg_ctl: u16) -> usize {
    let field = ((msg_ctl & MSI_CTL_MULTI_MSG_ENABLE) >> 4).min(MSI_MULTI_MSG_ENC_MAX);

    1 << field
}

/// Number of vectors the device reports it is able to request, taken from the
/// read-only "Multiple Message Capable" field. "Multiple Message Enable"
/// cannot exceed it, so this is how many vectors the device may end up using.
pub fn msi_num_capable_vectors(msg_ctl: u16) -> usize {
    let field = ((msg_ctl & MSI_CTL_MULTI_MSG_CAPABLE) >> 1).min(MSI_MULTI_MSG_ENC_MAX);

    1 << field
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed enabling the interrupt route")]
    EnableInterruptRoute(#[source] io::Error),
    #[error("Failed updating the interrupt route")]
    UpdateInterruptRoute(#[source] io::Error),
}

pub(crate) const MSI_CONFIG_ID: &str = "msi_config";

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
pub struct MsiCap {
    // Message Control Register
    //   0:     MSI enable.
    //   3-1;   Multiple message capable.
    //   6-4:   Multiple message enable.
    //   7:     64 bits address capable.
    //   8:     Per-vector masking capable.
    //   15-9:  Reserved.
    pub msg_ctl: u16,
    // Message Address (LSB)
    //   1-0:  Reserved.
    //   31-2: Message address.
    pub msg_addr_lo: u32,
    // Message Upper Address (MSB)
    //   31-0: Message address.
    pub msg_addr_hi: u32,
    // Message Data
    //   15-0: Message data.
    pub msg_data: u16,
    // Mask Bits
    //   31-0: Mask bits.
    pub mask_bits: u32,
    // Pending Bits
    //   31-0: Pending bits.
    pub pending_bits: u32,
}

impl MsiCap {
    fn addr_64_bits(&self) -> bool {
        self.msg_ctl & MSI_CTL_64_BITS == MSI_CTL_64_BITS
    }

    fn per_vector_mask(&self) -> bool {
        self.msg_ctl & MSI_CTL_PER_VECTOR == MSI_CTL_PER_VECTOR
    }

    fn enabled(&self) -> bool {
        self.msg_ctl & MSI_CTL_ENABLE == MSI_CTL_ENABLE
    }

    fn num_enabled_vectors(&self) -> usize {
        msi_num_enabled_vectors(self.msg_ctl)
    }

    fn vector_masked(&self, vector: usize) -> bool {
        if !self.per_vector_mask() {
            return false;
        }

        (self.mask_bits >> vector) & 0x1 == 0x1
    }

    fn size(&self) -> u64 {
        let mut size: u64 = 0xa;

        if self.addr_64_bits() {
            size += 0x4;
        }
        if self.per_vector_mask() {
            size += 0xa;
        }

        size
    }

    /// Applies a guest write to "Message Control", keeping the read-only bits
    /// and capping "Multiple Message Enable" at "Multiple Message Capable",
    /// which the PCI specification requires of the driver.
    fn set_msg_ctl(&mut self, value: u16) {
        let capable = (self.msg_ctl & MSI_CTL_MULTI_MSG_CAPABLE) >> 1;
        let enable = ((value & MSI_CTL_MULTI_MSG_ENABLE) >> 4).min(capable);

        self.msg_ctl = (self.msg_ctl & !(MSI_CTL_ENABLE | MSI_CTL_MULTI_MSG_ENABLE))
            | (value & MSI_CTL_ENABLE)
            | (enable << 4);
    }

    fn update(&mut self, offset: u64, data: &[u8]) {
        // Calculate message data offset depending on the address being 32 or
        // 64 bits.
        // Calculate upper address offset if the address is 64 bits.
        // Calculate mask bits offset based on the address being 32 or 64 bits
        // and based on the per vector masking being enabled or not.
        let (msg_data_offset, addr_hi_offset, mask_bits_offset): (u64, Option<u64>, Option<u64>) =
            if self.addr_64_bits() {
                let mask_bits = if self.per_vector_mask() {
                    Some(0x10)
                } else {
                    None
                };
                (0xc, Some(0x8), mask_bits)
            } else {
                let mask_bits = if self.per_vector_mask() {
                    Some(0xc)
                } else {
                    None
                };
                (0x8, None, mask_bits)
            };

        // Update cache without overriding the read-only bits.
        match data.len() {
            2 => {
                let value = u16::from_le_bytes(*data.as_array().expect("data should be 2 bytes"));
                match offset {
                    MSI_MSG_CTL_OFFSET => self.set_msg_ctl(value),
                    x if x == msg_data_offset => self.msg_data = value,
                    _ => debug!("invalid offset"),
                }
            }
            4 => {
                let value = u32::from_le_bytes(*data.as_array().expect("data should be 4 bytes"));
                match offset {
                    0x0 => self.set_msg_ctl((value >> 16) as u16),
                    MSI_MSG_ADDR_LO_OFFSET => self.msg_addr_lo = value & MSI_MSG_ADDR_LO_MASK,
                    x if x == msg_data_offset => self.msg_data = value as u16,
                    x if addr_hi_offset.is_some() && x == addr_hi_offset.unwrap() => {
                        self.msg_addr_hi = value;
                    }
                    x if mask_bits_offset.is_some() && x == mask_bits_offset.unwrap() => {
                        self.mask_bits = value;
                    }
                    _ => debug!("invalid offset"),
                }
            }
            _ => debug!("invalid data length"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MsiConfigState {
    cap: MsiCap,
}

pub struct MsiConfig {
    pub cap: MsiCap,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
}

impl MsiConfig {
    pub fn new(
        msg_ctl: u16,
        interrupt_source_group: Arc<dyn InterruptSourceGroup>,
        state: Option<MsiConfigState>,
    ) -> Result<Self, Error> {
        let cap = if let Some(state) = state {
            if state.cap.enabled() {
                for idx in 0..state.cap.num_enabled_vectors() {
                    let config = MsiIrqSourceConfig {
                        high_addr: state.cap.msg_addr_hi,
                        low_addr: state.cap.msg_addr_lo,
                        data: state.cap.msg_data as u32,
                        devid: 0,
                    };

                    interrupt_source_group
                        .update(
                            idx as InterruptIndex,
                            InterruptSourceConfig::MsiIrq(config),
                            state.cap.vector_masked(idx),
                            false,
                        )
                        .map_err(Error::UpdateInterruptRoute)?;
                }

                interrupt_source_group
                    .set_gsi()
                    .map_err(Error::EnableInterruptRoute)?;

                interrupt_source_group
                    .enable()
                    .map_err(Error::EnableInterruptRoute)?;
            }

            state.cap
        } else {
            MsiCap {
                msg_ctl,
                ..Default::default()
            }
        };

        Ok(MsiConfig {
            cap,
            interrupt_source_group,
        })
    }

    fn state(&self) -> MsiConfigState {
        MsiConfigState { cap: self.cap }
    }

    pub fn enabled(&self) -> bool {
        self.cap.enabled()
    }

    pub fn size(&self) -> u64 {
        self.cap.size()
    }

    pub fn num_enabled_vectors(&self) -> usize {
        self.cap.num_enabled_vectors()
    }

    pub fn update(&mut self, offset: u64, data: &[u8]) {
        let old_enabled = self.cap.enabled();

        self.cap.update(offset, data);

        if self.cap.enabled() {
            for idx in 0..self.num_enabled_vectors() {
                let config = MsiIrqSourceConfig {
                    high_addr: self.cap.msg_addr_hi,
                    low_addr: self.cap.msg_addr_lo,
                    data: self.cap.msg_data as u32,
                    devid: 0,
                };

                if let Err(e) = self.interrupt_source_group.update(
                    idx as InterruptIndex,
                    InterruptSourceConfig::MsiIrq(config),
                    self.cap.vector_masked(idx),
                    true,
                ) {
                    error!("Failed updating vector: {e:?}");
                }
            }

            if !old_enabled && let Err(e) = self.interrupt_source_group.enable() {
                error!("Failed enabling irq_fd: {e:?}");
            }
        } else if old_enabled && let Err(e) = self.interrupt_source_group.disable() {
            error!("Failed disabling irq_fd: {e:?}");
        }
    }
}

impl Pausable for MsiConfig {}

impl Snapshottable for MsiConfig {
    fn id(&self) -> String {
        String::from(MSI_CONFIG_ID)
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // "Multiple Message Capable" == 2, so the device can request 4 vectors.
    const MMC_FOUR_VECTORS: u16 = 2 << 1;

    #[test]
    fn enabled_vectors_come_from_the_enable_field() {
        assert_eq!(msi_num_enabled_vectors(0), 1);
        assert_eq!(msi_num_enabled_vectors(2 << 4), 4);
        // Reserved encodings are capped at the architectural maximum.
        assert_eq!(msi_num_enabled_vectors(MSI_CTL_MULTI_MSG_ENABLE), 32);
    }

    #[test]
    fn capable_vectors_come_from_the_capable_field() {
        assert_eq!(msi_num_capable_vectors(0), 1);
        assert_eq!(msi_num_capable_vectors(MMC_FOUR_VECTORS), 4);
        // "Multiple Message Enable" does not change the capability.
        let enabled = MMC_FOUR_VECTORS | MSI_CTL_MULTI_MSG_ENABLE;
        assert_eq!(msi_num_capable_vectors(enabled), 4);
        // Reserved encodings are capped at the architectural maximum.
        assert_eq!(msi_num_capable_vectors(MSI_CTL_MULTI_MSG_CAPABLE), 32);
    }

    #[test]
    fn multiple_message_enable_is_capped_at_multiple_message_capable() {
        let mut cap = MsiCap {
            msg_ctl: MMC_FOUR_VECTORS,
            ..Default::default()
        };

        // A driver asking for 32 vectors from a device that can request 4.
        let msg_ctl = MSI_CTL_ENABLE | (MSI_MULTI_MSG_ENC_MAX << 4);
        cap.update(MSI_MSG_CTL_OFFSET, &msg_ctl.to_le_bytes());

        assert!(cap.enabled());
        assert_eq!(cap.num_enabled_vectors(), 4);
        // The read-only capability field is untouched.
        assert_eq!(cap.msg_ctl & MSI_CTL_MULTI_MSG_CAPABLE, MMC_FOUR_VECTORS);
    }

    #[test]
    fn enabled_vectors_never_exceed_the_capable_vectors() {
        for capable in 0..=7u16 {
            for enable in 0..=7u16 {
                let mut cap = MsiCap {
                    msg_ctl: capable << 1,
                    ..Default::default()
                };
                cap.update(MSI_MSG_CTL_OFFSET, &(enable << 4).to_le_bytes());

                assert!(cap.num_enabled_vectors() <= msi_num_capable_vectors(cap.msg_ctl));
            }
        }
    }
}
