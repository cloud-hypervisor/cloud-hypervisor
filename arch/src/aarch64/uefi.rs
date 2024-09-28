// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::result;

use thiserror::Error;
use vm_memory::{GuestAddress, GuestMemory};

/// Errors thrown while loading UEFI binary
#[derive(Debug, Error)]
pub enum Error {
    /// Unable to seek to UEFI image start.
    #[error("Unable to seek to UEFI image start")]
    SeekUefiStart,
    /// Unable to seek to UEFI image end.
    #[error("Unable to seek to UEFI image end")]
    SeekUefiEnd,
    /// UEFI image too big.
    #[error("UEFI image too big")]
    UefiTooBig,
    /// Unable to read UEFI image
    #[error("Unable to read UEFI image")]
    ReadUefiImage,
}
type Result<T> = result::Result<T, Error>;

pub fn load_uefi<F, M: GuestMemory>(
    guest_mem: &M,
    guest_addr: GuestAddress,
    uefi_image: &mut F,
) -> Result<()>
where
    F: Read + Seek + AsFd,
{
    let uefi_size = uefi_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekUefiEnd)? as usize;

    // edk2 image on virtual platform is smaller than 3M
    if uefi_size > 0x300000 {
        return Err(Error::UefiTooBig);
    }
    uefi_image.rewind().map_err(|_| Error::SeekUefiStart)?;
    guest_mem
        .read_exact_volatile_from(guest_addr, &mut uefi_image.as_fd(), uefi_size)
        .map_err(|_| Error::ReadUefiImage)
}
