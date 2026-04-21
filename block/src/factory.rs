// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Disk image factory.
//!
//! [`open_disk`] is the single entry point for opening a disk image.
//! It opens the file, detects the image format, probes async I/O
//! support, and constructs the appropriate backend. Callers receive
//! a trait object that is ready for use by virtio queue workers.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::OnceLock;
use std::{fmt, fs};

use log::info;

use crate::disk_file::AsyncFullDiskFile;
use crate::error::{BlockError, BlockErrorKind, BlockResult};
#[cfg(feature = "io_uring")]
use crate::fixed_vhd_async::FixedVhdDiskAsync;
use crate::fixed_vhd_sync::FixedVhdDiskSync;
#[cfg(feature = "io_uring")]
use crate::qcow_async::QcowDiskAsync;
use crate::qcow_sync::QcowDiskSync;
use crate::raw_async_aio::RawFileDiskAio;
use crate::raw_sync::RawFileDiskSync;
use crate::vhdx_sync::VhdxDiskSync;
use crate::{
    ImageType, block_aio_is_supported, detect_image_type, open_disk_image, preallocate_disk,
};
#[cfg(feature = "io_uring")]
use crate::{block_io_uring_is_supported, raw_async::RawFileDisk};

/// Options for opening a disk image via [`open_disk`].
pub struct DiskOpenOptions<'a> {
    pub path: &'a Path,
    pub readonly: bool,
    pub direct: bool,
    pub sparse: bool,
    pub backing_files: bool,
    pub disable_io_uring: bool,
    pub disable_aio: bool,
}

/// Result of [`open_disk`], carrying the detected image type alongside
/// the constructed backend.
pub struct OpenedDisk {
    pub image_type: ImageType,
    pub disk: Box<dyn AsyncFullDiskFile>,
}

impl fmt::Debug for OpenedDisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedDisk")
            .field("image_type", &self.image_type)
            .finish_non_exhaustive()
    }
}

/// Returns true when io_uring is supported on the running kernel.
///
/// The result is cached so the probe runs at most once per process.
#[cfg(feature = "io_uring")]
fn io_uring_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(block_io_uring_is_supported)
}

/// Returns true when Linux AIO is supported on the running kernel.
///
/// The result is cached so the probe runs at most once per process.
fn aio_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(block_aio_is_supported)
}

/// Open a disk image and construct the appropriate async backend.
///
/// - Opens the file with the requested access mode and flags.
/// - Detects the image format from the file header.
/// - Probes io_uring and Linux AIO support on the running kernel.
/// - Constructs the most capable backend available for the detected
///   format, preferring io_uring over AIO over synchronous fallback.
///
/// The returned [`OpenedDisk`] exposes the detected [`ImageType`] so
/// callers can perform post construction validation (e.g. type mismatch
/// checks, configuration warnings).
pub fn open_disk(options: &DiskOpenOptions<'_>) -> BlockResult<OpenedDisk> {
    let mut fs_options = fs::OpenOptions::new();
    fs_options.read(true);
    fs_options.write(!options.readonly);
    if options.direct {
        fs_options.custom_flags(libc::O_DIRECT);
    }

    let mut file = open_disk_image(options.path, &fs_options)?;
    let image_type = detect_image_type(&mut file)?;

    let disk: Box<dyn AsyncFullDiskFile> = match image_type {
        ImageType::FixedVhd => open_fixed_vhd(file, options)?,
        ImageType::Raw => open_raw(file, options)?,
        ImageType::Qcow2 => open_qcow2(file, options)?,
        ImageType::Vhdx => open_vhdx(file, options)?,
        ImageType::Unknown => {
            return Err(
                BlockError::from_kind(BlockErrorKind::UnsupportedFeature).with_path(options.path)
            );
        }
    };

    Ok(OpenedDisk { image_type, disk })
}

fn open_vhdx(
    file: fs::File,
    options: &DiskOpenOptions<'_>,
) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
    info!("Opening VHDX disk file with synchronous backend");
    Ok(Box::new(
        VhdxDiskSync::new(file).map_err(|e| e.with_path(options.path))?,
    ))
}

fn open_fixed_vhd(
    file: fs::File,
    options: &DiskOpenOptions<'_>,
) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
    #[cfg(feature = "io_uring")]
    if !options.disable_io_uring {
        if io_uring_supported() {
            info!("Opening fixed VHD disk file with io_uring backend");
            return Ok(Box::new(
                FixedVhdDiskAsync::new(file).map_err(|e| e.with_path(options.path))?,
            ));
        }
        info!("io_uring runtime probe failed for fixed VHD, using synchronous backend");
    }

    info!("Opening fixed VHD disk file with synchronous backend");
    Ok(Box::new(
        FixedVhdDiskSync::new(file).map_err(|e| e.with_path(options.path))?,
    ))
}

fn open_raw(
    file: fs::File,
    options: &DiskOpenOptions<'_>,
) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
    if !options.readonly && !options.sparse {
        preallocate_disk(&file, options.path);
    }

    #[cfg(feature = "io_uring")]
    if !options.disable_io_uring {
        if io_uring_supported() {
            info!("Opening RAW disk file with io_uring backend");
            return Ok(Box::new(RawFileDisk::new(file)));
        }
        info!("io_uring runtime probe failed for RAW, trying next backend");
    }

    if !options.disable_aio {
        if aio_supported() {
            info!("Opening RAW disk file with AIO backend");
            return Ok(Box::new(RawFileDiskAio::new(file)));
        }
        info!("AIO runtime probe failed for RAW, using synchronous backend");
    }

    info!("Opening RAW disk file with synchronous backend");
    Ok(Box::new(RawFileDiskSync::new(file)))
}

fn open_qcow2(
    file: fs::File,
    options: &DiskOpenOptions<'_>,
) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
    #[cfg(feature = "io_uring")]
    if !options.disable_io_uring {
        if io_uring_supported() {
            info!("Opening QCOW2 disk file with io_uring backend");
            return Ok(Box::new(
                QcowDiskAsync::new(file, options.direct, options.backing_files, options.sparse)
                    .map_err(|e| e.with_path(options.path))?,
            ));
        }
        info!("io_uring runtime probe failed for QCOW2, using synchronous backend");
    }

    info!("Opening QCOW2 disk file with synchronous backend");
    Ok(Box::new(
        QcowDiskSync::new(file, options.direct, options.backing_files, options.sparse)
            .map_err(|e| e.with_path(options.path))?,
    ))
}

#[cfg(test)]
mod unit_tests {
    use std::io::Write;
    use std::path::Path;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::qcow::{QcowFile, RawFile};

    fn default_options(path: &Path) -> DiskOpenOptions<'_> {
        DiskOpenOptions {
            path,
            readonly: false,
            direct: false,
            sparse: false,
            backing_files: false,
            disable_io_uring: true,
            disable_aio: true,
        }
    }

    #[test]
    fn nonexistent_path_returns_error() {
        let path = Path::new("/tmp/no_such_disk_image.raw");
        let options = default_options(path);
        match open_disk(&options) {
            Err(e) => assert_eq!(e.kind(), BlockErrorKind::Io),
            Ok(_) => panic!("expected error for nonexistent path"),
        }
    }

    #[test]
    fn detect_raw_image() {
        let tmp = TempFile::new().unwrap();
        tmp.as_file().set_len(1 << 20).unwrap();
        let path = tmp.as_path().to_owned();
        let options = default_options(&path);
        let opened = open_disk(&options).unwrap();
        assert_eq!(opened.image_type, ImageType::Raw);
    }

    #[test]
    fn detect_qcow2_image() {
        let tmp = TempFile::new().unwrap();
        {
            let raw = RawFile::new(tmp.as_file().try_clone().unwrap(), false);
            let mut qcow = QcowFile::new(raw, 3, 100 * 1024 * 1024, true).unwrap();
            qcow.flush().unwrap();
        }
        let path = tmp.as_path().to_owned();
        let options = default_options(&path);
        let opened = open_disk(&options).unwrap();
        assert_eq!(opened.image_type, ImageType::Qcow2);
    }

    #[test]
    fn open_readonly() {
        let tmp = TempFile::new().unwrap();
        tmp.as_file().set_len(1 << 20).unwrap();
        let path = tmp.as_path().to_owned();
        let mut options = default_options(&path);
        options.readonly = true;
        let opened = open_disk(&options).unwrap();
        assert_eq!(opened.image_type, ImageType::Raw);
    }
}
