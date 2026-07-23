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

use log::{info, warn};

#[cfg(feature = "io_uring")]
use crate::block_io_uring_is_supported;
use crate::disk_file::AsyncFullDiskFile;
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::formats::qcow::QcowDisk;
use crate::formats::raw::{RawBackend, RawDisk};
use crate::formats::vhd::VhdDisk;
use crate::formats::vhdx::VhdxDisk;
use crate::{
    DiskTopology, ImageType, block_aio_is_supported, detect_image_type, open_disk_image,
    preallocate_disk,
};

/// Options for opening a disk image via [`open_disk`].
pub struct DiskOpenOptions<'a> {
    pub path: &'a Path,
    pub readonly: bool,
    pub direct: bool,
    pub sparse: bool,
    pub backing_files: bool,
    pub disable_io_uring: bool,
    pub disable_aio: bool,
    pub logical_block_size: Option<u64>,
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

    if options.logical_block_size.is_some() && image_type != ImageType::Raw {
        warn!("logical_block_size is only supported for raw disk images");
        return Err(
            BlockError::from_kind(BlockErrorKind::UnsupportedFeature).with_path(options.path)
        );
    }

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
        VhdxDisk::new(file, options.direct).map_err(|e| e.with_path(options.path))?,
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
                VhdDisk::new(file, true, options.direct).map_err(|e| e.with_path(options.path))?,
            ));
        }
        info!("io_uring runtime probe failed for fixed VHD, using synchronous backend");
    }

    info!("Opening fixed VHD disk file with synchronous backend");
    Ok(Box::new(
        VhdDisk::new(file, false, options.direct).map_err(|e| e.with_path(options.path))?,
    ))
}

fn open_raw(
    file: fs::File,
    options: &DiskOpenOptions<'_>,
) -> BlockResult<Box<dyn AsyncFullDiskFile>> {
    if !options.readonly && !options.sparse {
        preallocate_disk(&file, options.path);
    }

    if let Some(logical_block_size) = options.logical_block_size
        && options.direct
    {
        let topology = DiskTopology::probe(&file).unwrap_or_else(|_| {
            warn!("Unable to get device topology. Using default topology");
            DiskTopology::default()
        });
        if logical_block_size != topology.logical_block_size {
            warn!(
                "logical_block_size {} does not match device logical block size {} \
                and cannot be emulated with direct I/O",
                logical_block_size, topology.logical_block_size
            );
            return Err(
                BlockError::from_kind(BlockErrorKind::UnsupportedFeature).with_path(options.path)
            );
        }
    }

    #[cfg(feature = "io_uring")]
    if !options.disable_io_uring {
        if io_uring_supported() {
            info!("Opening RAW disk file with io_uring backend");
            return Ok(Box::new(
                RawDisk::new(file, RawBackend::IoUring, options.direct)
                    .with_logical_block_size(options.logical_block_size),
            ));
        }
        info!("io_uring runtime probe failed for RAW, trying next backend");
    }

    if !options.disable_aio {
        if aio_supported() {
            info!("Opening RAW disk file with AIO backend");
            return Ok(Box::new(
                RawDisk::new(file, RawBackend::Aio, options.direct)
                    .with_logical_block_size(options.logical_block_size),
            ));
        }
        info!("AIO runtime probe failed for RAW, using synchronous backend");
    }

    info!("Opening RAW disk file with synchronous backend");
    Ok(Box::new(
        RawDisk::new(file, RawBackend::Sync, options.direct)
            .with_logical_block_size(options.logical_block_size),
    ))
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
                QcowDisk::new(
                    file,
                    options.direct,
                    options.backing_files,
                    options.sparse,
                    true,
                )
                .map_err(|e| e.with_path(options.path))?,
            ));
        }
        info!("io_uring runtime probe failed for QCOW2, using synchronous backend");
    }

    info!("Opening QCOW2 disk file with synchronous backend");
    Ok(Box::new(
        QcowDisk::new(
            file,
            options.direct,
            options.backing_files,
            options.sparse,
            false,
        )
        .map_err(|e| e.with_path(options.path))?,
    ))
}

#[cfg(test)]
mod unit_tests {
    use std::path::Path;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::formats::qcow;

    fn default_options(path: &Path) -> DiskOpenOptions<'_> {
        DiskOpenOptions {
            path,
            readonly: false,
            direct: false,
            sparse: false,
            backing_files: false,
            disable_io_uring: true,
            disable_aio: true,
            logical_block_size: None,
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
        let tmp = qcow::QcowTempDisk::new(100 * 1024 * 1024, None, false, true, false)
            .unwrap()
            .into_tempfile();
        let path = tmp.as_path().to_owned();
        let options = default_options(&path);
        let opened = open_disk(&options).unwrap();
        assert_eq!(opened.image_type, ImageType::Qcow2);
    }

    #[test]
    fn logical_block_size_overrides_raw_topology() {
        let tmp = TempFile::new().unwrap();
        tmp.as_file().set_len(1 << 20).unwrap();
        let path = tmp.as_path().to_owned();
        let mut options = default_options(&path);
        options.logical_block_size = Some(4096);
        let opened = open_disk(&options).unwrap();
        assert_eq!(opened.image_type, ImageType::Raw);
        assert_eq!(opened.disk.topology().logical_block_size, 4096);
    }

    #[test]
    fn logical_block_size_rejected_for_qcow2() {
        let tmp = qcow::QcowTempDisk::new(100 * 1024 * 1024, None, false, true, false)
            .unwrap()
            .into_tempfile();
        let path = tmp.as_path().to_owned();
        let mut options = default_options(&path);
        options.logical_block_size = Some(4096);
        match open_disk(&options) {
            Err(e) => assert_eq!(e.kind(), BlockErrorKind::UnsupportedFeature),
            Ok(_) => panic!("expected error for qcow2 with logical_block_size"),
        }
    }

    #[test]
    fn logical_block_size_mismatch_rejected_with_direct() {
        let tmp = TempFile::new().unwrap();
        tmp.as_file().set_len(1 << 20).unwrap();
        let path = tmp.as_path().to_owned();
        let mut options = default_options(&path);
        options.direct = true;
        options.logical_block_size = Some(4096);
        // The file is opened without O_DIRECT on purpose. The topology
        // probe then falls back to the 512 default on any host filesystem,
        // which guarantees the mismatch against 4096.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        match open_raw(file, &options) {
            Err(e) => assert_eq!(e.kind(), BlockErrorKind::UnsupportedFeature),
            Ok(_) => panic!("expected error for mismatched logical_block_size with direct"),
        }
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

    #[test]
    fn sync_fallback_when_async_disabled() {
        let tmp = TempFile::new().unwrap();
        let size = 1u64 << 20;
        tmp.as_file().set_len(size).unwrap();
        let path = tmp.as_path().to_owned();
        let options = DiskOpenOptions {
            path: &path,
            readonly: false,
            direct: false,
            sparse: false,
            backing_files: false,
            disable_io_uring: true,
            disable_aio: true,
            logical_block_size: None,
        };
        let opened = open_disk(&options).unwrap();
        assert_eq!(opened.image_type, ImageType::Raw);
        assert_eq!(opened.disk.logical_size().unwrap(), size);
    }
}
