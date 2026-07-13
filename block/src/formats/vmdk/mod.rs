// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Flat VMDK block backend.
//!
//! Supports the `monolithicFlat` and `twoGbMaxExtentFlat` create types with
//! synchronous, extent-aware I/O.

mod descriptor;
mod engine_sync;
mod flat;

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub use descriptor::{has_descriptor_header, is_flat_vmdk};

use self::engine_sync::FlatVmdkSync;
use self::flat::FlatVmdk;
use crate::async_io::{AsyncIo, BorrowedDiskFd, DiskFileError};
use crate::error::{BlockError, BlockErrorKind, BlockResult, ErrorOp};
use crate::{DiskTopology, disk_file};

#[derive(Debug)]
pub struct VmdkDisk {
    inner: FlatVmdk,
}

impl VmdkDisk {
    /// Builds a Flat VMDK disk backend.
    pub fn new(file: File, path: &Path, direct: bool) -> Result<Self, BlockError> {
        let inner = FlatVmdk::new(file, path, direct)?;
        Ok(VmdkDisk { inner })
    }
}

impl disk_file::DiskSize for VmdkDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.inner.virtual_block_size())
    }
}

impl disk_file::PhysicalSize for VmdkDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        Ok(self.inner.physical_block_size())
    }
}

// Expose the descriptor file's fd for advisory image locking.
impl disk_file::DiskFd for VmdkDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.inner.as_raw_fd())
    }
}

impl disk_file::Geometry for VmdkDisk {
    fn topology(&self) -> DiskTopology {
        self.inner.topology()
    }
}

impl disk_file::SparseCapable for VmdkDisk {}

// Flat VMDK keeps no in-memory format metadata, so no-op.
impl disk_file::MetadataSync for VmdkDisk {}

impl disk_file::Resizable for VmdkDisk {
    fn resize(&mut self, _size: u64) -> BlockResult<()> {
        Err(BlockError::new(
            BlockErrorKind::UnsupportedFeature,
            DiskFileError::ResizeError(io::Error::other("resize not supported for flat VMDK")),
        )
        .with_op(ErrorOp::Resize))
    }
}

impl disk_file::DiskFile for VmdkDisk {}

impl disk_file::AsyncDiskFile for VmdkDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        Ok(Box::new(VmdkDisk {
            inner: self.inner.clone(),
        }))
    }

    fn create_async_io(&self, ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        // VMDK provides a synchronous, extent-aware worker, so the io_uring ring
        // depth is unused here.
        let _ = ring_depth;

        Ok(Box::new(
            FlatVmdkSync::new(self.inner.extents(), self.inner.virtual_block_size()).map_err(
                |e| {
                    BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e))
                        .with_op(ErrorOp::Open)
                },
            )?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::disk_file::{AsyncDiskFile, DiskFd, DiskSize, PhysicalSize, Resizable};

    const SECTOR: u64 = 512;

    // Builds a flat VMDK in `dir`: a descriptor plus one backing data file per
    // extent. When `allocate` is true the extent files are filled with real
    // blocks (fixed / pre-allocated layout used in practice); otherwise they
    // are created sparse via `set_len` (declared length but no allocated
    // blocks). `extents` entries are (filename, access, sectors). Returns the
    // descriptor path.
    fn build_flat_vmdk(
        dir: &Path,
        create_type: &str,
        extents: &[(&str, &str, u64)],
        allocate: bool,
    ) -> PathBuf {
        let mut desc = String::from("# Disk DescriptorFile\n");
        desc.push_str("version=1\n");
        desc.push_str("CID=fffffffe\n");
        desc.push_str("parentCID=ffffffff\n");
        desc.push_str(&format!("createType={create_type}\n"));
        desc.push_str("# Extent description\n");

        for (filename, access, sectors) in extents {
            let mut data = File::create(dir.join(filename)).unwrap();
            if allocate {
                data.write_all(&vec![0u8; (sectors * SECTOR) as usize])
                    .unwrap();
            } else {
                data.set_len(sectors * SECTOR).unwrap();
            }
            data.sync_all().unwrap();
            desc.push_str(&format!("{access} {sectors} FLAT \"{filename}\"\n"));
        }

        desc.push_str("# The Disk Data Base\n");
        desc.push_str("ddb.adapterType = \"ide\"\n");

        let desc_path = dir.join("disk.vmdk");
        let mut df = File::create(&desc_path).unwrap();
        df.write_all(desc.as_bytes()).unwrap();
        df.sync_all().unwrap();
        desc_path
    }

    // Sparse extents.
    fn write_flat_vmdk(dir: &Path, create_type: &str, extents: &[(&str, &str, u64)]) -> PathBuf {
        build_flat_vmdk(dir, create_type, extents, false)
    }

    // Fully pre-allocated extents.
    fn write_flat_vmdk_allocated(
        dir: &Path,
        create_type: &str,
        extents: &[(&str, &str, u64)],
    ) -> PathBuf {
        build_flat_vmdk(dir, create_type, extents, true)
    }

    fn open_descriptor(path: &Path) -> File {
        File::open(path).unwrap()
    }

    // Writes a descriptor referencing `extent_lines` verbatim (no backing data
    // files are created). Used to exercise `FlatVmdk::new`'s per-extent
    // validation, whose zero-size/overflow checks all run before an extent file
    // would be opened.
    fn write_descriptor(dir: &Path, create_type: &str, extent_lines: &[&str]) -> PathBuf {
        let mut desc = String::from("# Disk DescriptorFile\n");
        desc.push_str("version=1\n");
        desc.push_str("CID=fffffffe\n");
        desc.push_str("parentCID=ffffffff\n");
        desc.push_str(&format!("createType={create_type}\n"));
        desc.push_str("# Extent description\n");
        for line in extent_lines {
            desc.push_str(line);
            desc.push('\n');
        }
        desc.push_str("# The Disk Data Base\n");
        desc.push_str("ddb.adapterType = \"ide\"\n");

        let desc_path = dir.join("disk.vmdk");
        let mut df = File::create(&desc_path).unwrap();
        df.write_all(desc.as_bytes()).unwrap();
        df.sync_all().unwrap();
        desc_path
    }

    #[test]
    fn logical_and_physical_size_single_extent() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "monolithicFlat",
            &[("disk-flat.vmdk", "RW", 2048)],
        );
        let disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        assert_eq!(disk.logical_size().unwrap(), 2048 * SECTOR);
        // The extent is created sparse (`set_len`), so no blocks are allocated
        // and the `st_blocks`-based physical size is 0.
        assert_eq!(disk.physical_size().unwrap(), 0);
    }

    #[test]
    fn logical_size_sums_multiple_extents() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "twoGbMaxExtentFlat",
            &[("s001.vmdk", "RW", 2048), ("s002.vmdk", "RW", 1024)],
        );
        let disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        assert_eq!(disk.logical_size().unwrap(), (2048 + 1024) * SECTOR);
        // Sparse extents: no blocks are allocated, so physical size is 0.
        assert_eq!(disk.physical_size().unwrap(), 0);
    }

    #[test]
    fn physical_size_matches_fully_allocated_extents() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk_allocated(
            dir.as_path(),
            "twoGbMaxExtentFlat",
            &[("s001.vmdk", "RW", 2048), ("s002.vmdk", "RW", 1024)],
        );
        let disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        // Fully pre-allocated extents: host allocation (st_blocks) equals the
        // declared logical size.
        assert_eq!(disk.logical_size().unwrap(), (2048 + 1024) * SECTOR);
        assert_eq!(disk.physical_size().unwrap(), (2048 + 1024) * SECTOR);
    }

    #[test]
    fn fd_exposes_descriptor_file() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "monolithicFlat",
            &[("disk-flat.vmdk", "RW", 64)],
        );
        let file = open_descriptor(&path);
        let expected = file.as_raw_fd();

        let disk = VmdkDisk::new(file, &path, false).unwrap();

        assert_eq!(disk.fd().as_raw_fd(), expected);
    }

    #[test]
    fn resize_is_unsupported() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "monolithicFlat",
            &[("disk-flat.vmdk", "RW", 64)],
        );
        let mut disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        let err = disk.resize(4096).unwrap_err();
        assert_eq!(err.kind(), BlockErrorKind::UnsupportedFeature);
    }

    #[test]
    fn try_clone_preserves_size() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "monolithicFlat",
            &[("disk-flat.vmdk", "RW", 2048)],
        );
        let disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        let cloned = disk.try_clone().unwrap();
        assert_eq!(cloned.logical_size().unwrap(), disk.logical_size().unwrap());
    }

    #[test]
    fn create_async_io_builds_worker() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "monolithicFlat",
            &[("disk-flat.vmdk", "RW", 2048)],
        );
        let disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        // Ring depth is ignored by the synchronous VMDK worker.
        disk.create_async_io(0).unwrap();
    }

    #[test]
    fn create_async_io_supports_multi_extent() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-test").unwrap();
        let path = write_flat_vmdk(
            dir.as_path(),
            "twoGbMaxExtentFlat",
            &[("s001.vmdk", "RW", 2048), ("s002.vmdk", "RW", 2048)],
        );
        let disk = VmdkDisk::new(open_descriptor(&path), &path, false).unwrap();

        disk.create_async_io(32).unwrap();
    }

    #[test]
    fn new_rejects_zero_sector_extent() {
        let dir = TempDir::new_with_prefix("/tmp/vmdk-zero-test").unwrap();
        let path = write_descriptor(
            dir.as_path(),
            "monolithicFlat",
            &["RW 0 FLAT \"disk-flat.vmdk\""],
        );

        let err = FlatVmdk::new(open_descriptor(&path), &path, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn new_rejects_extent_size_overflow() {
        // size_in_sectors * 512 must fit in a u64.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-ovf-size-test").unwrap();
        let line = format!("RW {} FLAT \"disk-flat.vmdk\"", u64::MAX);
        let path = write_descriptor(dir.as_path(), "monolithicFlat", &[line.as_str()]);

        let err = FlatVmdk::new(open_descriptor(&path), &path, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn new_rejects_extent_file_offset_overflow() {
        // The offset * 512 must fit in a u64.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-ovf-offset-test").unwrap();
        let line = format!("RW 1 FLAT \"disk-flat.vmdk\" {}", u64::MAX);
        let path = write_descriptor(dir.as_path(), "monolithicFlat", &[line.as_str()]);

        let err = FlatVmdk::new(open_descriptor(&path), &path, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn new_rejects_extent_file_range_overflow() {
        // Each of offset*512 and size*512 fits in a u64, but their sum (the last
        // byte the extent addresses in its backing file) overflows.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-ovf-range-test").unwrap();
        // offset_in_sectors = floor(u64::MAX / 512) => offset bytes = u64::MAX -
        // 511; size 1 sector (512 bytes) pushes the end one byte past u64::MAX.
        let offset = u64::MAX / 512;
        let line = format!("RW 1 FLAT \"disk-flat.vmdk\" {offset}");
        let path = write_descriptor(dir.as_path(), "monolithicFlat", &[line.as_str()]);

        let err = FlatVmdk::new(open_descriptor(&path), &path, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn new_rejects_total_virtual_size_overflow() {
        // Two extents whose individual lengths fit in a u64 but whose running
        // sum (the total virtual disk size) overflows. size = 2^55 - 1 =>
        // length = 2^64 - 512; two of them overflow the total.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-ovf-total-test").unwrap();
        let size = (1u64 << 55) - 1;
        let l1 = format!("NOACCESS {size} FLAT \"s001.vmdk\"");
        let l2 = format!("NOACCESS {size} FLAT \"s002.vmdk\"");
        let path = write_descriptor(
            dir.as_path(),
            "twoGbMaxExtentFlat",
            &[l1.as_str(), l2.as_str()],
        );

        let err = FlatVmdk::new(open_descriptor(&path), &path, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
