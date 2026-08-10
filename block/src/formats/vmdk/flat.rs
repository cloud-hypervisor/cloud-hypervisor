// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Flat VMDK extent layout: opens the data extents referenced by the
//! descriptor and maps the virtual disk onto them.

use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions, canonicalize, read_link};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Component, Path};
use std::sync::Arc;

use log::warn;

use crate::formats::vmdk::descriptor::{ExtentAccess, VmdkDescriptor};
use crate::{AlignedFile, DiskTopology, query_device_size};

const VMDK_SECTOR_SIZE: u64 = 512;

/// A single Flat VMDK extent
///
/// `twoGbMaxExtentFlat` images concatenate several of these to form the full
/// virtual disk, `monolithicFlat` images have exactly one.
#[derive(Debug)]
pub(crate) struct VmdkExtent {
    /// Open, alignment-aware handle to this extent's data file. `None` for
    /// `NoAccess` extents, which are never opened because they cannot be
    /// accessed.
    ///
    /// The handle is wrapped in an [`AlignedFile`]
    pub file: Option<AlignedFile>,
    /// Access mode declared for this extent in the descriptor.
    pub access: ExtentAccess,
    /// First virtual-disk offset (in bytes) backed by this extent.
    pub virtual_start: u64,
    /// Length (in bytes) of the virtual-disk range backed by this extent.
    pub length: u64,
    /// Starting offset (in bytes) within the backing file for this extent.
    /// Non-zero when several extents reference the same file at growing
    /// offsets (e.g. a >2GB file split under `twoGbMaxExtentFlat`).
    pub file_base_offset: u64,
}

#[derive(Debug)]
pub struct FlatVmdk {
    descriptor: Arc<VmdkDescriptor>,
    // Open handle to the VMDK descriptor file.
    descriptor_file: Arc<File>,
    // All opened data extents, in virtual-disk order.
    extents: Arc<Vec<VmdkExtent>>,
    size: u64,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// open_how.resolve flags from openat2(2). The libc crate does not export
// them, so they are defined here with the values from the kernel UAPI
// (include/uapi/linux/openat2.h).
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;

// Splits an untrusted extent `filename` into its `Normal` path components for
// the fallback walk, rejecting any `..`/`.` traversal.
fn extent_components(filename: &str) -> io::Result<Vec<&OsStr>> {
    let mut components = Vec::new();
    for component in Path::new(filename).components() {
        match component {
            Component::Normal(name) => components.push(name),
            Component::RootDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "VMDK extent filename '{filename}' must not contain '..' or '.' path \
                         components"
                    ),
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("VMDK extent filename '{filename}' is empty"),
        ));
    }
    Ok(components)
}

// Opens a single VMDK data extent for the descriptor whose directory is
// base_path.
//
// The extent name may be relative to the descriptor or an absolute path. The
// only difference between the two is:
//   - relative -> colocated with descriptor file
//   - absolute -> the filesystem root
// The symlink policy rejects the final component if it is a symlink (O_NOFOLLOW).
//
// Resolution prefers openat2(2). On kernels without it (< 5.6, ENOSYS) or
// where it is blocked (EPERM, e.g. a seccomp filter), it falls back to a
// per-component openat walk.
fn open_extent(
    base_path: &str,
    filename: &str,
    writable: bool,
    direct: bool,
    extent_anchor_path: Option<&Path>,
) -> io::Result<AlignedFile> {
    let is_absolute = Path::new(filename).is_absolute();

    // absolute paths need an extent anchor to resolve against
    if is_absolute && extent_anchor_path.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "VMDK absolute extent '{filename}' is not permitted: no extent anchor path is \
                 configured (relative extents only)"
            ),
        ));
    }

    let anchor = if is_absolute { "/" } else { base_path };

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(anchor)?;

    let aligned = match open_extent_openat2(dir.as_raw_fd(), filename, writable, direct) {
        Ok(file) => AlignedFile::new(file, direct),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EPERM)) => {
            let components = extent_components(filename)?;
            open_extent_walk(dir, &components, writable, direct)?
        }
        Err(e) => return Err(e),
    };

    if let Some(anchor_path) = extent_anchor_path.filter(|_| is_absolute) {
        verify_within_extent_anchor(aligned.file(), anchor_path)?;
    }

    Ok(aligned)
}

fn verify_within_extent_anchor(file: &File, extent_anchor_path: &Path) -> io::Result<()> {
    // /proc/self/fd reports '<path> (deleted)' if the file path has been deleted, while still
    // holding the fd.
    if file.metadata()?.nlink() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VMDK absolute extent backing file was deleted; cannot verify containment",
        ));
    }

    let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let resolved = read_link(&proc_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot verify VMDK absolute extent: reading '{proc_path}' failed ({e}); is /proc \
                 mounted?"
            ),
        )
    })?;

    // canonicalize the anchor so a symlinked anchor path
    // still matches the kernel-resolved extent path
    let anchor = canonicalize(extent_anchor_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot verify VMDK absolute extent: extent anchor path '{}' is unusable ({e})",
                extent_anchor_path.display()
            ),
        )
    })?;

    if resolved.starts_with(&anchor) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "VMDK absolute extent resolves to '{}', outside the extent anchor path '{}'",
                resolved.display(),
                anchor.display()
            ),
        ))
    }
}

fn open_extent_openat2(
    dir_fd: RawFd,
    filename: &str,
    writable: bool,
    direct: bool,
) -> io::Result<File> {
    let cname = CString::new(filename).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "VMDK extent filename contains an interior NUL byte",
        )
    })?;

    let access = if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };

    let mut flags = access | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if direct {
        flags |= libc::O_DIRECT;
    }

    // Confine a relative extent name beneath the descriptor directory. An
    // absolute name is anchored at the filesystem root by the caller and its
    // policy is deliberately left unchanged here, so RESOLVE_BENEATH (which
    // rejects absolute pathnames outright) is not applied to it.
    let mut resolve = RESOLVE_NO_MAGICLINKS;
    if !Path::new(filename).is_absolute() {
        resolve |= RESOLVE_BENEATH;
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve,
    };

    // SAFETY: FFI syscall. `cname` is NUL-terminated and outlives the call,
    // `how` is a correctly sized `open_how` passed by pointer, and `dir_fd` is a
    // valid directory fd.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir_fd,
            cname.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat2` returned a fresh descriptor we now own exclusively.
    Ok(unsafe { File::from_raw_fd(ret as RawFd) })
}

fn open_extent_walk(
    mut dir: File,
    components: &[&OsStr],
    writable: bool,
    direct: bool,
) -> io::Result<AlignedFile> {
    let last = components.len() - 1;
    for (i, name) in components.iter().enumerate() {
        let cname = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMDK extent filename contains an interior NUL byte",
            )
        })?;

        let flags = if i < last {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
        } else {
            // Final component: the extent file, opened with the declared access
            // and cache mode, and O_NOFOLLOW so it may not be a symlink either.
            let access = if writable {
                libc::O_RDWR
            } else {
                libc::O_RDONLY
            };
            let mut flags = access | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            if direct {
                flags |= libc::O_DIRECT;
            }
            flags
        };

        // SAFETY: `dir` is a valid open directory fd and `cname` is a
        // NUL-terminated C string that outlives the call.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a freshly opened descriptor we now own exclusively.
        let opened = unsafe { File::from_raw_fd(fd) };

        if i < last {
            // Reassignment drops the previous directory `File`, closing that fd.
            dir = opened;
        } else {
            return Ok(AlignedFile::new(opened, direct));
        }
    }

    unreachable!("extent_components guarantees at least one component")
}

// Builds the error returned when a sector count/offset from the (untrusted)
// descriptor, scaled to bytes, does not fit in a u64.
fn overflow_error(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("VMDK {what} overflows a 64-bit byte count"),
    )
}

impl FlatVmdk {
    /// Opens a flat VMDK image from its already-open descriptor file.
    pub fn new(
        file: File,
        path: &Path,
        readonly: bool,
        direct: bool,
        extent_anchor_path: Option<&Path>,
    ) -> io::Result<Self> {
        let descriptor = VmdkDescriptor::new(&file, path)?;

        if descriptor.extents_list.extents.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMDK descriptor lists no extents",
            ));
        }

        // Open every data extent and record the virtual-disk byte range it
        // backs.
        let mut extents: Vec<VmdkExtent> =
            Vec::with_capacity(descriptor.extents_list.extents.len());
        let mut virtual_start: u64 = 0;
        for extent in &descriptor.extents_list.extents {
            // A flat extent is a fixed, pre-allocated region, a zero-sector
            // extent would back an empty virtual range that can never be read
            // or written
            if extent.size_in_sectors == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VMDK flat extent has zero size",
                ));
            }

            let length = extent
                .size_in_sectors
                .checked_mul(VMDK_SECTOR_SIZE)
                .ok_or_else(|| overflow_error("extent size"))?;
            let file_base_offset = extent
                .offset_in_sectors
                .checked_mul(VMDK_SECTOR_SIZE)
                .ok_or_else(|| overflow_error("extent file offset"))?;
            file_base_offset
                .checked_add(length)
                .ok_or_else(|| overflow_error("extent file range"))?;

            // Downgrade "RW" to read-only if the caller requested a read-only open.
            let access = if readonly && matches!(extent.access, ExtentAccess::ReadWrite) {
                ExtentAccess::ReadOnly
            } else {
                extent.access
            };

            let extent_file = match access {
                ExtentAccess::ReadWrite => Some(open_extent(
                    &descriptor.base_path,
                    &extent.filename,
                    true,
                    direct,
                    extent_anchor_path,
                )?),
                ExtentAccess::ReadOnly => Some(open_extent(
                    &descriptor.base_path,
                    &extent.filename,
                    false,
                    direct,
                    extent_anchor_path,
                )?),
                ExtentAccess::NoAccess => None,
            };

            extents.push(VmdkExtent {
                file: extent_file,
                access,
                virtual_start,
                length,
                file_base_offset,
            });

            virtual_start = virtual_start
                .checked_add(length)
                .ok_or_else(|| overflow_error("total virtual size"))?;
        }

        // The virtual disk size is the end offset of the last extent.
        let total_disk_size = virtual_start;

        Ok(Self {
            descriptor: Arc::new(descriptor),
            descriptor_file: Arc::new(file),
            extents: Arc::new(extents),
            size: total_disk_size,
        })
    }

    pub fn virtual_block_size(&self) -> u64 {
        self.size
    }

    /// Shared handle to the opened data extents, used to build the I/O worker.
    pub fn extents(&self) -> Arc<Vec<VmdkExtent>> {
        Arc::clone(&self.extents)
    }

    /// Host allocation size: the sum of every opened extent's actually
    /// allocated storage (`st_blocks * 512` for regular files, device size for
    /// block devices), so sparse extents are reported correctly. `NoAccess`
    /// extents (no open file) contribute 0, as does any extent whose size
    /// cannot be queried.
    pub fn physical_block_size(&self) -> u64 {
        self.extents
            .iter()
            .filter_map(|extent| extent.file.as_ref())
            .map(|f| query_device_size(f.file()).map_or(0, |(_, physical)| physical))
            .sum()
    }

    /// Sector/cluster geometry reported to the guest.
    pub fn topology(&self) -> DiskTopology {
        self.extents
            .iter()
            .find_map(|extent| extent.file.as_ref())
            .map(|f| {
                DiskTopology::probe(f.file()).unwrap_or_else(|_| {
                    warn!("Unable to get VMDK extent topology. Using default topology");
                    DiskTopology::default()
                })
            })
            .unwrap_or_default()
    }
}

// Expose the descriptor file's fd as the disk's representative fd.
impl AsRawFd for FlatVmdk {
    fn as_raw_fd(&self) -> RawFd {
        self.descriptor_file.as_raw_fd()
    }
}

impl Clone for FlatVmdk {
    fn clone(&self) -> Self {
        Self {
            descriptor: Arc::clone(&self.descriptor),
            descriptor_file: Arc::clone(&self.descriptor_file),
            extents: Arc::clone(&self.extents),
            size: self.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn extent_components_allows_bare_name() {
        // The common flat-VMDK case: a single co-located extent file.
        let comps = extent_components("disk-flat.vmdk").unwrap();
        assert_eq!(comps, [OsStr::new("disk-flat.vmdk")]);
    }

    #[test]
    fn extent_components_rejects_traversal_and_empty() {
        // `..`/`.` traversal and empty names are refused. (An absolute path is
        // decomposed into its Normal components, the leading `/` is skipped and
        // the caller anchors the walk at the filesystem root.)
        extent_components("../../etc/passwd").unwrap_err();
        extent_components("sub/../../escape").unwrap_err();
        extent_components("extent-1.vmdk/../../").unwrap_err();
        extent_components("./s001.vmdk").unwrap_err();
        extent_components("").unwrap_err();
    }

    #[test]
    fn extent_components_decomposes_absolute_path() {
        // A leading `/` is skipped, the remaining Normal components are walked
        // from the filesystem root by the caller.
        let comps = extent_components("/var/lib/layer.erofs").unwrap();
        assert_eq!(
            comps,
            [
                OsStr::new("var"),
                OsStr::new("lib"),
                OsStr::new("layer.erofs")
            ]
        );
    }

    // Opens `path` as a directory anchor fd, mirroring how `open_extent` opens
    // its anchor.
    fn open_dir(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .unwrap()
    }

    // Returns false when `openat2(2)` is unavailable.
    fn openat2_available(res: &io::Result<File>) -> bool {
        !matches!(
            res.as_ref().err().and_then(|e| e.raw_os_error()),
            Some(libc::ENOSYS) | Some(libc::EPERM)
        )
    }

    // Opens the same anchor + `filename` with BOTH extent-open implementations
    // so a single scenario asserts they behave identically:
    fn open_both(
        base_path: &Path,
        filename: &str,
        writable: bool,
        direct: bool,
    ) -> (io::Result<File>, io::Result<AlignedFile>) {
        let anchor: &Path = if Path::new(filename).is_absolute() {
            Path::new("/")
        } else {
            base_path
        };

        let openat2_dir = open_dir(anchor);
        let openat2_res = open_extent_openat2(openat2_dir.as_raw_fd(), filename, writable, direct);

        let walk_dir = open_dir(anchor);
        let walk_res = match extent_components(filename) {
            Ok(components) => open_extent_walk(walk_dir, &components, writable, direct),
            Err(e) => Err(e),
        };

        (openat2_res, walk_res)
    }

    // Asserts openat2.
    fn check_openat2(res: &io::Result<File>, expect_ok: bool) {
        if !openat2_available(res) {
            return;
        }
        assert_eq!(
            res.is_ok(),
            expect_ok,
            "openat2 result did not match expectation (expected ok = {expect_ok})"
        );
    }

    // Asserts the per-component walk result.
    fn check_walk(res: &io::Result<AlignedFile>, expect_ok: bool) {
        assert_eq!(
            res.is_ok(),
            expect_ok,
            "walk result did not match expectation (expected ok = {expect_ok})"
        );
    }

    #[test]
    fn open_extent_opens_regular_file() {
        use vmm_sys_util::tempdir::TempDir;

        let dir = TempDir::new_with_prefix("/tmp/vmdk-regular-test").unwrap();
        let base = dir.as_path();
        fs::write(base.join("disk-flat.vmdk"), b"data").unwrap();

        let (openat2_res, walk_res) = open_both(base, "disk-flat.vmdk", false, false);
        check_openat2(&openat2_res, true);
        check_walk(&walk_res, true);
    }

    #[test]
    fn open_extent_opens_file_in_subdirectory() {
        use vmm_sys_util::tempdir::TempDir;

        // A relative sub-path resolves beneath the descriptor directory.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-subdir-test").unwrap();
        let base = dir.as_path();
        fs::create_dir(base.join("extents")).unwrap();
        fs::write(base.join("extents").join("s001.vmdk"), b"data").unwrap();

        let (openat2_res, walk_res) = open_both(base, "extents/s001.vmdk", false, false);
        check_openat2(&openat2_res, true);
        check_walk(&walk_res, true);
    }

    #[test]
    fn open_extent_opens_absolute_path_within_descriptor_dir() {
        use vmm_sys_util::tempdir::TempDir;

        let dir = TempDir::new_with_prefix("/tmp/vmdk-abs-in-test").unwrap();
        let base = dir.as_path();
        fs::write(base.join("gpt_meta_head.img"), b"data").unwrap();
        let abs = base.join("gpt_meta_head.img");

        let (openat2_res, walk_res) = open_both(base, abs.to_str().unwrap(), false, false);
        check_openat2(&openat2_res, true);
        check_walk(&walk_res, true);
    }

    #[test]
    fn open_extent_opens_absolute_path_outside_descriptor_dir() {
        use vmm_sys_util::tempdir::TempDir;

        let desc_dir = TempDir::new_with_prefix("/tmp/vmdk-desc-test").unwrap();
        let layer_dir = TempDir::new_with_prefix("/tmp/vmdk-layer-test").unwrap();
        fs::write(layer_dir.as_path().join("layer.erofs"), b"data").unwrap();
        let abs = layer_dir.as_path().join("layer.erofs");

        let (openat2_res, walk_res) =
            open_both(desc_dir.as_path(), abs.to_str().unwrap(), false, false);
        check_openat2(&openat2_res, true);
        check_walk(&walk_res, true);
    }

    #[test]
    fn open_extent_rejects_symlinked_final_component_relative() {
        use std::os::unix::fs::symlink;

        use vmm_sys_util::tempdir::TempDir;

        // A bare-named extent that is actually a symlink to a file the guest
        // must never reach. Both implementations refuse it via O_NOFOLLOW.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-symlink-test").unwrap();
        let base = dir.as_path();
        let target = base.join("target-secret");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, base.join("disk-flat.vmdk")).unwrap();

        let (openat2_res, walk_res) = open_both(base, "disk-flat.vmdk", true, false);
        check_openat2(&openat2_res, false);
        check_walk(&walk_res, false);
    }

    #[test]
    fn open_extent_rejects_symlinked_final_component_absolute() {
        use std::os::unix::fs::symlink;

        use vmm_sys_util::tempdir::TempDir;

        // Even for absolute paths, the extent file itself may not be a symlink.
        let dir = TempDir::new_with_prefix("/tmp/vmdk-abs-finalsym-test").unwrap();
        let base = dir.as_path();
        let target = base.join("target-secret");
        fs::write(&target, b"secret").unwrap();
        let link = base.join("extent-link.vmdk");
        symlink(&target, &link).unwrap();

        let (openat2_res, walk_res) = open_both(base, link.to_str().unwrap(), true, false);
        check_openat2(&openat2_res, false);
        check_walk(&walk_res, false);
    }

    #[test]
    fn open_extent_follows_symlinked_intermediate_directory_relative() {
        use std::os::unix::fs::symlink;

        use vmm_sys_util::tempdir::TempDir;

        let dir = TempDir::new_with_prefix("/tmp/vmdk-rel-symdir-test").unwrap();
        let base = dir.as_path();
        fs::create_dir(base.join("real")).unwrap();
        fs::write(base.join("real").join("s001.vmdk"), b"data").unwrap();
        symlink("real", base.join("sub")).unwrap();

        let (openat2_res, walk_res) = open_both(base, "sub/s001.vmdk", false, false);
        check_openat2(&openat2_res, true);
        check_walk(&walk_res, true);
    }

    #[test]
    fn open_extent_openat2_rejects_relative_symlink_escape() {
        use std::os::unix::fs::symlink;

        use vmm_sys_util::tempdir::TempDir;

        let outside = TempDir::new_with_prefix("/tmp/vmdk-escape-outside").unwrap();
        fs::write(outside.as_path().join("s001.vmdk"), b"secret").unwrap();

        let dir = TempDir::new_with_prefix("/tmp/vmdk-escape-anchor").unwrap();
        let base = dir.as_path();
        symlink(outside.as_path(), base.join("sub")).unwrap();

        let anchor = open_dir(base);
        let res = open_extent_openat2(anchor.as_raw_fd(), "sub/s001.vmdk", false, false);
        check_openat2(&res, false);
    }

    #[test]
    fn open_extent_follows_symlinked_intermediate_directory_absolute() {
        use std::os::unix::fs::symlink;

        use vmm_sys_util::tempdir::TempDir;

        // An absolute path may likewise traverse a symlinked intermediate
        // directory (common in container deployments).
        let real = TempDir::new_with_prefix("/tmp/vmdk-abs-realdir-test").unwrap();
        fs::write(real.as_path().join("layer.erofs"), b"data").unwrap();

        let dir = TempDir::new_with_prefix("/tmp/vmdk-abs-linkdir-test").unwrap();
        let base = dir.as_path();
        symlink(real.as_path(), base.join("link")).unwrap();

        let via_symlink = base.join("link").join("layer.erofs");
        let (openat2_res, walk_res) = open_both(base, via_symlink.to_str().unwrap(), false, false);
        check_openat2(&openat2_res, true);
        check_walk(&walk_res, true);
    }

    #[test]
    fn open_extent_rejects_parent_dir_traversal() {
        use vmm_sys_util::tempdir::TempDir;

        // Layout:
        //   root/
        //     secret     <- must NOT be reachable through the extent name
        //     anchor/    <- the "descriptor directory" used as the open anchor
        let root = TempDir::new_with_prefix("/tmp/vmdk-traversal-test").unwrap();
        let anchor = root.as_path().join("anchor");
        fs::create_dir(&anchor).unwrap();
        fs::write(root.as_path().join("secret"), b"secret").unwrap();

        // `..` climbs out of `anchor` back into `root` and reaches `secret`.
        let (openat2_res, walk_res) = open_both(&anchor, "../secret", false, false);
        check_openat2(&openat2_res, false);
        check_walk(&walk_res, false);
    }

    #[test]
    fn open_extent_rejects_relative_traversal() {
        use vmm_sys_util::tempdir::TempDir;

        let outer = TempDir::new_with_prefix("/tmp/vmdk-traversal-test").unwrap();
        fs::write(outer.as_path().join("escape.vmdk"), b"secret").unwrap();
        let base = outer.as_path().join("descriptor-dir");
        fs::create_dir(&base).unwrap();

        for name in [
            "../escape.vmdk",
            "./../escape.vmdk",
            "sub/../../escape.vmdk",
        ] {
            let (openat2_res, walk_res) = open_both(&base, name, true, false);
            check_openat2(&openat2_res, false);
            check_walk(&walk_res, false);
        }

        let err =
            open_extent(base.to_str().unwrap(), "../escape.vmdk", true, false, None).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EXDEV),
            "extent traversal must fail with EXDEV, not fall back to the walk"
        );
    }
}
