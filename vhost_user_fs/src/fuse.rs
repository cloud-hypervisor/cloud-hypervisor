// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;

use bitflags::bitflags;
use libc;
use vm_memory::ByteValued;

/// Version number of this interface.
pub const KERNEL_VERSION: u32 = 7;

/// Minor version number of this interface.
pub const KERNEL_MINOR_VERSION: u32 = 27;

/// The ID of the inode corresponding to the root directory of the file system.
pub const ROOT_ID: u64 = 1;

// Bitmasks for `fuse_setattr_in.valid`.
const FATTR_MODE: u32 = 1;
const FATTR_UID: u32 = 2;
const FATTR_GID: u32 = 4;
const FATTR_SIZE: u32 = 8;
const FATTR_ATIME: u32 = 16;
const FATTR_MTIME: u32 = 32;
pub const FATTR_FH: u32 = 64;
const FATTR_ATIME_NOW: u32 = 128;
const FATTR_MTIME_NOW: u32 = 256;
pub const FATTR_LOCKOWNER: u32 = 512;
const FATTR_CTIME: u32 = 1024;

bitflags! {
    pub struct SetattrValid: u32 {
        const MODE = FATTR_MODE;
        const UID = FATTR_UID;
        const GID = FATTR_GID;
        const SIZE = FATTR_SIZE;
        const ATIME = FATTR_ATIME;
        const MTIME = FATTR_MTIME;
        const ATIME_NOW = FATTR_ATIME_NOW;
        const MTIME_NOW = FATTR_MTIME_NOW;
        const CTIME = FATTR_CTIME;
    }
}

// Flags returned by the OPEN request.

/// Bypass page cache for this open file.
const FOPEN_DIRECT_IO: u32 = 1;

/// Don't invalidate the data cache on open.
const FOPEN_KEEP_CACHE: u32 = 2;

/// The file is not seekable.
const FOPEN_NONSEEKABLE: u32 = 4;

bitflags! {
    /// Options controlling the behavior of files opened by the server in response
    /// to an open or create request.
    pub struct OpenOptions: u32 {
        const DIRECT_IO = FOPEN_DIRECT_IO;
        const KEEP_CACHE = FOPEN_KEEP_CACHE;
        const NONSEEKABLE = FOPEN_NONSEEKABLE;
    }
}

// INIT request/reply flags.

/// Asynchronous read requests.
const ASYNC_READ: u32 = 1;

/// Remote locking for POSIX file locks.
const POSIX_LOCKS: u32 = 2;

/// Kernel sends file handle for fstat, etc... (not yet supported).
const FILE_OPS: u32 = 4;

/// Handles the O_TRUNC open flag in the filesystem.
const ATOMIC_O_TRUNC: u32 = 8;

/// FileSystem handles lookups of "." and "..".
const EXPORT_SUPPORT: u32 = 16;

/// FileSystem can handle write size larger than 4kB.
const BIG_WRITES: u32 = 32;

/// Don't apply umask to file mode on create operations.
const DONT_MASK: u32 = 64;

/// Kernel supports splice write on the device.
const SPLICE_WRITE: u32 = 128;

/// Kernel supports splice move on the device.
const SPLICE_MOVE: u32 = 256;

/// Kernel supports splice read on the device.
const SPLICE_READ: u32 = 512;

/// Remote locking for BSD style file locks.
const FLOCK_LOCKS: u32 = 1024;

/// Kernel supports ioctl on directories.
const HAS_IOCTL_DIR: u32 = 2048;

/// Automatically invalidate cached pages.
const AUTO_INVAL_DATA: u32 = 4096;

/// Do READDIRPLUS (READDIR+LOOKUP in one).
const DO_READDIRPLUS: u32 = 8192;

/// Adaptive readdirplus.
const READDIRPLUS_AUTO: u32 = 16384;

/// Asynchronous direct I/O submission.
const ASYNC_DIO: u32 = 32768;

/// Use writeback cache for buffered writes.
const WRITEBACK_CACHE: u32 = 65536;

/// Kernel supports zero-message opens.
const NO_OPEN_SUPPORT: u32 = 131_072;

/// Allow parallel lookups and readdir.
const PARALLEL_DIROPS: u32 = 262_144;

/// Fs handles killing suid/sgid/cap on write/chown/trunc.
const HANDLE_KILLPRIV: u32 = 524_288;

/// FileSystem supports posix acls.
const POSIX_ACL: u32 = 1_048_576;

bitflags! {
    /// A bitfield passed in as a parameter to and returned from the `init` method of the
    /// `FileSystem` trait.
    pub struct FsOptions: u32 {
        /// Indicates that the filesystem supports asynchronous read requests.
        ///
        /// If this capability is not requested/available, the kernel will ensure that there is at
        /// most one pending read request per file-handle at any time, and will attempt to order
        /// read requests by increasing offset.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const ASYNC_READ = ASYNC_READ;

        /// Indicates that the filesystem supports "remote" locking.
        ///
        /// This feature is not enabled by default and should only be set if the filesystem
        /// implements the `getlk` and `setlk` methods of the `FileSystem` trait.
        const POSIX_LOCKS = POSIX_LOCKS;

        /// Kernel sends file handle for fstat, etc... (not yet supported).
        const FILE_OPS = FILE_OPS;

        /// Indicates that the filesystem supports the `O_TRUNC` open flag. If disabled, and an
        /// application specifies `O_TRUNC`, fuse first calls `setattr` to truncate the file and
        /// then calls `open` with `O_TRUNC` filtered out.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const ATOMIC_O_TRUNC = ATOMIC_O_TRUNC;

        /// Indicates that the filesystem supports lookups of "." and "..".
        ///
        /// This feature is disabled by default.
        const EXPORT_SUPPORT = EXPORT_SUPPORT;

        /// FileSystem can handle write size larger than 4kB.
        const BIG_WRITES = BIG_WRITES;

        /// Indicates that the kernel should not apply the umask to the file mode on create
        /// operations.
        ///
        /// This feature is disabled by default.
        const DONT_MASK = DONT_MASK;

        /// Indicates that the server should try to use `splice(2)` when writing to the fuse device.
        /// This may improve performance.
        ///
        /// This feature is not currently supported.
        const SPLICE_WRITE = SPLICE_WRITE;

        /// Indicates that the server should try to move pages instead of copying when writing to /
        /// reading from the fuse device. This may improve performance.
        ///
        /// This feature is not currently supported.
        const SPLICE_MOVE = SPLICE_MOVE;

        /// Indicates that the server should try to use `splice(2)` when reading from the fuse
        /// device. This may improve performance.
        ///
        /// This feature is not currently supported.
        const SPLICE_READ = SPLICE_READ;

        /// If set, then calls to `flock` will be emulated using POSIX locks and must
        /// then be handled by the filesystem's `setlock()` handler.
        ///
        /// If not set, `flock` calls will be handled by the FUSE kernel module internally (so any
        /// access that does not go through the kernel cannot be taken into account).
        ///
        /// This feature is disabled by default.
        const FLOCK_LOCKS = FLOCK_LOCKS;

        /// Indicates that the filesystem supports ioctl's on directories.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const HAS_IOCTL_DIR = HAS_IOCTL_DIR;

        /// Traditionally, while a file is open the FUSE kernel module only asks the filesystem for
        /// an update of the file's attributes when a client attempts to read beyond EOF. This is
        /// unsuitable for e.g. network filesystems, where the file contents may change without the
        /// kernel knowing about it.
        ///
        /// If this flag is set, FUSE will check the validity of the attributes on every read. If
        /// the attributes are no longer valid (i.e., if the *attribute* timeout has expired) then
        /// FUSE will first send another `getattr` request. If the new mtime differs from the
        /// previous value, any cached file *contents* will be invalidated as well.
        ///
        /// This flag should always be set when available. If all file changes go through the
        /// kernel, *attribute* validity should be set to a very large number to avoid unnecessary
        /// `getattr()` calls.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const AUTO_INVAL_DATA = AUTO_INVAL_DATA;

        /// Indicates that the filesystem supports readdirplus.
        ///
        /// The feature is not enabled by default and should only be set if the filesystem
        /// implements the `readdirplus` method of the `FileSystem` trait.
        const DO_READDIRPLUS = DO_READDIRPLUS;

        /// Indicates that the filesystem supports adaptive readdirplus.
        ///
        /// If `DO_READDIRPLUS` is not set, this flag has no effect.
        ///
        /// If `DO_READDIRPLUS` is set and this flag is not set, the kernel will always issue
        /// `readdirplus()` requests to retrieve directory contents.
        ///
        /// If `DO_READDIRPLUS` is set and this flag is set, the kernel will issue both `readdir()`
        /// and `readdirplus()` requests, depending on how much information is expected to be
        /// required.
        ///
        /// This feature is not enabled by default and should only be set if the file system
        /// implements both the `readdir` and `readdirplus` methods of the `FileSystem` trait.
        const READDIRPLUS_AUTO = READDIRPLUS_AUTO;

        /// Indicates that the filesystem supports asynchronous direct I/O submission.
        ///
        /// If this capability is not requested/available, the kernel will ensure that there is at
        /// most one pending read and one pending write request per direct I/O file-handle at any
        /// time.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const ASYNC_DIO = ASYNC_DIO;

        /// Indicates that writeback caching should be enabled. This means that individual write
        /// request may be buffered and merged in the kernel before they are sent to the file
        /// system.
        ///
        /// This feature is disabled by default.
        const WRITEBACK_CACHE = WRITEBACK_CACHE;

        /// Indicates support for zero-message opens. If this flag is set in the `capable` parameter
        /// of the `init` trait method, then the file system may return `ENOSYS` from the open() handler
        /// to indicate success. Further attempts to open files will be handled in the kernel. (If
        /// this flag is not set, returning ENOSYS will be treated as an error and signaled to the
        /// caller).
        ///
        /// Setting (or not setting) the field in the `FsOptions` returned from the `init` method
        /// has no effect.
        const ZERO_MESSAGE_OPEN = NO_OPEN_SUPPORT;

        /// Indicates support for parallel directory operations. If this flag is unset, the FUSE
        /// kernel module will ensure that lookup() and readdir() requests are never issued
        /// concurrently for the same directory.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const PARALLEL_DIROPS = PARALLEL_DIROPS;

        /// Indicates that the file system is responsible for unsetting setuid and setgid bits when a
        /// file is written, truncated, or its owner is changed.
        ///
        /// This feature is enabled by default when supported by the kernel.
        const HANDLE_KILLPRIV = HANDLE_KILLPRIV;

        /// Indicates support for POSIX ACLs.
        ///
        /// If this feature is enabled, the kernel will cache and have responsibility for enforcing
        /// ACLs. ACL will be stored as xattrs and passed to userspace, which is responsible for
        /// updating the ACLs in the filesystem, keeping the file mode in sync with the ACL, and
        /// ensuring inheritance of default ACLs when new filesystem nodes are created. Note that
        /// this requires that the file system is able to parse and interpret the xattr
        /// representation of ACLs.
        ///
        /// Enabling this feature implicitly turns on the `default_permissions` mount option (even
        /// if it was not passed to mount(2)).
        ///
        /// This feature is disabled by default.
        const POSIX_ACL = POSIX_ACL;
    }
}

// Release flags.
pub const RELEASE_FLUSH: u32 = 1;
pub const RELEASE_FLOCK_UNLOCK: u32 = 2;

// Getattr flags.
pub const GETATTR_FH: u32 = 1;

// Lock flags.
pub const LK_FLOCK: u32 = 1;

// Write flags.

/// Delayed write from page cache, file handle is guessed.
pub const WRITE_CACHE: u32 = 1;

/// `lock_owner` field is valid.
pub const WRITE_LOCKOWNER: u32 = 2;

// Read flags.
pub const READ_LOCKOWNER: u32 = 2;

// Ioctl flags.

/// 32bit compat ioctl on 64bit machine
const IOCTL_COMPAT: u32 = 1;

/// Not restricted to well-formed ioctls, retry allowed
const IOCTL_UNRESTRICTED: u32 = 2;

/// Retry with new iovecs
const IOCTL_RETRY: u32 = 4;

/// 32bit ioctl
const IOCTL_32BIT: u32 = 8;

/// Is a directory
const IOCTL_DIR: u32 = 16;

/// Maximum of in_iovecs + out_iovecs
const IOCTL_MAX_IOV: u32 = 256;

bitflags! {
    pub struct IoctlFlags: u32 {
        /// 32bit compat ioctl on 64bit machine
        const IOCTL_COMPAT = IOCTL_COMPAT;

        /// Not restricted to well-formed ioctls, retry allowed
        const IOCTL_UNRESTRICTED = IOCTL_UNRESTRICTED;

        /// Retry with new iovecs
        const IOCTL_RETRY = IOCTL_RETRY;

        /// 32bit ioctl
        const IOCTL_32BIT = IOCTL_32BIT;

        /// Is a directory
        const IOCTL_DIR = IOCTL_DIR;

        /// Maximum of in_iovecs + out_iovecs
        const IOCTL_MAX_IOV = IOCTL_MAX_IOV;
    }
}

/// Request poll notify.
pub const POLL_SCHEDULE_NOTIFY: u32 = 1;

/// The read buffer is required to be at least 8k, but may be much larger.
pub const FUSE_MIN_READ_BUFFER: u32 = 8192;

pub const FUSE_COMPAT_ENTRY_OUT_SIZE: u32 = 120;
pub const FUSE_COMPAT_ATTR_OUT_SIZE: u32 = 96;
pub const FUSE_COMPAT_MKNOD_IN_SIZE: u32 = 8;
pub const FUSE_COMPAT_WRITE_IN_SIZE: u32 = 24;
pub const FUSE_COMPAT_STATFS_SIZE: u32 = 48;
pub const FUSE_COMPAT_INIT_OUT_SIZE: u32 = 8;
pub const FUSE_COMPAT_22_INIT_OUT_SIZE: u32 = 24;

// Message definitions follow.  It is safe to implement ByteValued for all of these
// because they are POD types.

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub padding: u32,
}
unsafe impl ByteValued for Attr {}

impl From<libc::stat64> for Attr {
    fn from(st: libc::stat64) -> Attr {
        Attr {
            ino: st.st_ino,
            size: st.st_size as u64,
            blocks: st.st_blocks as u64,
            atime: st.st_atime as u64,
            mtime: st.st_mtime as u64,
            ctime: st.st_ctime as u64,
            atimensec: st.st_atime_nsec as u32,
            mtimensec: st.st_mtime_nsec as u32,
            ctimensec: st.st_ctime_nsec as u32,
            mode: st.st_mode,
            nlink: st.st_nlink as u32,
            uid: st.st_uid,
            gid: st.st_gid,
            rdev: st.st_rdev as u32,
            blksize: st.st_blksize as u32,
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Kstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}
unsafe impl ByteValued for Kstatfs {}

impl From<libc::statvfs64> for Kstatfs {
    fn from(st: libc::statvfs64) -> Self {
        Kstatfs {
            blocks: st.f_blocks,
            bfree: st.f_bfree,
            bavail: st.f_bavail,
            files: st.f_files,
            ffree: st.f_ffree,
            bsize: st.f_bsize as u32,
            namelen: st.f_namemax as u32,
            frsize: st.f_frsize as u32,
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FileLock {
    pub start: u64,
    pub end: u64,
    pub type_: u32,
    pub pid: u32, /* tgid */
}
unsafe impl ByteValued for FileLock {}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum Opcode {
    Lookup = 1,
    Forget = 2, /* No Reply */
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Setxattr = 21,
    Getxattr = 22,
    Listxattr = 23,
    Removexattr = 24,
    Flush = 25,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Fsyncdir = 30,
    Getlk = 31,
    Setlk = 32,
    Setlkw = 33,
    Access = 34,
    Create = 35,
    Interrupt = 36,
    Bmap = 37,
    Destroy = 38,
    Ioctl = 39,
    Poll = 40,
    NotifyReply = 41,
    BatchForget = 42,
    Fallocate = 43,
    Readdirplus = 44,
    Rename2 = 45,
    Lseek = 46,
    CopyFileRange = 47,
    SetupMapping = 48,
    RemoveMapping = 49,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum NotifyOpcode {
    Poll = 1,
    InvalInode = 2,
    InvalEntry = 3,
    Store = 4,
    Retrieve = 5,
    Delete = 6,
    CodeMax = 7,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct EntryOut {
    pub nodeid: u64,      /* Inode ID */
    pub generation: u64,  /* Inode generation: nodeid:gen must be unique for the fs's lifetime */
    pub entry_valid: u64, /* Cache timeout for the name */
    pub attr_valid: u64,  /* Cache timeout for the attributes */
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: Attr,
}
unsafe impl ByteValued for EntryOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ForgetIn {
    pub nlookup: u64,
}
unsafe impl ByteValued for ForgetIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ForgetOne {
    pub nodeid: u64,
    pub nlookup: u64,
}
unsafe impl ByteValued for ForgetOne {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BatchForgetIn {
    pub count: u32,
    pub dummy: u32,
}
unsafe impl ByteValued for BatchForgetIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct GetattrIn {
    pub flags: u32,
    pub dummy: u32,
    pub fh: u64,
}
unsafe impl ByteValued for GetattrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct AttrOut {
    pub attr_valid: u64, /* Cache timeout for the attributes */
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: Attr,
}
unsafe impl ByteValued for AttrOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
}
unsafe impl ByteValued for MknodIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MkdirIn {
    pub mode: u32,
    pub umask: u32,
}
unsafe impl ByteValued for MkdirIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RenameIn {
    pub newdir: u64,
}
unsafe impl ByteValued for RenameIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Rename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for Rename2In {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LinkIn {
    pub oldnodeid: u64,
}
unsafe impl ByteValued for LinkIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}
unsafe impl ByteValued for SetattrIn {}

impl Into<libc::stat64> for SetattrIn {
    fn into(self) -> libc::stat64 {
        // Safe because we are zero-initializing a struct with only POD fields.
        let mut out: libc::stat64 = unsafe { mem::zeroed() };
        out.st_mode = self.mode;
        out.st_uid = self.uid;
        out.st_gid = self.gid;
        out.st_size = self.size as i64;
        out.st_atime = self.atime as i64;
        out.st_mtime = self.mtime as i64;
        out.st_ctime = self.ctime as i64;
        out.st_atime_nsec = i64::from(self.atimensec);
        out.st_mtime_nsec = i64::from(self.mtimensec);
        out.st_ctime_nsec = i64::from(self.ctimensec);

        out
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct OpenIn {
    pub flags: u32,
    pub unused: u32,
}
unsafe impl ByteValued for OpenIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub padding: u32,
}
unsafe impl ByteValued for CreateIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct OpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for OpenOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}
unsafe impl ByteValued for ReleaseIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}
unsafe impl ByteValued for FlushIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for ReadIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for WriteIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WriteOut {
    pub size: u32,
    pub padding: u32,
}
unsafe impl ByteValued for WriteOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct StatfsOut {
    pub st: Kstatfs,
}
unsafe impl ByteValued for StatfsOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for FsyncIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SetxattrIn {
    pub size: u32,
    pub flags: u32,
}
unsafe impl ByteValued for SetxattrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct GetxattrIn {
    pub size: u32,
    pub padding: u32,
}
unsafe impl ByteValued for GetxattrIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct GetxattrOut {
    pub size: u32,
    pub padding: u32,
}
unsafe impl ByteValued for GetxattrOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LkIn {
    pub fh: u64,
    pub owner: u64,
    pub lk: FileLock,
    pub lk_flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for LkIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LkOut {
    pub lk: FileLock,
}
unsafe impl ByteValued for LkOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct AccessIn {
    pub mask: u32,
    pub padding: u32,
}
unsafe impl ByteValued for AccessIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}
unsafe impl ByteValued for InitIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub unused: [u32; 9],
}
unsafe impl ByteValued for InitOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InterruptIn {
    pub unique: u64,
}
unsafe impl ByteValued for InterruptIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BmapIn {
    pub block: u64,
    pub blocksize: u32,
    pub padding: u32,
}
unsafe impl ByteValued for BmapIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BmapOut {
    pub block: u64,
}
unsafe impl ByteValued for BmapOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoctlIn {
    pub fh: u64,
    pub flags: u32,
    pub cmd: u32,
    pub arg: u64,
    pub in_size: u32,
    pub out_size: u32,
}
unsafe impl ByteValued for IoctlIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoctlIovec {
    pub base: u64,
    pub len: u64,
}
unsafe impl ByteValued for IoctlIovec {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoctlOut {
    pub result: i32,
    pub flags: u32,
    pub in_iovs: u32,
    pub out_iovs: u32,
}
unsafe impl ByteValued for IoctlOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct PollIn {
    pub fh: u64,
    pub kh: u64,
    pub flags: u32,
    pub events: u32,
}
unsafe impl ByteValued for PollIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct PollOut {
    pub revents: u32,
    pub padding: u32,
}
unsafe impl ByteValued for PollOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NotifyPollWakeupOut {
    pub kh: u64,
}
unsafe impl ByteValued for NotifyPollWakeupOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FallocateIn {
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
    pub padding: u32,
}
unsafe impl ByteValued for FallocateIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}
unsafe impl ByteValued for InHeader {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct OutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}
unsafe impl ByteValued for OutHeader {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Dirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub type_: u32,
    // char name[];
}
unsafe impl ByteValued for Dirent {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Direntplus {
    pub entry_out: EntryOut,
    pub dirent: Dirent,
}
unsafe impl ByteValued for Direntplus {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NotifyInvalInodeOut {
    pub ino: u64,
    pub off: i64,
    pub len: i64,
}
unsafe impl ByteValued for NotifyInvalInodeOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NotifyInvalEntryOut {
    pub parent: u64,
    pub namelen: u32,
    pub padding: u32,
}
unsafe impl ByteValued for NotifyInvalEntryOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NotifyDeleteOut {
    pub parent: u64,
    pub child: u64,
    pub namelen: u32,
    pub padding: u32,
}
unsafe impl ByteValued for NotifyDeleteOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NotifyStoreOut {
    pub nodeid: u64,
    pub offset: u64,
    pub size: u32,
    pub padding: u32,
}
unsafe impl ByteValued for NotifyStoreOut {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Notify_Retrieve_Out {
    pub notify_unique: u64,
    pub nodeid: u64,
    pub offset: u64,
    pub size: u32,
    pub padding: u32,
}
unsafe impl ByteValued for Notify_Retrieve_Out {}

/* Matches the size of fuse_write_in */
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NotifyRetrieveIn {
    pub dummy1: u64,
    pub offset: u64,
    pub size: u32,
    pub dummy2: u32,
    pub dummy3: u64,
    pub dummy4: u64,
}
unsafe impl ByteValued for NotifyRetrieveIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LseekIn {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
    pub padding: u32,
}
unsafe impl ByteValued for LseekIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LseekOut {
    pub offset: u64,
}
unsafe impl ByteValued for LseekOut {}

bitflags! {
    pub struct SetupmappingFlags: u64 {
    const WRITE = 0x1;
    const READ = 0x2;
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct SetupmappingIn {
    pub fh: u64,
    pub foffset: u64,
    pub len: u64,
    pub flags: u64,
    pub moffset: u64,
}

unsafe impl ByteValued for SetupmappingIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RemovemappingIn {
    pub count: u32,
}

unsafe impl ByteValued for RemovemappingIn {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RemovemappingOne {
    pub moffset: u64,
    pub len: u64,
}

unsafe impl ByteValued for RemovemappingOne {}
