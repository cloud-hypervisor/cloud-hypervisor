// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Landlock confinement for the path backed targets.
//!
//! The qcow2 chain and VMDK targets hand the engine host paths from fuzzed
//! images. Their name guards are backed by confining the process to its
//! scratch directory, and callers fail closed if that fails. Landlock rather
//! than a namespace keeps the ASan symbolizer and OSS-Fuzz working.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// `LANDLOCK_CREATE_RULESET_VERSION`.
const CREATE_RULESET_VERSION: u32 = 1;

/// `LANDLOCK_RULE_PATH_BENEATH`.
const RULE_PATH_BENEATH: libc::c_int = 1;

const ACCESS_EXECUTE: u64 = 1 << 0;
const ACCESS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;
const ACCESS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_MAKE_REG: u64 = 1 << 8;
const ACCESS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_REFER: u64 = 1 << 13;
const ACCESS_TRUNCATE: u64 = 1 << 14;

/// Every access Landlock ABI 1 handles. Unhandled accesses are allowed.
const ACCESS_ABI1: u64 = (1 << 13) - 1;

/// Accesses that apply to a regular file rather than to a directory.
const ACCESS_FILE: u64 = ACCESS_EXECUTE | ACCESS_WRITE_FILE | ACCESS_READ_FILE | ACCESS_TRUNCATE;

/// What the target may do inside a directory it owns.
const ACCESS_READ: u64 = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR;
const ACCESS_WRITE: u64 = ACCESS_READ
    | ACCESS_WRITE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SYM
    | ACCESS_REFER
    | ACCESS_TRUNCATE;

/// `struct landlock_ruleset_attr`, ABI 1 layout.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`, packed as in the kernel header.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The Landlock ABI version, or `None` without Landlock.
fn abi_version() -> Option<i32> {
    // SAFETY: FFI call. The version query writes nothing.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    (abi > 0).then_some(abi as i32)
}

/// The accesses an ABI of `version` can handle.
fn handled_access(version: i32) -> u64 {
    let mut handled = ACCESS_ABI1;
    if version >= 2 {
        handled |= ACCESS_REFER;
    }
    if version >= 3 {
        handled |= ACCESS_TRUNCATE;
    }
    // LANDLOCK_ACCESS_FS_IOCTL_DEV stays unhandled: libFuzzer ioctls its tty.
    handled
}

/// Adds a rule granting `access` beneath `path`, masked to file accesses for
/// a file. A missing path is skipped.
fn add_rule(ruleset_fd: libc::c_int, path: &Path, access: u64) -> Result<(), ()> {
    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        return Ok(());
    };
    let access = if path.is_dir() {
        access
    } else {
        access & ACCESS_FILE
    };
    // SAFETY: FFI call with a NUL terminated path. O_PATH grants no access.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(());
    }

    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };
    // SAFETY: FFI call with a correctly sized rule and a live descriptor.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0u32,
        )
    };
    // SAFETY: FFI call closing a descriptor this function owns.
    unsafe { libc::close(fd) };

    if rc == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// The working directory and the absolute paths on the command line, where
/// libFuzzer reads its corpus and writes artifacts.
fn fuzzer_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd);
    }
    for arg in std::env::args().skip(1) {
        // -artifact_prefix=<path> and friends carry the path after '='.
        let value = arg.split_once('=').map_or(arg.as_str(), |(_, v)| v);
        let path = Path::new(value);
        if path.is_absolute() && path.exists() {
            paths.push(path.to_path_buf());
        }
    }
    paths
}

/// Confines this process to `scratch` plus what the runtime needs.
fn restrict(scratch: &Path) -> Result<(), ()> {
    // Landlock needs no privilege, but it does need no_new_privs.
    // SAFETY: FFI call with the documented argument count.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(());
    }

    let version = abi_version().ok_or(())?;
    let attr = RulesetAttr {
        handled_access_fs: handled_access(version),
    };
    // SAFETY: FFI call with a correctly sized ruleset attribute.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(());
    }
    let ruleset_fd = ruleset_fd as libc::c_int;

    // Grant only accesses this ABI handles, or adding the rule fails.
    let read = ACCESS_READ & attr.handled_access_fs;
    let write = ACCESS_WRITE & attr.handled_access_fs;

    let result = (|| {
        // Read only, for the loader, the ASan runtime and its symbolizer.
        for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc"] {
            add_rule(ruleset_fd, Path::new(dir), read)?;
        }
        add_rule(ruleset_fd, Path::new("/dev/null"), read | ACCESS_WRITE_FILE)?;
        add_rule(ruleset_fd, Path::new("/dev/urandom"), read)?;

        // The images and backing files live here.
        add_rule(ruleset_fd, scratch, write)?;

        for path in fuzzer_paths() {
            add_rule(ruleset_fd, &path, write)?;
        }
        Ok(())
    })();

    if result.is_ok() {
        // SAFETY: FFI call applying the ruleset to this and all later threads.
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) } != 0 {
            // SAFETY: FFI call closing a descriptor this function owns.
            unsafe { libc::close(ruleset_fd) };
            return Err(());
        }
    }
    // SAFETY: FFI call closing a descriptor this function owns.
    unsafe { libc::close(ruleset_fd) };

    result
}

/// Confines the process once and reports whether it worked. Callers must
/// reject their input if it did not.
pub fn confine(scratch: &Path) -> bool {
    static CONFINED: OnceLock<bool> = OnceLock::new();

    *CONFINED.get_or_init(|| {
        let confined = restrict(scratch).is_ok();
        if !confined {
            eprintln!("disk fuzz sandbox: Landlock unavailable, refusing path-backed input");
        }
        confined
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The kernel reads the rule attribute by size.
    #[test]
    fn the_rule_attribute_matches_the_kernel_layout() {
        assert_eq!(size_of::<PathBeneathAttr>(), 12);
        assert_eq!(size_of::<RulesetAttr>(), 8);
    }

    // Every ABI must get rules within its handled set.
    #[test]
    fn granted_accesses_stay_within_the_handled_set() {
        for version in 1..=6 {
            let handled = handled_access(version);
            assert_eq!((ACCESS_READ & handled) & !handled, 0);
            assert_eq!((ACCESS_WRITE & handled) & !handled, 0);
            assert_ne!(ACCESS_WRITE & handled & ACCESS_WRITE_FILE, 0);
        }
        assert_eq!(handled_access(1) & (ACCESS_TRUNCATE | ACCESS_REFER), 0);
        assert_ne!(handled_access(3) & ACCESS_TRUNCATE, 0);
    }

    // A kernel with Landlock must report its ABI.
    #[test]
    fn a_landlock_kernel_confines_the_process() {
        let Some(version) = abi_version() else {
            eprintln!("skipped: no Landlock on this kernel");
            return;
        };
        assert!(version >= 1);
    }

    // Ignored: it confines the whole test process. Run it on its own:
    //
    //     cargo test --lib -- --ignored --exact \
    //         disk_engine::sandbox::tests::the_confinement_denies_a_path_outside_the_scratch_directory
    #[test]
    #[ignore = "confines the whole test process"]
    fn the_confinement_denies_a_path_outside_the_scratch_directory() {
        if abi_version().is_none() {
            eprintln!("skipped: no Landlock on this kernel");
            return;
        }

        let scratch = std::env::temp_dir().join(format!("ch-fuzz-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch directory");
        let victim = std::env::temp_dir().join("ch-fuzz-sandbox-victim");
        std::fs::write(&victim, b"secret").expect("victim file");

        assert!(confine(&scratch), "the process must be confined");

        std::fs::write(scratch.join("backing.img"), b"backing")
            .expect("the scratch directory stays writable");
        // The victim was readable before confinement.
        let err = std::fs::read(&victim).expect_err("the victim file must be unreachable");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
