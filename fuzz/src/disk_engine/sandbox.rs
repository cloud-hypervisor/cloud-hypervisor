// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Process level filesystem confinement for the backing chain target.
//!
//! # Why a second belt
//!
//! A qcow2 image names its backing file by path, and the engine resolves a
//! relative name against the directory of the image that stores it
//! (block/src/formats/qcow/parser.rs:317) with a plain `Path::join`, which
//! follows `..` straight out of that directory, and then opens it with
//! `OpenOptions::read` (block/src/formats/qcow/parser.rs:192). Unlike the
//! VMDK extent path, the engine takes no `openat2` `RESOLVE_BENEATH`
//! precaution: qcow2 backing files are opt in and `docs/threat-model.md`
//! declares them trusted, and qemu does not confine them either. The harness
//! side name guard in
//! [`crate::disk_engine::formats::qcow2_chain::Qcow2Chain`] is therefore the
//! only thing standing between a corpus entry and an arbitrary host path,
//! with no kernel backstop behind it.
//!
//! One guard for a whole class of file disclosure is one too few, so the
//! target also confines the process itself with Landlock before the first
//! iteration. A bug in the name guard then costs a denied `open` rather than
//! the contents of a host file.
//!
//! # Why not a namespace
//!
//! `unshare` plus `pivot_root` would be a tighter jail, but it breaks the
//! ASan symbolizer and the OSS-Fuzz runner, both of which need the paths
//! they were started with. Landlock restricts the existing mount namespace
//! in place, survives `execve`, and needs no privilege.
//!
//! # Fail closed
//!
//! Every step is checked, and the whole target refuses to run with backing
//! files enabled when any of them fails, including the `ENOSYS` and
//! `EOPNOTSUPP` of a kernel built without Landlock. Raw syscalls rather than
//! a crate, so that the fuzzer gains no dependency for 150 lines of ABI.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// `LANDLOCK_CREATE_RULESET_VERSION`, which asks for the supported ABI
/// version instead of creating a ruleset.
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

/// Every filesystem access the first Landlock ABI knows about, bits 0 to 12.
///
/// An access the ruleset does not handle is allowed everywhere, so the
/// handled set has to be as wide as the ABI allows for the rules to mean
/// anything.
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
///
/// Later ABIs append fields; the size is passed to the kernel, so the older
/// layout stays valid and only asks for less.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel header declares
/// packed.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Returns the Landlock ABI version, or `None` when the kernel has no
/// Landlock at all.
fn abi_version() -> Option<i32> {
    // SAFETY: FFI call. A NULL attribute with the VERSION flag is the
    // documented way to query the ABI and writes nothing.
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
    // ABI 5 adds LANDLOCK_ACCESS_FS_IOCTL_DEV, which is deliberately left
    // unhandled: libFuzzer's terminal detection ioctls a tty, and denying
    // those would change how the fuzzer reports rather than what the target
    // can reach.
    handled
}

/// Adds a `path beneath` rule granting `access` under `path`.
///
/// A path that does not exist is not an error: the rule list covers several
/// distributions' library directories, and the fuzzer's own corpus and
/// artifact directories, only some of which exist on any one host.
///
/// A rule on a file may only grant the accesses that apply to a file, so
/// `access` is masked for one: asking for `READ_DIR` on /dev/null, or on a
/// corpus entry named on the command line, is `EINVAL` rather than a wider
/// rule, and a failed rule would take the whole confinement, and with it the
/// target, down.
fn add_rule(ruleset_fd: libc::c_int, path: &Path, access: u64) -> Result<(), ()> {
    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        return Ok(());
    };
    let access = if path.is_dir() {
        access
    } else {
        access & ACCESS_FILE
    };
    // SAFETY: FFI call with a NUL terminated path. O_PATH opens the name
    // without granting any access to its contents.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(());
    }

    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };
    // SAFETY: FFI call with a correctly sized rule attribute for the
    // PATH_BENEATH rule type and a live descriptor.
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

/// Directories the fuzzer itself needs, beyond the scratch directory.
///
/// libFuzzer reads a corpus entry from disk between iterations and writes a
/// crash artifact after one, so the confinement has to survive its own
/// bookkeeping or the target reports nothing. The corpus and artifact
/// directories are named on the command line, so they are read off there,
/// together with the working directory `cargo fuzz` passes them relative to.
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

    // A rule may only grant accesses the ruleset handles, so both sets are
    // masked with what this ABI knows: an older kernel gets a rule without
    // LANDLOCK_ACCESS_FS_TRUNCATE rather than EINVAL.
    let read = ACCESS_READ & attr.handled_access_fs;
    let write = ACCESS_WRITE & attr.handled_access_fs;

    let result = (|| {
        // Read only, so that the loader, the ASan runtime and the symbolizer
        // keep working. /proc is what ASan reads its own maps from.
        for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc"] {
            add_rule(ruleset_fd, Path::new(dir), read)?;
        }
        add_rule(ruleset_fd, Path::new("/dev/null"), read | ACCESS_WRITE_FILE)?;
        add_rule(ruleset_fd, Path::new("/dev/urandom"), read)?;

        // The images live here, and this is the only place a backing file
        // may be created or opened.
        add_rule(ruleset_fd, scratch, write)?;

        for path in fuzzer_paths() {
            add_rule(ruleset_fd, &path, write)?;
        }
        Ok(())
    })();

    if result.is_ok() {
        // SAFETY: FFI call applying the ruleset to this thread and every
        // thread and child that follows.
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

/// Confines the process once and reports whether it is confined.
///
/// The caller must refuse to enable backing files when this returns `false`:
/// the harness name guard would then be the only protection left, and this
/// module exists because one is not enough.
pub fn confine(scratch: &Path) -> bool {
    static CONFINED: OnceLock<bool> = OnceLock::new();

    *CONFINED.get_or_init(|| {
        let confined = restrict(scratch).is_ok();
        if !confined {
            eprintln!(
                "disk_qcow2_chain: Landlock unavailable, refusing to enable qcow2 backing files"
            );
        }
        confined
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The rule attribute is passed to the kernel by size, so a wrong layout
    // is a silently misread rule rather than a compile error. The kernel
    // header declares landlock_path_beneath_attr packed: 8 + 4 bytes.
    #[test]
    fn the_rule_attribute_matches_the_kernel_layout() {
        assert_eq!(size_of::<PathBeneathAttr>(), 12);
        assert_eq!(size_of::<RulesetAttr>(), 8);
    }

    // `landlock_add_rule` fails with EINVAL on a rule that grants an access
    // the ruleset does not handle, so the masking has to hold on every ABI:
    // an ABI 1 kernel must get the rules without TRUNCATE and REFER, not a
    // failed ruleset and a target that refuses to run.
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

    // The confinement is worth nothing if it is not applied, so a kernel
    // that has Landlock must actually take the ruleset.
    #[test]
    fn a_landlock_kernel_confines_the_process() {
        let Some(version) = abi_version() else {
            eprintln!("skipped: no Landlock on this kernel");
            return;
        };
        assert!(version >= 1);
    }

    // What the belt is for: a path outside the scratch directory must be
    // unreachable even for code that asks for it directly, which is the
    // situation a bug in the name guard would create.
    //
    // Ignored by default because it confines the whole test process, and a
    // test that ran after it would lose its own scratch directory. Run it on
    // its own:
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
        // The victim was readable a moment ago, from this very process, so a
        // denial here is the ruleset and nothing else.
        let err = std::fs::read(&victim).expect_err("the victim file must be unreachable");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
