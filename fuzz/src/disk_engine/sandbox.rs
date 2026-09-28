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
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ORIGINAL_TMPDIR: OnceLock<PathBuf> = OnceLock::new();
static FUZZ_TMPDIR: OnceLock<PathBuf> = OnceLock::new();
static FUZZ_TMPDIR_OWNER: OnceLock<bool> = OnceLock::new();

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

const SHM_ROOT: &str = "/dev/shm";

fn valid_generated_tmpdir(path: &Path, name: &str) -> bool {
    let Ok(canonical) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(root) = fs::canonicalize(SHM_ROOT) else {
        return false;
    };
    let Some(file_name) = canonical.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let prefix = format!("ch-fuzz-{name}-");
    if canonical.parent() != Some(root.as_path()) || !file_name.starts_with(&prefix) {
        return false;
    }
    let Ok(metadata) = fs::metadata(&canonical) else {
        return false;
    };
    metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o777 == 0o700
}

extern "C" fn cleanup_generated_tmpdir() {
    let Some(path) = FUZZ_TMPDIR.get() else {
        return;
    };
    if !FUZZ_TMPDIR_OWNER.get().copied().unwrap_or(false) {
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let _ = fs::remove_dir_all(entry.path());
            let _ = fs::remove_file(entry.path());
        }
    }
    let _ = fs::remove_dir(path);
}

/// Resolves `tmpdir` before checking whether it is inside `cwd`.
fn local_tmpdir(cwd: &Path, tmpdir: &Path) -> Option<PathBuf> {
    let cwd = fs::canonicalize(cwd).ok()?;
    let tmpdir = fs::canonicalize(tmpdir).ok()?;
    (tmpdir.is_dir() && tmpdir.starts_with(cwd)).then_some(tmpdir)
}

/// Keep libFuzzer's temporary fork tree in tmpfs when the supplied TMPDIR is
/// external. This runs before FuzzWithFork creates its directory.
pub fn prepare_tmpdir(name: &str) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let tmpdir = std::env::temp_dir();
    let original = fs::canonicalize(&tmpdir).unwrap_or_else(|_| tmpdir.clone());
    let _ = ORIGINAL_TMPDIR.set(original.clone());
    if let Some(local) = local_tmpdir(&cwd, &tmpdir) {
        std::env::set_var("TMPDIR", &local);
        let _ = FUZZ_TMPDIR.set(local);
        let _ = FUZZ_TMPDIR_OWNER.set(false);
        return;
    }

    if valid_generated_tmpdir(&tmpdir, name) {
        std::env::set_var("TMPDIR", &original);
        let _ = FUZZ_TMPDIR.set(original);
        let _ = FUZZ_TMPDIR_OWNER.set(false);
        return;
    }

    let root = Path::new(SHM_ROOT);
    if root.is_dir() {
        let path = root.join(format!("ch-fuzz-{name}-{}", std::process::id()));
        if fs::DirBuilder::new().mode(0o700).create(&path).is_ok() {
            if valid_generated_tmpdir(&path, name) {
                std::env::set_var("TMPDIR", &path);
                let _ = FUZZ_TMPDIR.set(path);
                let _ = FUZZ_TMPDIR_OWNER.set(true);
                // SAFETY: handler only removes this process-owned directory.
                unsafe { libc::atexit(cleanup_generated_tmpdir) };
                return;
            }
            let _ = fs::remove_dir(&path);
        }
    }
    eprintln!("disk fuzz sandbox: /dev/shm unavailable, using cwd for TMPDIR");
    let cwd = fs::canonicalize(&cwd).unwrap_or(cwd);
    std::env::set_var("TMPDIR", &cwd);
    let _ = FUZZ_TMPDIR.set(cwd);
    let _ = FUZZ_TMPDIR_OWNER.set(false);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathAccess {
    Read,
    Write,
}

fn argument_path(arg: &str) -> Option<PathBuf> {
    let value = arg.split_once('=').map_or(arg, |(_, v)| v);
    let value = value.strip_prefix('@').unwrap_or(value);
    (!value.is_empty()).then(|| PathBuf::from(value))
}

fn output_path(arg: &str) -> Option<(PathBuf, bool)> {
    [
        ("-exact_artifact_path=", false),
        ("-merge_control_file=", false),
        ("-mutation_graph_file=", false),
        ("-features_dir=", false),
        ("-artifact_prefix=", true),
    ]
    .iter()
    .find_map(|(prefix, is_prefix)| {
        arg.strip_prefix(prefix)
            .map(|value| (PathBuf::from(value), *is_prefix))
    })
}

/// Return a writable output path, or its existing canonical parent when the
/// output does not exist. Only recognized libFuzzer output flags use parents.
fn writable_output_path(path: &Path, original_tmpdir: &Path, is_prefix: bool) -> Option<PathBuf> {
    if path.exists() {
        let canonical = fs::canonicalize(path).ok()?;
        let target = if is_prefix && canonical.is_file() {
            canonical.parent()?.to_path_buf()
        } else {
            canonical
        };
        return (target != Path::new("/") && target != original_tmpdir).then_some(target);
    }
    let parent = fs::canonicalize(path.parent()?).ok()?;
    (parent != Path::new("/") && parent != original_tmpdir).then_some(parent)
}

/// The working directory, corpus directories, and exact command-line files.
/// Positional files and input metadata are read-only; recognized output paths
/// are writable without granting unknown flags access to their parents.
fn fuzzer_paths_from(args: impl Iterator<Item = String>) -> Vec<(PathBuf, PathAccess)> {
    let mut paths = Vec::new();
    let original_tmpdir = ORIGINAL_TMPDIR.get().cloned().unwrap_or_else(|| {
        let tmpdir = std::env::temp_dir();
        fs::canonicalize(&tmpdir).unwrap_or(tmpdir)
    });
    if let Ok(cwd) = std::env::current_dir() {
        paths.push((cwd, PathAccess::Write));
    }
    for arg in args {
        if arg.starts_with("-seed_inputs=") {
            continue;
        }
        if let Some((path, is_prefix)) = output_path(&arg) {
            if let Some(path) = writable_output_path(&path, &original_tmpdir, is_prefix) {
                paths.push((path, PathAccess::Write));
            }
            continue;
        }
        let Some(path) = argument_path(&arg) else {
            continue;
        };
        if !arg.starts_with('-') && path.is_dir() {
            paths.push((path, PathAccess::Write));
        } else if path.is_file() {
            paths.push((path, PathAccess::Read));
        }
    }
    paths
}

fn fuzzer_paths() -> Vec<(PathBuf, PathAccess)> {
    fuzzer_paths_from(std::env::args().skip(1))
}

/// Files named by explicit libFuzzer `-seed_inputs` metadata. `@` applies only
/// to a value whose first byte is `@`; both forms are a single CSV string.
fn seed_paths_from(args: impl Iterator<Item = String>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for arg in args {
        let Some(value) = arg.strip_prefix("-seed_inputs=") else {
            continue;
        };
        let entries = if let Some(list_name) = value.strip_prefix('@') {
            let list = Path::new(list_name);
            let Ok(contents) = fs::read_to_string(list) else {
                continue;
            };
            paths.push(list.to_path_buf());
            contents
        } else {
            value.to_owned()
        };
        for entry in entries.split(',') {
            let path = Path::new(entry);
            if path.is_file() {
                paths.push(path.to_path_buf());
            }
        }
    }
    paths
}

fn seed_paths() -> Vec<PathBuf> {
    seed_paths_from(std::env::args().skip(1))
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

        // Fork workers may re-exec the fuzz binary after confinement.
        let executable = std::env::current_exe().map_err(|_| ())?;
        add_rule(ruleset_fd, &executable, read)?;

        // The images and backing files live here.
        add_rule(ruleset_fd, scratch, write)?;
        if let Some(tmpdir) = FUZZ_TMPDIR.get() {
            add_rule(ruleset_fd, tmpdir, write)?;
        }

        for (path, access) in fuzzer_paths() {
            let access = match access {
                PathAccess::Read => read,
                PathAccess::Write => write,
            };
            add_rule(ruleset_fd, &path, access)?;
        }
        // Seed inputs remain read-only.
        for path in seed_paths() {
            add_rule(ruleset_fd, &path, read)?;
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

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ch-fuzz-{label}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

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

    #[test]
    fn cwd_local_tmpdir_cannot_escape_through_a_symlink() {
        let base = test_path("local-tmp");
        let cwd = base.join("cwd");
        let outside = base.join("outside");
        fs::create_dir_all(&cwd).expect("cwd");
        fs::create_dir(&outside).expect("outside");
        fs::create_dir(cwd.join("inside")).expect("inside");
        std::os::unix::fs::symlink(&outside, cwd.join("link")).expect("external symlink");

        assert_eq!(
            local_tmpdir(&cwd, &cwd.join("inside")),
            fs::canonicalize(cwd.join("inside")).ok()
        );
        assert_eq!(local_tmpdir(&cwd, &cwd.join("link")), None);
        fs::remove_dir_all(base).expect("remove test directories");
    }

    #[test]
    fn generated_tmpdir_validation_requires_owned_mode0700_shm_directory() {
        let name = format!("validation-{}", std::process::id());
        let path = Path::new(SHM_ROOT).join(format!("ch-fuzz-{name}-test"));
        if fs::create_dir(&path).is_err() {
            eprintln!("skipped: /dev/shm unavailable");
            return;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("permissions");
        assert!(valid_generated_tmpdir(&path, &name));
        assert!(!valid_generated_tmpdir(Path::new(SHM_ROOT), &name));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("permissions");
        assert!(!valid_generated_tmpdir(&path, &name));
        fs::remove_dir(path).expect("remove test directory");
    }

    #[test]
    fn generated_tmpdir_validation_rejects_wrong_prefix() {
        let path = Path::new(SHM_ROOT).join(format!("not-ch-fuzz-{}", std::process::id()));
        if fs::create_dir(&path).is_err() {
            eprintln!("skipped: /dev/shm unavailable");
            return;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("permissions");
        assert!(!valid_generated_tmpdir(&path, "wrong-prefix"));
        fs::remove_dir(path).expect("remove test directory");
    }

    #[test]
    fn positional_files_are_not_seed_lists() {
        let file = test_path("positional").with_extension("txt");
        std::fs::write(&file, "/etc/passwd\n").expect("positional input");
        let paths = fuzzer_paths_from([file.to_string_lossy().into_owned()].into_iter());
        assert!(!paths
            .iter()
            .any(|(path, _)| path == Path::new("/etc/passwd")));
        assert!(
            !seed_paths_from([file.to_string_lossy().into_owned()].into_iter())
                .contains(&PathBuf::from("/etc/passwd"))
        );
        std::fs::remove_file(file).expect("remove positional input");
    }

    #[test]
    fn seed_inputs_support_direct_and_at_list_comma_syntax() {
        let base = test_path("seeds");
        let first = base.with_extension("first");
        let second = base.with_extension("second");
        let list = base.with_extension("list");
        std::fs::write(&first, b"first").expect("first seed");
        std::fs::write(&second, b"second").expect("second seed");
        std::fs::write(&list, format!("{},{}", first.display(), second.display()))
            .expect("seed list");

        let direct = seed_paths_from(
            [format!(
                "-seed_inputs={},{}",
                first.display(),
                second.display()
            )]
            .into_iter(),
        );
        assert!(direct.contains(&first));
        assert!(direct.contains(&second));
        let listed = seed_paths_from([format!("-seed_inputs=@{}", list.display())].into_iter());
        assert!(listed.contains(&list));
        assert!(listed.contains(&first));
        assert!(listed.contains(&second));

        let newline_list = base.with_extension("newline-list");
        std::fs::write(
            &newline_list,
            format!("{}\n{}", first.display(), second.display()),
        )
        .expect("newline list");
        let newline_paths =
            seed_paths_from([format!("-seed_inputs=@{}", newline_list.display())].into_iter());
        assert_eq!(newline_paths, vec![newline_list.clone()]);

        let whitespace = base.with_extension(" whitespace");
        std::fs::write(&whitespace, b"whitespace").expect("whitespace seed");
        let whitespace_paths =
            seed_paths_from([format!("-seed_inputs={}", whitespace.display())].into_iter());
        assert!(whitespace_paths.contains(&whitespace));

        std::fs::remove_file(newline_list).expect("remove newline list");
        std::fs::remove_file(whitespace).expect("remove whitespace seed");
        std::fs::remove_file(first).expect("remove first seed");
        std::fs::remove_file(second).expect("remove second seed");
        std::fs::remove_file(list).expect("remove seed list");
    }

    #[test]
    fn output_parent_is_writable_only_for_recognized_flags() {
        let base = test_path("output");
        let parent = base.join("parent");
        fs::create_dir_all(&parent).expect("output parent");
        let missing = parent.join("artifact");
        let existing = parent.join("existing-artifact");
        let prefix_file = parent.join("artifact-prefix-file");
        fs::write(&existing, b"artifact").expect("existing artifact");
        fs::write(&prefix_file, b"prefix").expect("existing prefix");
        let output = fuzzer_paths_from(
            [
                format!("-exact_artifact_path={}", missing.display()),
                format!(
                    "-mutation_graph_file={}",
                    parent.join("mutation-graph").display()
                ),
                format!("-features_dir={}", parent.join("features").display()),
                format!("-merge_control_file={}", existing.display()),
                format!("-artifact_prefix={}", prefix_file.display()),
                format!("-unknown={}", parent.join("other").display()),
            ]
            .into_iter(),
        );
        assert!(output.contains(&(parent.clone(), PathAccess::Write)));
        assert!(output.contains(&(existing, PathAccess::Write)));
        assert_eq!(output.iter().filter(|entry| entry.0 == parent).count(), 4);
        // An existing artifact prefix is a string prefix, so its file's parent
        // is authorized rather than the file itself.
        assert!(!output.contains(&(prefix_file, PathAccess::Write)));
        fs::remove_dir_all(base).expect("remove output parent");
    }

    #[test]
    fn existing_output_aliases_cannot_escape_root_or_tmpdir() {
        let base = test_path("output-alias");
        fs::create_dir_all(&base).expect("alias directory");
        let original_tmpdir = fs::canonicalize(std::env::temp_dir()).expect("tmpdir");
        let normal = base.join("normal");
        let root_alias = base.join("root-alias");
        let tmp_alias = base.join("tmp-alias");
        fs::write(&normal, b"output").expect("normal output");
        std::os::unix::fs::symlink("/", &root_alias).expect("root alias");
        std::os::unix::fs::symlink(&original_tmpdir, &tmp_alias).expect("tmp alias");

        assert_eq!(
            writable_output_path(&normal, &original_tmpdir, false),
            Some(fs::canonicalize(&normal).expect("canonical output"))
        );
        assert_eq!(
            writable_output_path(&root_alias, &original_tmpdir, false),
            None
        );
        assert_eq!(
            writable_output_path(&tmp_alias, &original_tmpdir, false),
            None
        );
        fs::remove_dir_all(base).expect("remove alias directory");
    }

    #[test]
    fn positional_directory_is_writable_and_explicit_files_are_exact() {
        let directory = test_path("corpus");
        std::fs::create_dir_all(&directory).expect("corpus directory");
        let file = directory.join("testcase");
        std::fs::write(&file, b"input").expect("testcase");
        let paths = fuzzer_paths_from(
            [
                directory.to_string_lossy().into_owned(),
                file.to_string_lossy().into_owned(),
                "corpus".into(),
                "-seed_inputs=relative-list".into(),
            ]
            .into_iter(),
        );
        assert!(paths.contains(&(directory.clone(), PathAccess::Write)));
        assert!(paths.contains(&(file.clone(), PathAccess::Read)));
        assert!(!paths.iter().any(|(path, _)| path == Path::new("corpus")));
        std::fs::remove_dir_all(directory).expect("remove corpus directory");
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
