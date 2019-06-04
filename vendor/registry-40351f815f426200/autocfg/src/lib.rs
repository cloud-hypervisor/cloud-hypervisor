//! A Rust library for build scripts to automatically configure code based on
//! compiler support.  Code snippets are dynamically tested to see if the `rustc`
//! will accept them, rather than hard-coding specific version support.
//!
//!
//! ## Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [build-dependencies]
//! autocfg = "0.1"
//! ```
//!
//! Then use it in your `build.rs` script to detect compiler features.  For
//! example, to test for 128-bit integer support, it might look like:
//!
//! ```rust
//! extern crate autocfg;
//!
//! fn main() {
//! #   // Normally, cargo will set `OUT_DIR` for build scripts.
//! #   std::env::set_var("OUT_DIR", "target");
//!     let ac = autocfg::new();
//!     ac.emit_has_type("i128");
//!
//!     // (optional) We don't need to rerun for anything external.
//!     autocfg::rerun_path(file!());
//! }
//! ```
//!
//! If the type test succeeds, this will write a `cargo:rustc-cfg=has_i128` line
//! for Cargo, which translates to Rust arguments `--cfg has_i128`.  Then in the
//! rest of your Rust code, you can add `#[cfg(has_i128)]` conditions on code that
//! should only be used when the compiler supports it.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{stderr, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[allow(deprecated)]
use std::sync::atomic::ATOMIC_USIZE_INIT;
use std::sync::atomic::{AtomicUsize, Ordering};

mod error;
pub use error::Error;

mod version;
use version::Version;

#[cfg(test)]
mod tests;

/// Helper to detect compiler features for `cfg` output in build scripts.
#[derive(Clone, Debug)]
pub struct AutoCfg {
    out_dir: PathBuf,
    rustc: PathBuf,
    rustc_version: Version,
    target: Option<OsString>,
    no_std: bool,
}

/// Writes a config flag for rustc on standard out.
///
/// This looks like: `cargo:rustc-cfg=CFG`
///
/// Cargo will use this in arguments to rustc, like `--cfg CFG`.
pub fn emit(cfg: &str) {
    println!("cargo:rustc-cfg={}", cfg);
}

/// Writes a line telling Cargo to rerun the build script if `path` changes.
///
/// This looks like: `cargo:rerun-if-changed=PATH`
///
/// This requires at least cargo 0.7.0, corresponding to rustc 1.6.0.  Earlier
/// versions of cargo will simply ignore the directive.
pub fn rerun_path(path: &str) {
    println!("cargo:rerun-if-changed={}", path);
}

/// Writes a line telling Cargo to rerun the build script if the environment
/// variable `var` changes.
///
/// This looks like: `cargo:rerun-if-env-changed=VAR`
///
/// This requires at least cargo 0.21.0, corresponding to rustc 1.20.0.  Earlier
/// versions of cargo will simply ignore the directive.
pub fn rerun_env(var: &str) {
    println!("cargo:rerun-if-env-changed={}", var);
}

/// Create a new `AutoCfg` instance.
///
/// # Panics
///
/// Panics if `AutoCfg::new()` returns an error.
pub fn new() -> AutoCfg {
    AutoCfg::new().unwrap()
}

impl AutoCfg {
    /// Create a new `AutoCfg` instance.
    ///
    /// # Common errors
    ///
    /// - `rustc` can't be executed, from `RUSTC` or in the `PATH`.
    /// - The version output from `rustc` can't be parsed.
    /// - `OUT_DIR` is not set in the environment, or is not a writable directory.
    ///
    pub fn new() -> Result<Self, Error> {
        match env::var_os("OUT_DIR") {
            Some(d) => Self::with_dir(d),
            None => Err(error::from_str("no OUT_DIR specified!")),
        }
    }

    /// Create a new `AutoCfg` instance with the specified output directory.
    ///
    /// # Common errors
    ///
    /// - `rustc` can't be executed, from `RUSTC` or in the `PATH`.
    /// - The version output from `rustc` can't be parsed.
    /// - `dir` is not a writable directory.
    ///
    pub fn with_dir<T: Into<PathBuf>>(dir: T) -> Result<Self, Error> {
        let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let rustc: PathBuf = rustc.into();
        let rustc_version = try!(Version::from_rustc(&rustc));

        // Sanity check the output directory
        let dir = dir.into();
        let meta = try!(fs::metadata(&dir).map_err(error::from_io));
        if !meta.is_dir() || meta.permissions().readonly() {
            return Err(error::from_str("output path is not a writable directory"));
        }

        let mut ac = AutoCfg {
            out_dir: dir,
            rustc: rustc,
            rustc_version: rustc_version,
            target: env::var_os("TARGET"),
            no_std: false,
        };

        // Sanity check with and without `std`.
        if !ac.probe("").unwrap_or(false) {
            ac.no_std = true;
            if !ac.probe("").unwrap_or(false) {
                // Neither worked, so assume nothing...
                ac.no_std = false;
                let warning = b"warning: autocfg could not probe for `std`\n";
                stderr().write_all(warning).ok();
            }
        }
        Ok(ac)
    }

    /// Test whether the current `rustc` reports a version greater than
    /// or equal to "`major`.`minor`".
    pub fn probe_rustc_version(&self, major: usize, minor: usize) -> bool {
        self.rustc_version >= Version::new(major, minor, 0)
    }

    /// Sets a `cfg` value of the form `rustc_major_minor`, like `rustc_1_29`,
    /// if the current `rustc` is at least that version.
    pub fn emit_rustc_version(&self, major: usize, minor: usize) {
        if self.probe_rustc_version(major, minor) {
            emit(&format!("rustc_{}_{}", major, minor));
        }
    }

    fn probe<T: AsRef<[u8]>>(&self, code: T) -> Result<bool, Error> {
        #[allow(deprecated)]
        static ID: AtomicUsize = ATOMIC_USIZE_INIT;

        let id = ID.fetch_add(1, Ordering::Relaxed);
        let mut command = Command::new(&self.rustc);
        command
            .arg("--crate-name")
            .arg(format!("probe{}", id))
            .arg("--crate-type=lib")
            .arg("--out-dir")
            .arg(&self.out_dir)
            .arg("--emit=llvm-ir");

        if let Some(target) = self.target.as_ref() {
            command.arg("--target").arg(target);
        }

        command.arg("-").stdin(Stdio::piped());
        let mut child = try!(command.spawn().map_err(error::from_io));
        let mut stdin = child.stdin.take().expect("rustc stdin");

        if self.no_std {
            try!(stdin.write_all(b"#![no_std]\n").map_err(error::from_io));
        }
        try!(stdin.write_all(code.as_ref()).map_err(error::from_io));
        drop(stdin);

        let status = try!(child.wait().map_err(error::from_io));
        Ok(status.success())
    }

    /// Tests whether the given path can be used.
    ///
    /// The test code is subject to change, but currently looks like:
    ///
    /// ```ignore
    /// pub use PATH;
    /// ```
    pub fn probe_path(&self, path: &str) -> bool {
        self.probe(format!("pub use {};", path)).unwrap_or(false)
    }

    /// Emits a config value `has_PATH` if `probe_path` returns true.
    ///
    /// Any non-identifier characters in the `path` will be replaced with
    /// `_` in the generated config value.
    pub fn emit_has_path(&self, path: &str) {
        if self.probe_path(path) {
            emit(&format!("has_{}", mangle(path)));
        }
    }

    /// Emits the given `cfg` value if `probe_path` returns true.
    pub fn emit_path_cfg(&self, path: &str, cfg: &str) {
        if self.probe_path(path) {
            emit(cfg);
        }
    }

    /// Tests whether the given trait can be used.
    ///
    /// The test code is subject to change, but currently looks like:
    ///
    /// ```ignore
    /// pub trait Probe: TRAIT + Sized {}
    /// ```
    pub fn probe_trait(&self, name: &str) -> bool {
        self.probe(format!("pub trait Probe: {} + Sized {{}}", name))
            .unwrap_or(false)
    }

    /// Emits a config value `has_TRAIT` if `probe_trait` returns true.
    ///
    /// Any non-identifier characters in the trait `name` will be replaced with
    /// `_` in the generated config value.
    pub fn emit_has_trait(&self, name: &str) {
        if self.probe_trait(name) {
            emit(&format!("has_{}", mangle(name)));
        }
    }

    /// Emits the given `cfg` value if `probe_trait` returns true.
    pub fn emit_trait_cfg(&self, name: &str, cfg: &str) {
        if self.probe_trait(name) {
            emit(cfg);
        }
    }

    /// Tests whether the given type can be used.
    ///
    /// The test code is subject to change, but currently looks like:
    ///
    /// ```ignore
    /// pub type Probe = TYPE;
    /// ```
    pub fn probe_type(&self, name: &str) -> bool {
        self.probe(format!("pub type Probe = {};", name))
            .unwrap_or(false)
    }

    /// Emits a config value `has_TYPE` if `probe_type` returns true.
    ///
    /// Any non-identifier characters in the type `name` will be replaced with
    /// `_` in the generated config value.
    pub fn emit_has_type(&self, name: &str) {
        if self.probe_type(name) {
            emit(&format!("has_{}", mangle(name)));
        }
    }

    /// Emits the given `cfg` value if `probe_type` returns true.
    pub fn emit_type_cfg(&self, name: &str, cfg: &str) {
        if self.probe_type(name) {
            emit(cfg);
        }
    }
}

fn mangle(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'...'Z' | 'a'...'z' | '0'...'9' => c,
            _ => '_',
        })
        .collect()
}
