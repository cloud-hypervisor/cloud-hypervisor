// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Parsing of RBD disk paths.
//!
//! The accepted form is `rbd:<pool>/<image>[@<snapshot>]`, matching the
//! familiar `rbd` command line syntax. The parser is kept free of any
//! librbd dependency so that path handling and configuration validation
//! can be tested without Ceph installed.

use std::io;
use std::path::Path;

use crate::error::{BlockError, BlockErrorKind, BlockResult};

/// A parsed `rbd:<pool>/<image>[@<snapshot>]` path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RbdUri {
    /// Ceph pool containing the image.
    pub pool: String,
    /// Image name inside the pool.
    pub image: String,
    /// Optional snapshot name. Read-only must be requested separately.
    pub snapshot: Option<String>,
}

fn invalid(path: &Path, message: impl Into<String>) -> BlockError {
    BlockError::new(
        BlockErrorKind::InvalidFormat,
        io::Error::new(io::ErrorKind::InvalidInput, message.into()),
    )
    .with_path(path)
}

/// Returns true when `path` uses the `rbd:` scheme.
pub fn is_rbd_path(path: &Path) -> bool {
    path.to_str().is_some_and(|path| path.starts_with("rbd:"))
}

impl RbdUri {
    /// Parses an RBD path of the form `rbd:<pool>/<image>[@<snapshot>]`.
    ///
    /// The last `@` separates the snapshot name; image names containing
    /// `@` are therefore not supported.
    pub fn parse(path: &Path) -> BlockResult<Self> {
        let value = path
            .to_str()
            .ok_or_else(|| invalid(path, "RBD path is not valid UTF-8"))?;
        let rest = value
            .strip_prefix("rbd:")
            .ok_or_else(|| invalid(path, "RBD path must start with 'rbd:'"))?;

        if rest.is_empty() {
            return Err(invalid(
                path,
                "RBD path must be rbd:<pool>/<image>[@<snapshot>]",
            ));
        }
        if rest.contains('\0') {
            return Err(invalid(path, "RBD path must not contain NUL bytes"));
        }

        let (name, snapshot) = match rest.rsplit_once('@') {
            Some((name, snapshot)) => {
                if snapshot.is_empty() {
                    return Err(invalid(path, "RBD snapshot name must not be empty"));
                }
                (name, Some(snapshot.to_owned()))
            }
            None => (rest, None),
        };

        let (pool, image) = name
            .split_once('/')
            .ok_or_else(|| invalid(path, "RBD path must be rbd:<pool>/<image>[@<snapshot>]"))?;

        if pool.is_empty() {
            return Err(invalid(path, "RBD pool name must not be empty"));
        }
        if image.is_empty() {
            return Err(invalid(path, "RBD image name must not be empty"));
        }
        if image.contains('/') {
            return Err(invalid(
                path,
                "RBD image name must not contain '/'; namespaces are configured with rbd_namespace=",
            ));
        }
        if image.contains('@') {
            return Err(invalid(
                path,
                "RBD image name must not contain '@'; snapshots use the last '@'",
            ));
        }

        Ok(Self {
            pool: pool.to_owned(),
            image: image.to_owned(),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    fn parse(value: &str) -> BlockResult<RbdUri> {
        RbdUri::parse(Path::new(value))
    }

    #[test]
    fn parse_plain_image() {
        assert_eq!(
            parse("rbd:rbd/vm-root").unwrap(),
            RbdUri {
                pool: "rbd".to_owned(),
                image: "vm-root".to_owned(),
                snapshot: None,
            }
        );
    }

    #[test]
    fn parse_snapshot() {
        assert_eq!(
            parse("rbd:rbd/vm-root@snap-001").unwrap(),
            RbdUri {
                pool: "rbd".to_owned(),
                image: "vm-root".to_owned(),
                snapshot: Some("snap-001".to_owned()),
            }
        );
    }

    #[test]
    fn parse_image_with_slashes_is_rejected() {
        parse("rbd:rbd/ns/image").unwrap_err();
    }

    #[test]
    fn parse_rejects_invalid_forms() {
        for value in [
            "",
            "rbd:",
            "rbd:rbd",
            "rbd:/image",
            "rbd:pool/",
            "rbd:pool/image/",
            "rbd:pool/image@",
            "rbd:pool/image@snap@extra",
            "file:pool/image",
            "/dev/rbd0",
            "rbd:pool/im\0age",
        ] {
            assert!(parse(value).is_err(), "expected {value:?} to be rejected");
        }
    }

    #[test]
    fn parse_rejects_non_utf8() {
        let path = Path::new(OsStr::from_bytes(b"rbd:pool/\xffimage"));
        RbdUri::parse(path).unwrap_err();
    }

    #[test]
    fn is_rbd_path_checks_the_scheme() {
        assert!(is_rbd_path(Path::new("rbd:pool/image")));
        assert!(!is_rbd_path(Path::new("/dev/rbd0")));
        assert!(!is_rbd_path(Path::new("raw:pool/image")));
    }
}
