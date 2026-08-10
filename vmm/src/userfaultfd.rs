// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::str::FromStr;

// See include/uapi/linux/userfaultfd.h in the kernel code.
pub const UFFDIO_API: u64 = 0xc018_aa3f; // _IOWR(0xAA, 0x3F, struct uffdio_api)
pub const UFFDIO_REGISTER: u64 = 0xc020_aa00; // _IOWR(0xAA, 0x00, struct uffdio_register)
pub const UFFDIO_COPY: u64 = 0xc028_aa03; // _IOWR(0xAA, 0x03, struct uffdio_copy)
pub const UFFDIO_WAKE: u64 = 0x8010_aa02; // _IOR(0xAA, 0x02, struct uffdio_range)

// Validate ioctl encoding against the _IO{R,W,WR}(type, nr, size) formula so
// transposed direction bits or sizes are caught at compile time.
const fn ioctl_ioc(dir: u64, typ: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (typ << 8) | nr
}
const IOC_READ: u64 = 2;
const IOC_READWRITE: u64 = 3;
const _: () = assert!(UFFDIO_API == ioctl_ioc(IOC_READWRITE, 0xAA, 0x3F, 24));
const _: () = assert!(UFFDIO_REGISTER == ioctl_ioc(IOC_READWRITE, 0xAA, 0x00, 32));
const _: () = assert!(UFFDIO_COPY == ioctl_ioc(IOC_READWRITE, 0xAA, 0x03, 40));
const _: () = assert!(UFFDIO_WAKE == ioctl_ioc(IOC_READ, 0xAA, 0x02, 16));

// Seccomp compares these as Dword (u32); ensure they fit.
const _: () = assert!(UFFDIO_API <= u32::MAX as u64);
const _: () = assert!(UFFDIO_REGISTER <= u32::MAX as u64);
const _: () = assert!(UFFDIO_COPY <= u32::MAX as u64);
const _: () = assert!(UFFDIO_WAKE <= u32::MAX as u64);

// /dev/userfaultfd ioctl: _IO(0xAA, 0x00)
pub const USERFAULTFD_IOC_NEW: u64 = 0x0000_AA00;
const _: () = assert!(USERFAULTFD_IOC_NEW == ioctl_ioc(0, 0xAA, 0x00, 0));
const _: () = assert!(USERFAULTFD_IOC_NEW <= u32::MAX as u64);

pub const UFFD_API: u64 = 0xAA;
pub const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
pub const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
pub const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
pub const UFFD_FEATURE_MISSING_HUGETLBFS: u64 = 1 << 4;
pub const UFFD_FEATURE_MISSING_SHMEM: u64 = 1 << 5;
pub const UFFD_FEATURE_WP_HUGETLBFS_SHMEM: u64 = 1 << 6;
pub const UFFD_FEATURE_WP_UNPOPULATED: u64 = 1 << 13;
pub const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;

const _UFFDIO_COPY: u64 = 0x03;
const _UFFDIO_WAKE: u64 = 0x02;
pub const UFFD_API_RANGE_IOCTLS_BASIC: u64 = (1 << _UFFDIO_WAKE) | (1 << _UFFDIO_COPY);

/// Parsed `MISSING|WP|WP_UNPOPULATED|WP_ASYNC`-style configuration
/// spec for a single uffd handoff.
///
/// Two kernel surfaces are deliberately conflated into one user-facing
/// token string:
/// - register modes (MISSING, WP) → `UFFDIO_REGISTER` `mode` field
/// - features (WP_UNPOPULATED, WP_ASYNC) → `UFFDIO_API`
///   `features` field
///
/// They live in different ioctls and the async features are also
/// toggleable later via `UFFDIO_SET_MODE`, but for the handoff use
/// case they describe one decision (“how do I want this uffd
/// configured?”), the token namespaces are disjoint, and the only
/// features we accept here are the ones tightly coupled to the
/// WP register mode — so a single spec is the ergonomic choice.
///
/// Stored as the parsed bits but serialised on the wire (CLI / JSON
/// config / HTTP body) as the original token-string form, so config
/// validation surfaces parse errors at deserialise time rather than
/// at handoff time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct UffdHandoffSpec {
    pub register: u64,
    pub features: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UffdHandoffSpecParseError {
    #[error(
        "unknown UFFD mode token '{0}' (expected one of \
        MISSING, WP, WP_UNPOPULATED, WP_ASYNC)"
    )]
    UnknownToken(String),
    #[error("UFFD mode requires at least one register mode (MISSING, WP)")]
    NoRegisterMode,
    #[error("UFFD feature '{feature}' requires register mode '{requires}'")]
    FeatureRequiresRegisterMode {
        feature: &'static str,
        requires: &'static str,
    },
}

impl UffdHandoffSpec {
    /// Parse a `|`-separated set of tokens (whitespace around tokens is
    /// trimmed). At least one register-mode token is required; async
    /// tokens are optional.
    pub fn parse(s: &str) -> Result<Self, UffdHandoffSpecParseError> {
        let mut register = 0u64;
        let mut features = 0u64;
        for token in s.split('|').map(str::trim).filter(|t| !t.is_empty()) {
            match token {
                "MISSING" => register |= UFFDIO_REGISTER_MODE_MISSING,
                "WP" => register |= UFFDIO_REGISTER_MODE_WP,
                "WP_UNPOPULATED" => features |= UFFD_FEATURE_WP_UNPOPULATED,
                "WP_ASYNC" => features |= UFFD_FEATURE_WP_ASYNC,
                other => return Err(UffdHandoffSpecParseError::UnknownToken(other.into())),
            }
        }
        if register == 0 {
            return Err(UffdHandoffSpecParseError::NoRegisterMode);
        }
        // Feature/register cross-checks: each accepted feature is
        // tightly coupled to a register mode (per the type docstring).
        // Catch invalid combos here so the manager gets a 400 at
        // deserialise time instead of a 5xx from UFFDIO_REGISTER.
        if features & (UFFD_FEATURE_WP_UNPOPULATED | UFFD_FEATURE_WP_ASYNC) != 0
            && register & UFFDIO_REGISTER_MODE_WP == 0
        {
            let feature = if features & UFFD_FEATURE_WP_ASYNC != 0 {
                "WP_ASYNC"
            } else {
                "WP_UNPOPULATED"
            };
            return Err(UffdHandoffSpecParseError::FeatureRequiresRegisterMode {
                feature,
                requires: "WP",
            });
        }
        Ok(UffdHandoffSpec { register, features })
    }
}

impl FromStr for UffdHandoffSpec {
    type Err = UffdHandoffSpecParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for UffdHandoffSpec {
    /// Canonical representation: tokens in fixed order joined by `|`.
    /// Round-trips through `parse` (modulo input ordering / whitespace).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tokens: Vec<&str> = Vec::with_capacity(4);
        if self.register & UFFDIO_REGISTER_MODE_MISSING != 0 {
            tokens.push("MISSING");
        }
        if self.register & UFFDIO_REGISTER_MODE_WP != 0 {
            tokens.push("WP");
        }
        if self.features & UFFD_FEATURE_WP_UNPOPULATED != 0 {
            tokens.push("WP_UNPOPULATED");
        }
        if self.features & UFFD_FEATURE_WP_ASYNC != 0 {
            tokens.push("WP_ASYNC");
        }
        f.write_str(&tokens.join("|"))
    }
}

impl From<UffdHandoffSpec> for String {
    fn from(m: UffdHandoffSpec) -> String {
        m.to_string()
    }
}

impl TryFrom<String> for UffdHandoffSpec {
    type Error = UffdHandoffSpecParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_register_mode() {
        let m = UffdHandoffSpec::parse("WP").unwrap();
        assert_eq!(m.register, UFFDIO_REGISTER_MODE_WP);
        assert_eq!(m.features, 0);
    }

    #[test]
    fn parse_combination() {
        let m = UffdHandoffSpec::parse("MISSING|WP|WP_ASYNC").unwrap();
        assert_eq!(
            m.register,
            UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP
        );
        assert_eq!(m.features, UFFD_FEATURE_WP_ASYNC);
    }

    #[test]
    fn parse_whitespace_tolerant() {
        let m = UffdHandoffSpec::parse(" MISSING |  WP ").unwrap();
        assert_eq!(
            m.register,
            UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP
        );
    }

    #[test]
    fn parse_rejects_unknown_token() {
        assert_eq!(
            UffdHandoffSpec::parse("MISSING|FOO"),
            Err(UffdHandoffSpecParseError::UnknownToken("FOO".into()))
        );
    }

    #[test]
    fn parse_rejects_no_register_mode() {
        assert_eq!(
            UffdHandoffSpec::parse(""),
            Err(UffdHandoffSpecParseError::NoRegisterMode)
        );
        assert_eq!(
            UffdHandoffSpec::parse("WP_ASYNC"),
            Err(UffdHandoffSpecParseError::NoRegisterMode)
        );
    }

    #[test]
    fn parse_rejects_feature_without_register_mode() {
        assert_eq!(
            UffdHandoffSpec::parse("MISSING|WP_ASYNC"),
            Err(UffdHandoffSpecParseError::FeatureRequiresRegisterMode {
                feature: "WP_ASYNC",
                requires: "WP",
            })
        );
        assert_eq!(
            UffdHandoffSpec::parse("MISSING|WP_UNPOPULATED"),
            Err(UffdHandoffSpecParseError::FeatureRequiresRegisterMode {
                feature: "WP_UNPOPULATED",
                requires: "WP",
            })
        );
    }

    #[test]
    fn display_canonical_and_roundtrip() {
        assert_eq!(UffdHandoffSpec::parse("WP").unwrap().to_string(), "WP");
        assert_eq!(
            UffdHandoffSpec::parse("MISSING|WP").unwrap().to_string(),
            "MISSING|WP"
        );
        // Display order is fixed regardless of parse-input order.
        let m = UffdHandoffSpec::parse("WP_ASYNC|WP|MISSING").unwrap();
        assert_eq!(m.to_string(), "MISSING|WP|WP_ASYNC");
        // Round-trip preserves bits.
        assert_eq!(UffdHandoffSpec::parse(&m.to_string()).unwrap(), m);
        // WP + WP_UNPOPULATED tokens.
        let wp = UffdHandoffSpec::parse("WP|WP_UNPOPULATED").unwrap();
        assert_eq!(wp.register, UFFDIO_REGISTER_MODE_WP);
        assert_eq!(wp.features, UFFD_FEATURE_WP_UNPOPULATED);
        assert_eq!(wp.to_string(), "WP|WP_UNPOPULATED");
    }
}
