// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! A deserialization barrier compatible file descriptor.

use std::fmt::Debug;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::deserialization_barrier::{Active, Deserialized, ExportScmRights, Sealed};

/// Marker Trait
#[expect(private_bounds)]
pub trait FdMarker: FdMarkerImpl + Sealed {}

/// Contains the implementation details for [`FdMarker`].
///
/// Private helper trait to prevent access to private implementation details.
trait FdMarkerImpl {
    /// File descriptor type.
    type Repr: Debug + AsRawFd;
    /// Clones [`Self::Repr`].
    ///
    /// Helper to enable a [`Clone`] implementation for all `T: FdMarkerImpl`.
    fn clone(inner: &Self::Repr) -> Self::Repr;
}

impl FdMarkerImpl for Deserialized {
    type Repr = RawFd;

    fn clone(inner: &Self::Repr) -> Self::Repr {
        *inner
    }
}
impl FdMarker for Deserialized {}

impl FdMarkerImpl for Active {
    type Repr = OwnedFd;

    fn clone(inner: &Self::Repr) -> Self::Repr {
        inner.try_clone().unwrap()
    }
}
impl FdMarker for Active {}

/// File descriptor with state information.
///
/// Depending on the generic parameter, the file descriptor can be:
/// - [`Deserialized`], which means the file descriptor is invalid.
/// - [`Active`], which means the file descriptor can be used like [`OwnedFd`].
///
/// The file descriptor will always de-/serialize to an invalid state.
#[derive(Debug)]
pub struct Fd<S>
where
    S: FdMarker,
{
    fd: <S as FdMarkerImpl>::Repr,
}

impl Fd<Deserialized> {
    /// Creates a new [`Fd<Deserialized>`].
    pub fn new_deserialized(raw_fd: RawFd) -> Self {
        Self { fd: raw_fd }
    }

    /// Updates the file descriptor with an [`OwnedFd`], turning it [`Active`].
    pub fn activate(self, owned_fd: OwnedFd) -> Fd<Active> {
        Fd { fd: owned_fd }
    }
}

/// Errors creating an [`Fd<Active>`] from a [`RawFd`].
#[derive(Error, Debug)]
pub enum FromRawError {
    /// F_GETFD on the file descriptor returned an error.
    #[error("Invalid file descriptor \"{raw_fd}\": {source}")]
    InvalidFd {
        raw_fd: RawFd,
        #[source]
        source: std::io::Error,
    },
}

impl Fd<Active> {
    /// Creates a new [`Fd<Active>`].
    pub fn new_active(owned_fd: OwnedFd) -> Self {
        Self { fd: owned_fd }
    }

    /// Converts the [`RawFd`] into [`Fd<Active>`].
    ///
    /// # Safety
    ///
    /// Requires the same safety guarantees as [`OwnedFd::from_raw_fd`].
    ///
    /// # Panics
    ///
    /// Has the same panic cases as [`OwnedFd::from_raw_fd`].
    pub unsafe fn new_from_raw(raw_fd: RawFd) -> Result<Self, FromRawError> {
        // SAFETY: F_GETFD handles invalid file descriptors.
        let fcntl_result = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        if fcntl_result == -1 {
            return Err(FromRawError::InvalidFd {
                raw_fd,
                source: std::io::Error::last_os_error(),
            });
        }
        // SAFETY: We checked that the user supplied a valid file descriptor.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(owned_fd.into())
    }
}

impl Default for Fd<Deserialized> {
    fn default() -> Self {
        Self { fd: -1 }
    }
}

impl<S> Clone for Fd<S>
where
    S: FdMarker,
{
    fn clone(&self) -> Self {
        Self {
            fd: <S as FdMarkerImpl>::clone(&self.fd),
        }
    }
}

// TODO(fd): remove the `Eq` and `PartialEq` implementation.
// Neither makes sense for `OwnedFd` since there cannot be two `OwnedFd`s with the same underlying `RawFd`.
// Blocked on removing both traits from `VmConfig` and friends.
impl<S> Eq for Fd<S> where S: FdMarker {}

impl<S> PartialEq for Fd<S>
where
    S: FdMarker,
{
    fn eq(&self, other: &Self) -> bool {
        self.fd.as_raw_fd() == other.fd.as_raw_fd()
    }
}

impl<S> Serialize for Fd<S>
where
    S: FdMarker,
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        // File descriptors cannot be used over the serialization barrier so all fds are
        // serialized as invalid.
        serializer.serialize_i32(-1)
    }
}

impl<'de> Deserialize<'de> for Fd<Deserialized> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fd = RawFd::deserialize(deserializer)?;
        Ok(Self::new_deserialized(fd))
    }
}

impl AsFd for Fd<Active> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Fd<Active> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl From<RawFd> for Fd<Deserialized> {
    fn from(value: RawFd) -> Self {
        Self::new_deserialized(value)
    }
}

impl From<OwnedFd> for Fd<Active> {
    fn from(value: OwnedFd) -> Self {
        Self::new_active(value)
    }
}

impl From<File> for Fd<Active> {
    fn from(value: File) -> Self {
        Self::new_active(value.into())
    }
}

impl From<Fd<Active>> for OwnedFd {
    fn from(value: Fd<Active>) -> Self {
        value.fd
    }
}

impl ExportScmRights for Fd<Active> {
    type Inactive = Fd<Deserialized>;

    fn export_fd_list_inner(self, fds: &mut Vec<OwnedFd>) -> Self::Inactive {
        let fd = self.fd;
        let raw_fd = fd.as_raw_fd();
        fds.push(fd);
        Fd { fd: raw_fd }
    }
}

#[cfg(test)]
mod unit_tests {
    use std::fs::File;
    use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};

    use crate::deserialization_barrier::{Active, Deserialized, ExportScmRights, Fd, FromRawError};

    #[test]
    fn de_ser_roundtrip() {
        let file = File::open("/dev/null").unwrap();
        let fd: Fd<Active> = file.into();
        let serialized_fd = serde_json::to_string(&fd).unwrap();
        assert_eq!(serialized_fd, "-1");
        let deserialized_fd: Fd<Deserialized> = serde_json::from_str(&serialized_fd).unwrap();
        assert_eq!(deserialized_fd.fd, -1);
    }

    #[test]
    fn deserialize_placeholder() {
        let serialized_fd = "123";
        let deserialized_fd: Fd<Deserialized> = serde_json::from_str(serialized_fd).unwrap();
        assert_eq!(deserialized_fd.fd, 123);
    }

    #[test]
    fn scm_rights() {
        let file = File::open("/dev/null").unwrap();
        let fd: Fd<Active> = file.into();
        let raw_fd = fd.as_raw_fd();
        let (inactive_fd, fd_list): (Fd<Deserialized>, _) = fd.export_fd_list();
        assert_eq!(fd_list.len(), 1);
        assert_eq!(inactive_fd.fd, raw_fd);
    }

    #[test]
    fn activate() {
        let file = File::open("/dev/null").unwrap();
        let fd: OwnedFd = file.into();
        let raw_fd = fd.as_raw_fd();
        let inactive_fd = Fd::new_deserialized(-1);
        let activated_fd = inactive_fd.activate(fd);
        assert_eq!(activated_fd.as_raw_fd(), raw_fd);
    }

    #[test]
    fn new_from_raw() {
        // Success case:
        let file = File::open("/dev/null").unwrap();
        let raw_fd = file.into_raw_fd();
        // SAFETY: We got the RawFd from an OwnedFd.
        let fd = unsafe { Fd::new_from_raw(raw_fd) }.unwrap();
        assert_eq!(fd.as_raw_fd(), raw_fd);

        // Failure case:
        let raw_fd = -1;
        // SAFETY: `new_from_raw` will handle the invalid raw fd.
        let FromRawError::InvalidFd { raw_fd, source } =
            unsafe { Fd::new_from_raw(raw_fd) }.unwrap_err();
        assert_eq!(raw_fd, -1);
        assert_eq!(source.raw_os_error().unwrap(), libc::EBADF);
    }

    #[test]
    fn clone() {
        let file = File::open("/dev/null").unwrap();
        let fd: Fd<Active> = file.into();
        let cloned_fd = fd.clone();
        assert_ne!(cloned_fd.as_raw_fd(), fd.as_raw_fd());
        assert_ne!(cloned_fd, fd);

        let fd = Fd::new_deserialized(-1);
        let cloned_fd = fd.clone();
        assert_eq!(cloned_fd.fd, fd.fd);
        assert_eq!(cloned_fd, fd);
    }
}
