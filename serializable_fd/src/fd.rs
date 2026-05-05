use std::fmt::{Display, Formatter};
use std::fs::File;
use std::num::ParseIntError;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub enum SerializableFd {
    Active(OwnedFd),
    Serialized(RawFd),
}

impl Serialize for SerializableFd {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let fd = match self {
            SerializableFd::Active(fd) => fd.as_raw_fd(),
            SerializableFd::Serialized(fd) => *fd,
        };
        serializer.serialize_i32(fd)
    }
}

impl<'de> Deserialize<'de> for SerializableFd {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fd = i32::deserialize(deserializer)?;
        Ok(Self::new_serialized(fd))
    }
}

impl Display for SerializableFd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let fd = match self {
            SerializableFd::Active(fd) => fd.as_raw_fd(),
            SerializableFd::Serialized(fd) => *fd,
        };

        write!(f, "{fd}")
    }
}

impl FromStr for SerializableFd {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::Serialized(s.parse::<RawFd>()?))
    }
}

impl Eq for SerializableFd {}

impl PartialEq for SerializableFd {
    fn eq(&self, other: &Self) -> bool {
        match self {
            SerializableFd::Active(self_fd) => match other {
                SerializableFd::Active(other_fd) => self_fd.as_raw_fd() == other_fd.as_raw_fd(),
                SerializableFd::Serialized(_) => false,
            },
            SerializableFd::Serialized(self_fd) => match other {
                SerializableFd::Active(_) => false,
                SerializableFd::Serialized(other_fd) => self_fd == other_fd,
            },
        }
    }
}

impl From<SerializableFd> for OwnedFd {
    fn from(value: SerializableFd) -> Self {
        match value {
            SerializableFd::Active(fd) => fd,
            SerializableFd::Serialized(_) => {
                panic!("cannot access serialized FD");
            }
        }
    }
}

impl From<OwnedFd> for SerializableFd {
    fn from(value: OwnedFd) -> Self {
        Self::Active(value)
    }
}

impl AsFd for SerializableFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self {
            SerializableFd::Active(fd) => fd.as_fd(),
            SerializableFd::Serialized(_) => {
                panic!("cannot access serialized FD");
            }
        }
    }
}

impl AsRawFd for SerializableFd {
    fn as_raw_fd(&self) -> RawFd {
        match &self {
            SerializableFd::Active(fd) => fd.as_raw_fd(),
            SerializableFd::Serialized(_) => {
                panic!("cannot access serialized FD");
            }
        }
    }
}

impl Clone for SerializableFd {
    fn clone(&self) -> Self {
        match self {
            SerializableFd::Active(fd) => {
                let duplicated_fd = fd.try_clone().unwrap();
                Self::Active(duplicated_fd)
            }
            SerializableFd::Serialized(fd) => Self::Serialized(*fd),
        }
    }
}

impl SerializableFd {
    pub fn new_active(fd: OwnedFd) -> Self {
        SerializableFd::Active(fd)
    }

    pub fn new_serialized(fd: RawFd) -> Self {
        SerializableFd::Serialized(fd)
    }

    #[cfg(test)]
    pub fn new_active_dev_null() -> Self {
        let file = File::open("/dev/null").unwrap();
        SerializableFd::new_active(file.into())
    }

    /// # Safety
    /// TODO(fd)
    pub unsafe fn new_active_from_raw(fd: RawFd) -> Self {
        // TODO(fd): error handling
        assert!(fd >= 1, "invalid FD");
        // SAFETY: TODO(fd)
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::new_active(fd)
    }

    pub fn update(&mut self, other: SerializableFd) {
        if self.is_active() {
            // TODO(fd): error handling
            panic!("cannot update active FD")
        }
        *self = other;
    }

    pub fn set_active(&mut self, fd: OwnedFd) {
        match self {
            SerializableFd::Active(_) => {
                // TODO(fd): proper error handling
                panic!("Cannot update active FD");
            }
            SerializableFd::Serialized(_) => {
                *self = SerializableFd::Active(fd);
            }
        }
    }

    pub fn set_all_active(serializable_fds: &mut [Self], updated_fds: Vec<File>) {
        // TODO(fd): proper error handling
        assert_eq!(serializable_fds.len(), updated_fds.len());
        serializable_fds
            .iter_mut()
            .zip(updated_fds)
            .for_each(|(serializable_fd, file)| serializable_fd.set_active(OwnedFd::from(file)));
    }

    pub fn is_active(&self) -> bool {
        match self {
            SerializableFd::Active(_) => true,
            SerializableFd::Serialized(_) => false,
        }
    }

    pub fn to_serialized(&self) -> Self {
        match self {
            SerializableFd::Active(fd) => SerializableFd::Serialized(fd.as_raw_fd()),
            SerializableFd::Serialized(_) => self.clone(),
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use std::os::fd::AsRawFd;

    use crate::SerializableFd;

    #[test]
    fn test_serialization_deserialization() {
        let fd = SerializableFd::new_active_dev_null();
        let serialized_fd = serde_json::to_string(&fd).unwrap();

        assert_eq!(serialized_fd, format!("{}", fd.as_raw_fd()));

        let deserialized_fd: SerializableFd = serde_json::from_str(&serialized_fd).unwrap();
        assert_eq!(
            deserialized_fd,
            SerializableFd::new_serialized(fd.as_raw_fd())
        );
    }
}
