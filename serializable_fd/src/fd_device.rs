use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

#[derive(Error, Debug, Eq, PartialEq)]
pub enum FdDeviceParseError {
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

// `serde_json` requires strings for keys to generate valid JSON.
// We use `SerializeDisplay` and `DeserializeFromStr` to achieve that.
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, SerializeDisplay, DeserializeFromStr, Ord, PartialOrd,
)]
pub enum FdDevice {
    Net { id: String },
}

impl Display for FdDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FdDevice::Net { id } => {
                write!(f, "net({id})")
            }
        }
    }
}

impl FromStr for FdDevice {
    type Err = FdDeviceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (device, rest) = s
            .split_once('(')
            .ok_or(FdDeviceParseError::InvalidValue(s.to_owned()))?;
        let metadata = &rest[0..rest.len() - 1];
        let expected_closing_bracket = &rest[rest.len() - 1..];
        let fd_device = match device {
            "net" => Ok(FdDevice::Net {
                id: metadata.to_string(),
            }),
            unknown => Err(FdDeviceParseError::InvalidValue(unknown.to_owned())),
        }?;
        if expected_closing_bracket != ")" {
            return Err(FdDeviceParseError::InvalidValue(s.to_owned()));
        }
        Ok(fd_device)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(
            FdDevice::Net {
                id: "10".to_owned()
            }
            .to_string(),
            "net(10)".to_owned()
        );
    }

    #[test]
    fn test_from_str() {
        let input = "net(foo_123!?())";
        assert_eq!(
            FdDevice::from_str(input),
            Ok(FdDevice::Net {
                id: "foo_123!?()".to_owned()
            })
        );

        let input = "foo(123)";
        assert_eq!(
            FdDevice::from_str(input),
            Err(FdDeviceParseError::InvalidValue("foo".to_owned()))
        );

        let input = "net(123";
        assert_eq!(
            FdDevice::from_str(input),
            Err(FdDeviceParseError::InvalidValue("net(123".to_owned()))
        );
    }
}
