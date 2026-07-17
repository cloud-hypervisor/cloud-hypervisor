// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LandlockConfig {
    pub path: PathBuf,
    pub access: String,
}

#[derive(Debug, Error)]
pub enum LandlockConfigParseError {
    #[error("Failed to parse Landlock configuration")]
    Parse(#[source] OptionParserError),
    #[error("Landlock path or access is missing")]
    MissingFields,
}

impl LandlockConfig {
    pub const SYNTAX: &'static str = "Landlock parameters \
        \"path=<path/to/{file/dir}>,access=[rw]\"";

    pub fn parse(landlock_rule: &str) -> Result<Self, LandlockConfigParseError> {
        let mut parser = OptionParser::new();
        parser.add("path").add("access");
        parser
            .parse(landlock_rule)
            .map_err(LandlockConfigParseError::Parse)?;

        let path = parser
            .get("path")
            .map(PathBuf::from)
            .ok_or(LandlockConfigParseError::MissingFields)?;

        let access = parser
            .get("access")
            .ok_or(LandlockConfigParseError::MissingFields)?;

        if access.chars().count() > 2 {
            return Err(LandlockConfigParseError::Parse(
                OptionParserError::InvalidValue(access.to_string()),
            ));
        }

        Ok(LandlockConfig { path, access })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{LandlockConfig, LandlockConfigParseError};

    #[test]
    fn test_landlock_parsing() -> Result<(), LandlockConfigParseError> {
        // should not be empty
        LandlockConfig::parse("").unwrap_err();
        // access should not be empty
        LandlockConfig::parse("path=/dir/path1").unwrap_err();
        LandlockConfig::parse("path=/dir/path1,access=rwr").unwrap_err();
        assert_eq!(
            LandlockConfig::parse("path=/dir/path1,access=rw")?,
            LandlockConfig {
                path: PathBuf::from("/dir/path1"),
                access: "rw".to_string(),
            }
        );
        Ok(())
    }
}
