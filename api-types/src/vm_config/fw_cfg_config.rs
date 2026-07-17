// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;
use std::str::FromStr;

use option_parser::{OptionParser, OptionParserError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FwCfgItemList {
    #[serde(default)]
    pub item_list: Vec<FwCfgItem>,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FwCfgItem {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub string: Option<String>,
}

impl FwCfgItem {
    pub fn parse(fw_cfg: &str) -> Result<Self, OptionParserError> {
        let mut parser = OptionParser::new();
        parser.add("name").add("file").add("string");
        parser.parse(fw_cfg)?;

        let name = parser.get("name").ok_or(OptionParserError::InvalidValue(
            "missing FwCfgItem name".to_string(),
        ))?;
        let file = parser.get("file").map(PathBuf::from);
        let string = parser.get("string");
        Ok(FwCfgItem { name, file, string })
    }
}

pub enum FwCfgItemError {
    InvalidValue(String),
}

impl FromStr for FwCfgItemList {
    type Err = FwCfgItemError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s
            .trim()
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| FwCfgItemError::InvalidValue(s.to_string()))?;

        let mut fw_cfg_items: Vec<FwCfgItem> = vec![];
        let items: Vec<&str> = body.split(':').collect();
        for item in items {
            fw_cfg_items.push(
                FwCfgItem::parse(item)
                    .map_err(|_| FwCfgItemError::InvalidValue(item.to_string()))?,
            );
        }
        Ok(FwCfgItemList {
            item_list: fw_cfg_items,
        })
    }
}
