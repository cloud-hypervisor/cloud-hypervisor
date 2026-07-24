// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;
use std::str::FromStr;

use option_parser::{OptionParser, OptionParserError, Toggle};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct FwCfgConfig {
    pub e820: bool,
    pub kernel: bool,
    pub cmdline: bool,
    pub initramfs: bool,
    pub acpi_tables: bool,
    pub items: Option<FwCfgItemList>,
}

impl Default for FwCfgConfig {
    fn default() -> Self {
        FwCfgConfig {
            e820: true,
            kernel: true,
            cmdline: true,
            initramfs: true,
            acpi_tables: true,
            items: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum FwCfgConfigParseError {
    #[error("Failed to parse fw_cfg configuration")]
    Parse(#[source] OptionParserError),
}

impl FwCfgConfig {
    pub const SYNTAX: &'static str = "Boot params to pass to FW CFG device \
    \"e820=on|off,kernel=on|off,cmdline=on|off,initramfs=on|off,acpi_table=on|off, \
    items=[name=<item_name>,file=<file_path>:name=<item_name>,string=<string_value>]\"";

    pub fn parse(fw_cfg_config: &str) -> Result<Self, FwCfgConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("e820")
            .add("kernel")
            .add("cmdline")
            .add("initramfs")
            .add("acpi_table")
            .add("items");
        parser
            .parse(fw_cfg_config)
            .map_err(FwCfgConfigParseError::Parse)?;
        let e820 = parser
            .convert::<Toggle>("e820")
            .map_err(FwCfgConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let kernel = parser
            .convert::<Toggle>("kernel")
            .map_err(FwCfgConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let cmdline = parser
            .convert::<Toggle>("cmdline")
            .map_err(FwCfgConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let initramfs = parser
            .convert::<Toggle>("initramfs")
            .map_err(FwCfgConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let acpi_tables = parser
            .convert::<Toggle>("acpi_table")
            .map_err(FwCfgConfigParseError::Parse)?
            .unwrap_or(Toggle(true))
            .0;
        let items = if parser.is_set("items") {
            Some(
                parser
                    .convert::<FwCfgItemList>("items")
                    .map_err(FwCfgConfigParseError::Parse)?
                    .unwrap(),
            )
        } else {
            None
        };

        Ok(FwCfgConfig {
            e820,
            kernel,
            cmdline,
            initramfs,
            acpi_tables,
            items,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{FwCfgConfig, FwCfgConfigParseError, FwCfgItem, FwCfgItemList};

    #[test]
    fn test_fw_cfg_config_item_list_parsing() -> Result<(), FwCfgConfigParseError> {
        // Empty list
        FwCfgConfig::parse("items=[]").unwrap_err();
        // Missing closing bracket
        FwCfgConfig::parse("items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item")
            .unwrap_err();
        // Single file Item
        assert_eq!(
            FwCfgConfig::parse(
                "items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item]"
            )?,
            FwCfgConfig {
                items: Some(FwCfgItemList {
                    item_list: vec![FwCfgItem {
                        name: "opt/org.test/fw_cfg_test_item".to_string(),
                        file: Some(PathBuf::from("/tmp/fw_cfg_test_item")),
                        string: None,
                    }]
                }),
                ..Default::default()
            },
        );
        // Multiple file Items
        assert_eq!(
            FwCfgConfig::parse(
                "items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item:name=opt/org.test/fw_cfg_test_item2,file=/tmp/fw_cfg_test_item2]"
            )?,
            FwCfgConfig {
                items: Some(FwCfgItemList {
                    item_list: vec![
                        FwCfgItem {
                            name: "opt/org.test/fw_cfg_test_item".to_string(),
                            file: Some(PathBuf::from("/tmp/fw_cfg_test_item")),
                            string: None,
                        },
                        FwCfgItem {
                            name: "opt/org.test/fw_cfg_test_item2".to_string(),
                            file: Some(PathBuf::from("/tmp/fw_cfg_test_item2")),
                            string: None,
                        }
                    ]
                }),
                ..Default::default()
            },
        );
        // Single string Item (for OVMF MMIO64 config, GPU CC passthrough, etc.)
        assert_eq!(
            FwCfgConfig::parse("items=[name=opt/ovmf/X-PciMmio64Mb,string=262144]")?,
            FwCfgConfig {
                items: Some(FwCfgItemList {
                    item_list: vec![FwCfgItem {
                        name: "opt/ovmf/X-PciMmio64Mb".to_string(),
                        file: None,
                        string: Some("262144".to_string()),
                    }]
                }),
                ..Default::default()
            },
        );
        // Mixed file and string Items
        assert_eq!(
            FwCfgConfig::parse(
                "items=[name=opt/org.test/fw_cfg_test_item,file=/tmp/fw_cfg_test_item:name=opt/ovmf/X-PciMmio64Mb,string=262144]"
            )?,
            FwCfgConfig {
                items: Some(FwCfgItemList {
                    item_list: vec![
                        FwCfgItem {
                            name: "opt/org.test/fw_cfg_test_item".to_string(),
                            file: Some(PathBuf::from("/tmp/fw_cfg_test_item")),
                            string: None,
                        },
                        FwCfgItem {
                            name: "opt/ovmf/X-PciMmio64Mb".to_string(),
                            file: None,
                            string: Some("262144".to_string()),
                        }
                    ]
                }),
                ..Default::default()
            },
        );
        // Missing both file and string parses OK but fails validation
        let missing_content =
            FwCfgConfig::parse("items=[name=opt/org.test/missing_content]").unwrap();
        assert_eq!(
            missing_content.items.as_ref().unwrap().item_list[0].file,
            None
        );
        assert_eq!(
            missing_content.items.as_ref().unwrap().item_list[0].string,
            None
        );
        // Both file and string parses OK but fails validation
        let both = FwCfgConfig::parse("items=[name=opt/org.test/both,file=/tmp/test,string=test]")
            .unwrap();
        assert!(both.items.as_ref().unwrap().item_list[0].file.is_some());
        assert!(both.items.as_ref().unwrap().item_list[0].string.is_some());
        Ok(())
    }
}
