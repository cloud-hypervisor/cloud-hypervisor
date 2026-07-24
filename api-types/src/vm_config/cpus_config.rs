// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use arch::CpuProfile;
use option_parser::{OptionParser, OptionParserError, StringList, Toggle, Tuple, TupleList};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuAffinity {
    pub vcpu: u32,
    pub host_cpus: Box<[usize]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuFeatures {
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub amx: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum CoreScheduling {
    #[default]
    Vm, // All vCPUs have the same cookie so can share a core
    Vcpu, // Each vCPU has a unique cookie so can't share a core
    Off,
}

pub enum ParseCoreSchedulingError {
    InvalidValue(String),
}

impl FromStr for CoreScheduling {
    type Err = ParseCoreSchedulingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vm" => Ok(CoreScheduling::Vm),
            "vcpu" => Ok(CoreScheduling::Vcpu),
            "off" => Ok(CoreScheduling::Off),
            _ => Err(ParseCoreSchedulingError::InvalidValue(s.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuTopology {
    pub threads_per_core: u16,
    pub cores_per_die: u16,
    pub dies_per_package: u16,
    pub packages: u16,
}

pub enum CpuTopologyParseError {
    InvalidValue(String),
}

impl FromStr for CpuTopology {
    type Err = CpuTopologyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 4 {
            return Err(Self::Err::InvalidValue(s.to_owned()));
        }

        let t = CpuTopology {
            threads_per_core: parts[0]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            cores_per_die: parts[1]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            dies_per_package: parts[2]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
            packages: parts[3]
                .parse()
                .map_err(|_| Self::Err::InvalidValue(s.to_owned()))?,
        };

        Ok(t)
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpusConfig {
    pub boot_vcpus: u32,
    pub max_vcpus: u32,
    #[serde(default)]
    pub topology: Option<CpuTopology>,
    #[serde(default)]
    pub kvm_hyperv: bool,
    #[serde(default = "default_cpuconfig_max_phys_bits")]
    pub max_phys_bits: u8,
    #[serde(default)]
    pub affinity: Option<Box<[CpuAffinity]>>,
    #[serde(default)]
    pub features: CpuFeatures,
    #[serde(default = "default_cpusconfig_nested")]
    pub nested: bool,
    #[serde(default)]
    pub core_scheduling: CoreScheduling,
    // Defaults to "Host" if no profile is given.
    #[serde(default)]
    pub profile: CpuProfile,
}

impl Default for CpusConfig {
    fn default() -> Self {
        CpusConfig {
            boot_vcpus: DEFAULT_VCPUS,
            max_vcpus: DEFAULT_VCPUS,
            topology: None,
            kvm_hyperv: false,
            max_phys_bits: DEFAULT_MAX_PHYS_BITS,
            affinity: None,
            features: CpuFeatures::default(),
            nested: true,
            core_scheduling: CoreScheduling::default(),
            profile: CpuProfile::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum CpusConfigParseError {
    /// Invalid CPU features
    #[error("Invalid feature in --cpus features list: {0}")]
    InvalidCpuFeatures(String),
    /// Failed to parse config string.
    #[error("Failed to parse configuration string")]
    ParseCpusConfig(#[source] OptionParserError),
}

impl CpusConfig {
    pub fn parse(cpus: &str) -> Result<Self, CpusConfigParseError> {
        let mut parser = OptionParser::new();
        parser
            .add("boot")
            .add("max")
            .add("topology")
            .add("kvm_hyperv")
            .add("max_phys_bits")
            .add("affinity")
            .add("features")
            .add("nested")
            .add("core_scheduling")
            .add("profile");
        parser
            .parse(cpus)
            .map_err(CpusConfigParseError::ParseCpusConfig)?;

        let boot_vcpus: u32 = parser
            .convert("boot")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or(DEFAULT_VCPUS);
        let max_vcpus: u32 = parser
            .convert("max")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or(boot_vcpus);
        let topology = parser
            .convert("topology")
            .map_err(CpusConfigParseError::ParseCpusConfig)?;
        let kvm_hyperv = parser
            .convert::<Toggle>("kvm_hyperv")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or(Toggle(false))
            .0;
        let max_phys_bits = parser
            .convert::<u8>("max_phys_bits")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or(DEFAULT_MAX_PHYS_BITS);
        let affinity = parser
            .convert::<TupleList<u32, Vec<usize>>>("affinity")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .map(|v| {
                v.0.iter()
                    .map(|Tuple(e1, e2)| CpuAffinity {
                        vcpu: *e1,
                        host_cpus: e2.clone().into_boxed_slice(),
                    })
                    .collect()
            });

        let profile = parser
            .convert::<CpuProfile>("profile")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or_default();

        let features_list = parser
            .convert::<StringList>("features")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or_default();

        #[allow(unused_mut)]
        let mut features = CpuFeatures::default();
        {
            #[cfg(target_arch = "x86_64")]
            for feature in features_list.0 {
                match feature.as_str() {
                    "amx" => features.amx = true,
                    _ => return Err(CpusConfigParseError::InvalidCpuFeatures(feature)),
                }
            }

            #[cfg(not(target_arch = "x86_64"))]
            if let Some(feature) = features_list.0.into_iter().next() {
                return Err(CpusConfigParseError::InvalidCpuFeatures(feature));
            }
        }

        let nested = parser
            .convert::<Toggle>("nested")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .is_none_or(|toggle| toggle.0);

        let core_scheduling = parser
            .convert("core_scheduling")
            .map_err(CpusConfigParseError::ParseCpusConfig)?
            .unwrap_or(CoreScheduling::Vm);

        Ok(CpusConfig {
            boot_vcpus,
            max_vcpus,
            topology,
            kvm_hyperv,
            max_phys_bits,
            affinity,
            features,
            nested,
            core_scheduling,
            profile,
        })
    }
}

// When booting with PVH boot the maximum physical addressable size
// is a 46 bit address space even when the host supports with 5-level
// paging.
pub const DEFAULT_MAX_PHYS_BITS: u8 = 46;
pub const DEFAULT_VCPUS: u32 = 1;
pub fn default_cpuconfig_max_phys_bits() -> u8 {
    DEFAULT_MAX_PHYS_BITS
}
fn default_cpusconfig_nested() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use crate::{CoreScheduling, CpuAffinity, CpuTopology, CpusConfig, CpusConfigParseError};

    #[test]
    fn test_cpu_parsing() -> Result<(), CpusConfigParseError> {
        assert_eq!(CpusConfig::parse("")?, CpusConfig::default());

        assert_eq!(
            CpusConfig::parse("boot=1")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=1,max=2")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 2,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=8,topology=2:2:1:2")?,
            CpusConfig {
                boot_vcpus: 8,
                max_vcpus: 8,
                topology: Some(CpuTopology {
                    threads_per_core: 2,
                    cores_per_die: 2,
                    dies_per_package: 1,
                    packages: 2
                }),
                ..Default::default()
            }
        );

        CpusConfig::parse("boot=8,topology=2:2:1").unwrap_err();
        CpusConfig::parse("boot=8,topology=2:2:1:x").unwrap_err();
        assert_eq!(
            CpusConfig::parse("boot=1,kvm_hyperv=on")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                kvm_hyperv: true,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=2,affinity=[0@[0,2],1@[1,3]]")?,
            CpusConfig {
                boot_vcpus: 2,
                max_vcpus: 2,
                affinity: Some(Box::new([
                    CpuAffinity {
                        vcpu: 0,
                        host_cpus: Box::new([0, 2]),
                    },
                    CpuAffinity {
                        vcpu: 1,
                        host_cpus: Box::new([1, 3]),
                    }
                ])),
                ..Default::default()
            },
        );

        // Test core_scheduling parsing
        assert_eq!(
            CpusConfig::parse("boot=1,core_scheduling=vm")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                core_scheduling: CoreScheduling::Vm,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=1,core_scheduling=vcpu")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                core_scheduling: CoreScheduling::Vcpu,
                ..Default::default()
            }
        );
        assert_eq!(
            CpusConfig::parse("boot=1,core_scheduling=off")?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 1,
                core_scheduling: CoreScheduling::Off,
                ..Default::default()
            }
        );
        // Default (no core_scheduling specified) should be Vm
        assert_eq!(
            CpusConfig::parse("boot=1")?.core_scheduling,
            CoreScheduling::Vm
        );
        // Invalid value should error
        CpusConfig::parse("boot=1,core_scheduling=invalid").unwrap_err();

        Ok(())
    }
}
