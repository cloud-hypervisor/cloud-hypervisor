// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use serde::{Deserialize, Serialize};

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
