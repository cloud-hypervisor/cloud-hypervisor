// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Memory transfer mode for a migration.
#[derive(Copy, Clone, Default, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum MigrationMode {
    /// Transfer all guest memory before the destination resumes.
    #[default]
    Precopy,
    /// Resume the destination first and fault guest pages in on demand.
    /// This is an experimental mode. It uses a single connection even
    /// when parallel connections are configured. Pages are served on
    /// demand, but a background faulting mechanism also pulls in the
    /// remaining pages to speed up completion.
    Postcopy,
}

impl FromStr for MigrationMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "precopy" => Ok(MigrationMode::Precopy),
            "postcopy" => Ok(MigrationMode::Postcopy),
            _ => Err(format!("Invalid migration mode: {s}")),
        }
    }
}
