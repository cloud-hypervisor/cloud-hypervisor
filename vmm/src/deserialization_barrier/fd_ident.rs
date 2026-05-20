// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

/// An identifier for any resource backed by a file descriptor.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Ord, PartialOrd)]
pub enum FdIdent {
    Net { id: String },
}

impl FdIdent {
    /// Returns a new [`FdIdent`] for a network device.
    pub fn new_net(id: String) -> Self {
        Self::Net { id }
    }
}
