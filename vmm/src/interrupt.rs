// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::sync::Arc;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceConfig, InterruptSourceGroup, InterruptType,
};

/// Reuse std::io::Result to simplify interoperability among crates.
pub type Result<T> = std::io::Result<T>;

pub struct MsiInterruptGroup {}

impl MsiInterruptGroup {
    fn new() -> Self {
        MsiInterruptGroup {}
    }
}

impl InterruptSourceGroup for MsiInterruptGroup {
    fn trigger(&self, _index: InterruptIndex) -> Result<()> {
        Ok(())
    }

    fn update(&self, _index: InterruptIndex, _config: InterruptSourceConfig) -> Result<()> {
        Ok(())
    }
}

pub struct KvmInterruptManager {}

impl InterruptManager for KvmInterruptManager {
    fn create_group(
        &self,
        _interrupt_type: InterruptType,
        _base: InterruptIndex,
        _count: InterruptIndex,
    ) -> Result<Arc<Box<dyn InterruptSourceGroup>>> {
        let interrupt_source_group = MsiInterruptGroup::new();
        Ok(Arc::new(Box::new(interrupt_source_group)))
    }

    fn destroy_group(&self, _group: Arc<Box<dyn InterruptSourceGroup>>) -> Result<()> {
        Ok(())
    }
}
