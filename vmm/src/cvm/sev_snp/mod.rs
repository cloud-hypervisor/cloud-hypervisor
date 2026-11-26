// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

//! Launch and guest state handling for AMD SEV-SNP guests.

#[cfg(all(feature = "kvm", feature = "sev_snp", feature = "fw_cfg"))]
mod sev;

use std::sync::{Arc, Mutex};
use std::thread;

use arch::EntryPoint;
use igvm::IgvmFile;
use igvm_defs::SnpPolicy;
use vm_migration::{Snapshot, snapshot_from_id};

#[cfg(all(feature = "kvm", feature = "sev_snp", feature = "fw_cfg"))]
pub(crate) use self::sev::{
    MeasuredBootInfo, SEV_HASH_BLOCK_ADDRESS, SEV_HASH_BLOCK_SIZE, SevSnpSharedPageTracker,
};
use crate::cpu::CpuManager;
use crate::igvm::igvm_loader;
use crate::memory_manager::MemoryManager;
use crate::vm::{Error, Result, Vm};
use crate::{CPU_MANAGER_SNAPSHOT_ID, VmConfig};

fn default_guest_policy() -> SnpPolicy {
    SnpPolicy::new()
        .with_abi_minor(0)
        .with_abi_major(0)
        // SMT permitted: allows the guest to run on an SMT-enabled host.
        // This is the permissive default; future work can expose this as a
        // configurable platform option.
        .with_smt(1)
        .with_reserved_must_be_one(1)
        .with_migrate_ma(0)
}

pub(crate) fn start_launch(
    vm: &dyn hypervisor::Vm,
    memory_manager: &Arc<Mutex<MemoryManager>>,
    cpu_manager: &Arc<Mutex<CpuManager>>,
    config: &Arc<Mutex<VmConfig>>,
    snapshot: Option<&Snapshot>,
    igvm_file: Option<IgvmFile>,
) -> Result<Option<thread::JoinHandle<Result<EntryPoint>>>> {
    // Create vCPUs before SEV-SNP initialization, including reserved
    // hotplug vCPUs on KVM. Only boot_vcpus are started at boot.
    cpu_manager
        .lock()
        .unwrap()
        .create_boot_vcpus(snapshot_from_id(snapshot, CPU_MANAGER_SNAPSHOT_ID))
        .map_err(Error::CpuManager)?;

    // Extract guest policy from IGVM if available, otherwise use default.
    let guest_policy = igvm_file
        .as_ref()
        .and_then(igvm_loader::extract_guest_policy)
        .unwrap_or_else(default_guest_policy);

    vm.sev_snp_init(guest_policy)
        .map_err(Error::InitializeSevSnpVm)?;

    // Load payload for SEV-SNP (IGVM parser needs cpu_manager for cpuid)
    if snapshot.is_none() {
        Vm::load_payload_async(memory_manager, config, cpu_manager, igvm_file)
    } else {
        Ok(None)
    }
}
