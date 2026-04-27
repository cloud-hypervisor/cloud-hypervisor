// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use hypervisor::CpuVendor;
use hypervisor::arch::x86::CpuIdEntry;

use crate::x86_64::CpuidReg;
use crate::x86_64::cpu_profile::cpuid_adjustments::{
    CpuidOutputRegisterAdjustments, CpuidProfileData, MissingCpuidEntriesError,
};

pub mod cpuid_adjustments;

/*
NOTE: This is a temporary stub that will be replaced in a follow up PR.
*/
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between host's with potentially different CPU models.
pub enum CpuProfile {
    #[default]
    Host,
}

impl CpuProfile {
    /// Adjust `cpuid` to the chosen CPU profile.
    ///
    /// The CPUID data obtained from the hypervisor is thus downgraded to the selected profile.
    ///
    /// This method does **not** perform any compatibility checks beyond
    /// ensuring that all expected (sub) leaves required by the CPU profile are present.
    ///
    /// The caller is responsible for ensuring compatibility of `cpuid` by the time it is
    /// utilized.
    ///
    /// If Intel AMX is not desired, then passing `amx:=false` will permit missing (sub)-leaves
    /// that are **purely AMX related**.
    ///
    /// The Host profile guarantees that `cpuid` is returned without any modifications.
    pub(in crate::x86_64) fn adjust_cpuid(
        &self,
        cpuid: Vec<CpuIdEntry>,
        amx: bool,
        cpu_vendor: CpuVendor,
    ) -> Result<Vec<CpuIdEntry>, MissingCpuidEntriesError> {
        let Some(CpuidProfileData { mut adjustments }) = self.cpuid_data() else {
            return Ok(cpuid);
        };

        if (!amx) && matches!(cpu_vendor, CpuVendor::Intel) {
            // In this case we invalidate tile state components and zero out all other purely AMX related leaves
            // in order to maximize our chances of finding all required (sub) leaves.
            for adj in adjustments.iter_mut() {
                if adj.0.sub_leaf.start() != adj.0.sub_leaf.end() {
                    continue;
                }
                let sub_leaf = *adj.0.sub_leaf.start();
                let leaf = adj.0.leaf;
                if (leaf == 0xd) && (sub_leaf == 0) && (adj.0.register == CpuidReg::EAX) {
                    adj.1.replacements &= !((1 << 17) | (1 << 18));
                }

                if (leaf == 0xd) && (sub_leaf == 1) && (adj.0.register == CpuidReg::ECX) {
                    adj.1.replacements &= !((1 << 17) | (1 << 18));
                }

                if (leaf == 0xd) && ((sub_leaf == 17) | (sub_leaf == 18)) {
                    adj.1.replacements = 0;
                }

                // Tile Information (purely AMX related).
                if leaf == 0x1d {
                    adj.1.replacements = 0;
                }

                // TMUL information (purely AMX related)
                if leaf == 0x1e {
                    adj.1.replacements = 0;
                }
            }
        }

        CpuidOutputRegisterAdjustments::adjust_cpuid_entries(cpuid, &adjustments)
    }

    /*
    This function is mainly a stub at this point, but will be
    meaningful once we add some actual CPU profiles in the near
    future.
    */
    /// Obtain CPUID adjustment data related to the CPU profile.
    fn cpuid_data(&self) -> Option<CpuidProfileData> {
        match self {
            CpuProfile::Host => None,
        }
    }
}
