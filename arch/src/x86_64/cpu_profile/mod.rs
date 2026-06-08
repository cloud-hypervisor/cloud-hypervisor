// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashSet;

use hypervisor::CpuVendor;
use hypervisor::arch::x86::{CpuIdEntry, MsrEntry};
use log::{error, warn};

use crate::x86_64::cpu_profile::cpuid_adjustments::{
    CpuidOutputRegisterAdjustments, CpuidProfileData, MissingCpuidEntriesError,
};
use crate::x86_64::cpu_profile::msr_adjustments::{
    FeatureMsrAdjustment, MsrProfileData, RequiredMsrUpdates,
};
use crate::x86_64::hyperv_msrs::HYPERV_MSRS;
use crate::x86_64::{AMX_TILECFG_BIT, AMX_TILEDATA_BIT, CpuidReg, Error};

/// Mask indicating availability of the AMX TILECFG state component
const TILECFG_MASK: u32 = 1_u32 << AMX_TILECFG_BIT;
/// Mask indicating availability of the AMX TILEDATA state component
const TILEDATA_MASK: u32 = 1_u32 << AMX_TILEDATA_BIT;

pub mod cpuid_adjustments;
pub mod msr_adjustments;

// TODO: Auto generate the CpuProfile enum with a build script once we introduce user facing CPU profiles.

/// A [`CpuProfile`] is a mechanism for ensuring live migration compatibility
/// between hosts with potentially different CPU models.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// If Intel AMX is not desired, then passing `amx = false` will permit missing (sub)-leaves
    /// that are **purely AMX related**.
    ///
    /// The Host profile guarantees that `cpuid` is returned without any modifications.
    pub(in crate::x86_64) fn adjust_cpuid(
        &self,
        cpuid: Vec<CpuIdEntry>,
        amx: bool,
        cpu_vendor: CpuVendor,
    ) -> Result<Vec<CpuIdEntry>, MissingCpuidEntriesError> {
        let Some(cpuid_profile_data) = self.cpuid_data() else {
            return Ok(cpuid);
        };
        adjust_cpuid(cpuid_profile_data, cpuid, amx, cpu_vendor)
    }

    /// Obtain CPUID adjustment data related to the CPU profile.
    fn cpuid_data(&self) -> Option<CpuidProfileData> {
        // TODO: Auto generate this through a build script once
        // we introduce actual CPU profiles.
        match self {
            CpuProfile::Host => None,
        }
    }

    /// Obtain MSR adjustment data related to the given CPU profile.
    fn msr_data(&self) -> Option<MsrProfileData> {
        // TODO: Auto generate this through a build script once
        // we introduce actual CPU profiles.
        match self {
            CpuProfile::Host => None,
        }
    }

    /// Compute the MSR-related updates required by the chosen CPU profile.
    ///
    /// This method does **not** perform any compatibility checks beyond
    /// ensuring that all expected MSRs are present.
    ///
    /// The caller is responsible for ensuring that the returned feature MSRs
    /// may be utilized.
    ///
    /// If (KVM) Hyper-V is not desired, then passing `kvm_hyperv = false` will ignore
    /// missing MSRs that are **purely Hyper-V related**.
    ///
    /// The Host profile guarantees that `Ok(None)` is returned.
    pub(in crate::x86_64) fn required_msr_updates(
        &self,
        feature_msrs: &[MsrEntry],
        msr_index_list: &[u32],
        kvm_hyperv: bool,
    ) -> Result<Option<RequiredMsrUpdates>, Error> {
        let Some(msr_profile_data) = self.msr_data() else {
            return Ok(None);
        };
        required_msr_updates(msr_profile_data, feature_msrs, msr_index_list, kvm_hyperv).map(Some)
    }
}

/// See [`CpuProfile::adjust_cpuid`](CpuProfile::adjust_cpuid)
fn adjust_cpuid(
    CpuidProfileData { mut adjustments }: CpuidProfileData,
    cpuid: Vec<CpuIdEntry>,
    amx: bool,
    cpu_vendor: CpuVendor,
) -> Result<Vec<CpuIdEntry>, MissingCpuidEntriesError> {
    if (!amx) && matches!(cpu_vendor, CpuVendor::Intel) {
        let amx_tilecfg_leaf = u32::from(AMX_TILECFG_BIT);
        let amx_tiledata_leaf = u32::from(AMX_TILEDATA_BIT);

        // In this case we invalidate tile state components and zero out all other purely AMX related leaves
        // in order to maximize our chances of finding all required (sub) leaves.
        for adj in adjustments.iter_mut() {
            if adj.0.sub_leaf.start() != adj.0.sub_leaf.end() {
                continue;
            }
            let sub_leaf = *adj.0.sub_leaf.start();
            let leaf = adj.0.leaf;
            if (leaf == 0xd) && (sub_leaf == 0) && (adj.0.register == CpuidReg::EAX) {
                adj.1.mask &= !(TILECFG_MASK | TILEDATA_MASK);
                adj.1.replacements &= !(TILECFG_MASK | TILEDATA_MASK);
            }

            if (leaf == 0xd) && (sub_leaf == 1) && (adj.0.register == CpuidReg::ECX) {
                adj.1.mask &= !(TILECFG_MASK | TILEDATA_MASK);
                adj.1.replacements &= !(TILECFG_MASK | TILEDATA_MASK);
            }

            if (leaf == 0xd) && ((sub_leaf == amx_tilecfg_leaf) || (sub_leaf == amx_tiledata_leaf))
            {
                adj.1.mask = 0;
                adj.1.replacements = 0;
            }

            // Tile Information (purely AMX related).
            if leaf == 0x1d {
                adj.1.mask = 0;
                adj.1.replacements = 0;
            }

            // TMUL information (purely AMX related)
            if leaf == 0x1e {
                adj.1.mask = 0;
                adj.1.replacements = 0;
            }
        }
    }

    CpuidOutputRegisterAdjustments::adjust_cpuid_entries(cpuid, &adjustments)
}

/// See [`CpuProfile::required_msr_updates`]
fn required_msr_updates(
    MsrProfileData {
        adjustments,
        permitted_msrs,
    }: MsrProfileData,
    feature_msrs: &[MsrEntry],
    msr_index_list: &[u32],
    kvm_hyperv: bool,
) -> Result<RequiredMsrUpdates, Error> {
    let adjusted_feature_msrs = FeatureMsrAdjustment::adjust_to(&adjustments, feature_msrs)?;

    let queryable_msrs: HashSet<u32> = feature_msrs
        .iter()
        .map(|entry| &entry.index)
        .chain(msr_index_list)
        .copied()
        .collect();

    let permitted: HashSet<u32> = permitted_msrs.iter().map(|r| r.0).collect();

    // Permitted extracts its MSRs from feature MSRs and the MSR index list returned from the hypervisor
    // at the point when the CPU profile is generated. We need to check that the host has all of these
    // MSRs, otherwise we have a compatibility issue.
    if !permitted.is_subset(&queryable_msrs) {
        let mut missing_crucial_msr = false;

        let hyper_v_msrs: HashSet<u32> = HYPERV_MSRS.into_iter().collect();
        // Log the missing entries at the error level
        for missing_msr in permitted.difference(&queryable_msrs) {
            if hyper_v_msrs.contains(missing_msr) && (!kvm_hyperv) {
                warn!(
                    "CPU profile required MSR {missing_msr:#x} was not found: continuing under the assumption that the MSR is Hyper-V related (kvm_hyperv=off)"
                );
                continue;
            }

            missing_crucial_msr = true;
            error!("Did not find MSR {missing_msr:#x}, but it is required by the CPU profile");
        }

        if missing_crucial_msr {
            return Err(Error::CpuProfileMissingMsr);
        }
    }

    // We collect MSRs that are present on the host, but known to be incompatible with
    // the CPU profile and list them as denied. Note that the host certainly supports
    // some MSRs that we cannot directly query for, but we expect these additional MSRs
    // to be compatible with the CPU profile. See MsrProfileData::permitted_msrs for more
    // information about implicitly permitted MSRs.
    //
    // The following collection of denied_msrs should thus be seen as a best effort (or at least a reasonable effort)
    // attempt.
    let denied_msrs: HashSet<u32> = queryable_msrs.difference(&permitted).copied().collect();

    Ok(RequiredMsrUpdates {
        feature_msrs: adjusted_feature_msrs,
        denied_msrs,
    })
}

#[cfg(test)]
mod unit_tests {
    use hypervisor::arch::x86::MsrEntry;
    use proptest::prelude::*;

    use super::{CpuIdEntry, CpuVendor, CpuidProfileData, CpuidReg, adjust_cpuid};
    use crate::x86_64::cpu_profile::cpuid_adjustments::{
        CpuidOutputRegisterAdjustments, CpuidParameters,
    };
    use crate::x86_64::cpu_profile::msr_adjustments::{
        FeatureMsrAdjustment, MsrProfileData, RegisterAddress,
    };
    use crate::x86_64::cpu_profile::{TILECFG_MASK, TILEDATA_MASK, required_msr_updates};
    use crate::x86_64::hyperv_msrs::HYPERV_MSRS;

    // Note that the tests for adjust_cpuid within this module tend to use much simpler inputs
    // than what it will be called with at runtime within Cloud hypervisor. We do this here in order
    // to keep each test focused on the behavioral aspect under test.

    /// Helper function that returns adjustments tied to purely AMX related leaves.
    fn amx_related_adjustments() -> Vec<(CpuidParameters, CpuidOutputRegisterAdjustments)> {
        let amx_adjustments_json = r#"
            [
                [
                  {
                    "leaf": "0xd",
                    "sub_leaf": {
                      "start": "0x11",
                      "end": "0x11"
                    },
                    "register": "EAX"
                  },
                  {
                    "replacements": "0x40",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0xd",
                    "sub_leaf": {
                      "start": "0x11",
                      "end": "0x11"
                    },
                    "register": "EBX"
                  },
                  {
                    "replacements": "0xac0",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0xd",
                    "sub_leaf": {
                      "start": "0x11",
                      "end": "0x11"
                    },
                    "register": "ECX"
                  },
                  {
                    "replacements": "0x2",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0xd",
                    "sub_leaf": {
                      "start": "0x12",
                      "end": "0x12"
                    },
                    "register": "EAX"
                  },
                  {
                    "replacements": "0x2000",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0xd",
                    "sub_leaf": {
                      "start": "0x12",
                      "end": "0x12"
                    },
                    "register": "EBX"
                  },
                  {
                    "replacements": "0xb00",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0xd",
                    "sub_leaf": {
                      "start": "0x12",
                      "end": "0x12"
                    },
                    "register": "ECX"
                  },
                  {
                    "replacements": "0x6",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0x1d",
                    "sub_leaf": {
                      "start": "0x0",
                      "end": "0x0"
                    },
                    "register": "EAX"
                  },
                  {
                    "replacements": "0x1",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0x1d",
                    "sub_leaf": {
                      "start": "0x1",
                      "end": "0x1"
                    },
                    "register": "EAX"
                  },
                  {
                    "replacements": "0x4002000",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0x1d",
                    "sub_leaf": {
                      "start": "0x1",
                      "end": "0x1"
                    },
                    "register": "EBX"
                  },
                  {
                    "replacements": "0x80040",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0x1d",
                    "sub_leaf": {
                      "start": "0x1",
                      "end": "0x1"
                    },
                    "register": "ECX"
                  },
                  {
                    "replacements": "0x10",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0x1e",
                    "sub_leaf": {
                      "start": "0x0",
                      "end": "0x0"
                    },
                    "register": "EAX"
                  },
                  {
                    "replacements": "0x0",
                    "mask": "0x0"
                  }
                ],
                [
                  {
                    "leaf": "0x1e",
                    "sub_leaf": {
                      "start": "0x0",
                      "end": "0x0"
                    },
                    "register": "EBX"
                  },
                  {
                    "replacements": "0x4010",
                    "mask": "0x0"
                  }
                ]
            ]"#;
        serde_json::from_str(amx_adjustments_json).unwrap()
    }

    // Randonly generate three CPUID entries and construct some simple adjustments which we apply
    // through the `adjust_cpuid` function and assert that our expectations are met.
    proptest! {
        #[test]
        fn adjust_cpuid_simple_adjustments(
            leaf0 in any::<u32>(),
            leaf1 in any::<u32>(),
            leaf2 in any::<u32>(),
            a in any::<u32>(),
            b in any::<u32>(),
            c in any::<u32>(),
            d in any::<u32>(),
        ) {
            // Ensure that we have distinct leaves in this test
            let mut leaves = [leaf0, leaf1, leaf2];
            leaves.sort_unstable();
            for (l, i) in leaves.iter_mut().zip([0, 1, 2]) {
                *l = l.wrapping_add(i);
            }

            let [leaf0, leaf1, leaf2] = leaves;

            // The following leaves have some special handling that we test in later
            // more specialized tests. In this simple test we want to avoid them.
            let leaves_with_special_handling = { [0xd, 0x1d, 0x1e] };

            let transform_leaf = |leaf: u32| {
                if leaves_with_special_handling.contains(&leaf) {
                    // Ensures that we get a leaf different from any of the leaves that have special handling
                    leaf | 0x1000
                } else {
                    leaf
                }
            };

            let leaf0 = transform_leaf(leaf0);

            let leaf1 = transform_leaf(leaf1);

            let leaf2 = transform_leaf(leaf2);

            // The leaves should still be distinct
            assert!(leaf0 != leaf1);
            assert!(leaf0 != leaf2);
            assert!(leaf1 != leaf2);
            // We have now setup leaves to be used in this test

            // Let's now construct some simple adjustments

            // mask retaining bits 0,1,2 and 3
            let first_four_bits_mask = 15;

            // Retain the first four bits of the register and overwrite the remaining bits with the value "42"
            let adjustment_u = CpuidOutputRegisterAdjustments {
                mask: first_four_bits_mask,
                replacements: 42 << 4,
            };

            let assert_adjustment_u = |new_value: u32, old_value: u32| {
                assert_eq!(new_value & first_four_bits_mask, (old_value & first_four_bits_mask));
                // Recall that we placed the value 42 into bits 31:4
                assert_eq!(new_value >> 4, 42);
            };

            // Set bits 0 and 28 and zero out the rest
            let adjustment_v = CpuidOutputRegisterAdjustments {
                replacements: 1 | (1 << 28),
                mask: 0
            };

            let assert_adjustment_v = |new_value: u32| {
                assert_eq!(new_value, 1 | (1 << 28));
            };

            // Make adjustment_u apply to EAX of leaf0 and EBX of leaf1.
            //
            // Make adjustment_v apply to EDX of leaf0 and ECX of leaf1.
            //
            // We do not specify any adjustment for leaf2.
            let cpuid_profile_data = CpuidProfileData {
                adjustments: vec![
                    (
                        CpuidParameters {
                            leaf: leaf0,
                            sub_leaf: 0..=0,
                            register: CpuidReg::EAX,
                        },
                        adjustment_u,
                    ),
                    (
                        CpuidParameters {
                            leaf: leaf0,
                            sub_leaf: 0..=0,
                            register: CpuidReg::EDX,
                        },
                        adjustment_v,
                    ),
                    (
                        CpuidParameters {
                            leaf: leaf1,
                            sub_leaf: 0..=0,
                            register: CpuidReg::EBX,
                        },
                        adjustment_u,
                    ),
                    (
                        CpuidParameters {
                            leaf: leaf1,
                            sub_leaf: 0..=0,
                            register: CpuidReg::ECX,
                        },
                        adjustment_v,
                    ),
                ],
            };

            // Construct cpuid entries consisting of leaves leaf0, leaf1 and leaf2.
            // The registers eax, ebx, ecx, edx are populated with the randomly generated values `a`, `b`, `c` and `d`
            // and we do not consider sub-leaves in this test.
            let cpuid = vec![
                CpuIdEntry {
                    function: leaf0,
                    index: 0,
                    flags: 0,
                    eax: a,
                    ebx: b,
                    ecx: c,
                    edx: d,
                },
                CpuIdEntry {
                    function: leaf1,
                    index: 0,
                    flags: 0,
                    eax: a,
                    ebx: b,
                    ecx: c,
                    edx: d,
                },
                CpuIdEntry {
                    function: leaf2,
                    index: 0,
                    flags: 0,
                    eax: a,
                    ebx: b,
                    ecx: c,
                    edx: d,
                },
            ];

            // Check that the output of `adjust_cpuid` contains the same CPUID leaves as the
            // `cpuid` vector we started with.
            let expected_num_entries = cpuid.len();
            let mut found_entry_count = 0;

            let adjusted_cpuid =
                adjust_cpuid(cpuid_profile_data, cpuid, false, CpuVendor::Intel).unwrap();

            // Iterate through our adjusted entries and assert that our expectations are met.
            for entry in adjusted_cpuid {
                let CpuIdEntry {
                    function,
                    index,
                    flags,
                    eax,
                    ebx,
                    ecx,
                    edx,
                } = entry;
                if function == leaf0 {
                    found_entry_count += 1;

                    assert_adjustment_u(eax, a);
                    assert_adjustment_v(edx);

                    // ebx and ecx should be zeroed out
                    assert_eq!(ebx, 0);
                    assert_eq!(ecx, 0);
                }
                if function == leaf1 {
                    found_entry_count += 1;
                    assert_adjustment_u(ebx, b);
                    assert_adjustment_v(ecx);

                    // eax and edx should be zeroed out
                    assert_eq!(eax, 0);
                    assert_eq!(edx, 0);
                }

                if function == leaf2 {
                    found_entry_count += 1;

                    // All registers should be zeroed out
                    assert_eq!(eax, ebx);
                    assert_eq!(ebx, ecx);
                    assert_eq!(ecx, edx);
                    assert_eq!(edx, 0);
                }

                // Index and flags should not be altered. Since these were both
                // always 0 for all leaves in the original `cpuid` that should
                // remain the case.
                assert_eq!(index, 0);
                assert_eq!(flags, 0);
            }

            assert_eq!(expected_num_entries, found_entry_count);
        }
    }

    // Check that adjust_cpuid follows the prescribed adjustments on
    // specified subleaf ranges
    #[test]
    fn adjust_cpuid_works_with_subleaf_ranges() {
        // As in the real runtime case the Topology enumeration leaves should not be altered
        // by CPU profiles. In this test we thus define adjustment's that do not alter non-reserved
        // bits for the 0x1f leaf and its sub-leaves.
        let adjustments_json = r#"
        [
            [
              {
                "leaf": "0x1f",
                "sub_leaf": {
                  "start": "0x0",
                  "end": "0xffffffff"
                },
                "register": "EAX"
              },
              {
                "replacements": "0x0",
                "mask": "0x1f"
              }
            ],
            [
              {
                "leaf": "0x1f",
                "sub_leaf": {
                  "start": "0x0",
                  "end": "0xffffffff"
                },
                "register": "EBX"
              },
              {
                "replacements": "0x0",
                "mask": "0xffff"
              }
            ],
            [
              {
                "leaf": "0x1f",
                "sub_leaf": {
                  "start": "0x0",
                  "end": "0xffffffff"
                },
                "register": "ECX"
              },
              {
                "replacements": "0x0",
                "mask": "0xffff"
              }
            ],
            [
              {
                "leaf": "0x1f",
                "sub_leaf": {
                  "start": "0x0",
                  "end": "0xffffffff"
                },
                "register": "EDX"
              },
              {
                "replacements": "0x0",
                "mask": "0xffffffff"
              }
            ]
        ]"#;
        let cpuid_profile_data = CpuidProfileData {
            adjustments: serde_json::from_str(adjustments_json).unwrap(),
        };

        let cpuid = vec![
            CpuIdEntry {
                function: 0x1f,
                index: 0,
                flags: 1,
                eax: 0x00000001,
                ebx: 0x00000002,
                ecx: 0x00000100,
                edx: 0x00000000,
            },
            CpuIdEntry {
                function: 0x1f,
                index: 1,
                flags: 1,
                eax: 0x00000004,
                ebx: 0x00000008,
                ecx: 0x00000201,
                edx: 0x00000006,
            },
        ];

        let adjusted_cpuid =
            adjust_cpuid(cpuid_profile_data, cpuid.clone(), false, CpuVendor::Intel).unwrap();

        // Check that cpuid was indeed not altered
        for entry in cpuid {
            let adjusted_entry = adjusted_cpuid
                .iter()
                .find(|e| (e.function == entry.function) && (e.index == entry.index))
                .unwrap();
            assert_eq!(entry.eax, adjusted_entry.eax);
            assert_eq!(entry.ebx, adjusted_entry.ebx);
            assert_eq!(entry.ecx, adjusted_entry.ecx);
            assert_eq!(entry.edx, adjusted_entry.edx);
        }
    }

    #[test]
    fn adjust_cpuid_fails_on_missing_entries() {
        let cpuid = vec![CpuIdEntry {
            function: 0x0,
            index: 0x0,
            eax: 0x20,
            ebx: 0x756e6547,
            ecx: 0x6c65746e,
            edx: 0x49656e69,
            flags: 0,
        }];

        let cpuid_profile_data = CpuidProfileData {
            adjustments: vec![(
                CpuidParameters {
                    leaf: 0x1,
                    sub_leaf: 0x0..=0x0,
                    register: CpuidReg::EAX,
                },
                CpuidOutputRegisterAdjustments {
                    replacements: 0x000806f8,
                    mask: 0,
                },
            )],
        };
        let _ =
            adjust_cpuid(cpuid_profile_data, cpuid.clone(), false, CpuVendor::Intel).unwrap_err();

        // Also check this for a purely AMX related leaves which has special handling
        let _ = adjust_cpuid(
            CpuidProfileData {
                adjustments: amx_related_adjustments(),
            },
            cpuid,
            true,
            CpuVendor::Intel,
        )
        .unwrap_err();
    }

    // Check that if `amx = false` then AMX related leaves are zeroed out
    #[test]
    fn adjust_cpuid_no_amx_zeros_amx_leaves() {
        // Not AMX related
        let leaf_zero = CpuIdEntry {
            function: 0x0,
            index: 0x0,
            eax: 0x20,
            ebx: 0x756e6547,
            ecx: 0x6c65746e,
            edx: 0x49656e69,
            flags: 0,
        };

        let cpuid = vec![
            leaf_zero,
            // State components base leaf extracted from granite rapids the AMX related state component bits are set
            CpuIdEntry {
                function: 0xd,
                index: 0x0,
                flags: 1,
                eax: 0x000602e7,
                ebx: 0x00002b00,
                ecx: 0x00002b00,
                edx: 0x00000000,
            },
            // TILECFG state
            CpuIdEntry {
                function: 0xd,
                index: 0x11,
                flags: 1,
                eax: 0x00000040,
                ebx: 0x00000ac0,
                ecx: 0x00000002,
                edx: 0x00000000,
            },
            // TILEDATA state
            CpuIdEntry {
                function: 0xd,
                index: 0x12,
                flags: 1,
                eax: 0x00002000,
                ebx: 0x00000b00,
                ecx: 0x00000006,
                edx: 0x00000000,
            },
            // Tile information base leaf
            CpuIdEntry {
                function: 0x1d,
                index: 0x0,
                flags: 1,
                eax: 0x00000001,
                ebx: 0x00000000,
                ecx: 0x00000000,
                edx: 0x00000000,
            },
            // Tile Palette 1
            CpuIdEntry {
                function: 0x1d,
                index: 0x1,
                flags: 1,
                eax: 0x04002000,
                ebx: 0x00080040,
                ecx: 0x00000010,
                edx: 0x00000000,
            },
            // TMUL information base leaf
            CpuIdEntry {
                function: 0x1e,
                index: 0x0,
                flags: 1,
                eax: 0x00000000,
                ebx: 0x00004010,
                ecx: 0x00000000,
                edx: 0x00000000,
            },
        ];

        let adjustments: Vec<(CpuidParameters, CpuidOutputRegisterAdjustments)> =
            amx_related_adjustments()
                .into_iter()
                // leave leaf 0 untouched
                .chain([
                    (
                        CpuidParameters {
                            leaf: 0x0,
                            sub_leaf: 0x0..=0x0,
                            register: CpuidReg::EAX,
                        },
                        CpuidOutputRegisterAdjustments {
                            replacements: 0,
                            mask: u32::MAX,
                        },
                    ),
                    (
                        CpuidParameters {
                            leaf: 0x0,
                            sub_leaf: 0x0..=0x0,
                            register: CpuidReg::EBX,
                        },
                        CpuidOutputRegisterAdjustments {
                            replacements: 0,
                            mask: u32::MAX,
                        },
                    ),
                    (
                        CpuidParameters {
                            leaf: 0x0,
                            sub_leaf: 0x0..=0x0,
                            register: CpuidReg::ECX,
                        },
                        CpuidOutputRegisterAdjustments {
                            replacements: 0,
                            mask: u32::MAX,
                        },
                    ),
                    (
                        CpuidParameters {
                            leaf: 0x0,
                            sub_leaf: 0x0..=0x0,
                            register: CpuidReg::EDX,
                        },
                        CpuidOutputRegisterAdjustments {
                            replacements: 0,
                            mask: u32::MAX,
                        },
                    ),
                ])
                // Keep EAX of leaf 0xd so we see that the AMX-related state component bits get unset, regardless of what
                // the adjustment says
                .chain([(
                    CpuidParameters {
                        leaf: 0xd,
                        sub_leaf: 0x0..=0x0,
                        register: CpuidReg::EAX,
                    },
                    CpuidOutputRegisterAdjustments {
                        mask: u32::MAX,
                        replacements: 0,
                    },
                )])
                .collect();

        let adjusted_cpuid = adjust_cpuid(
            CpuidProfileData { adjustments },
            cpuid.clone(),
            false,
            CpuVendor::Intel,
        )
        .unwrap();

        // Check that leaf zero is left untouched as expected
        {
            let adjusted_leaf_zero = adjusted_cpuid
                .iter()
                .find(|entry| entry.function == 0x0)
                .unwrap();
            assert_eq!(adjusted_leaf_zero.eax, leaf_zero.eax);
            assert_eq!(adjusted_leaf_zero.ebx, leaf_zero.ebx);
            assert_eq!(adjusted_leaf_zero.ecx, leaf_zero.ecx);
            assert_eq!(adjusted_leaf_zero.edx, leaf_zero.edx);
        }

        // Check that the TILECFG and TILEDATA state bits are now zeroed ut
        {
            let state_cmp_base_leaf = adjusted_cpuid
                .iter()
                .find(|entry| (entry.function == 0xd) && (entry.index == 0x0))
                .unwrap();
            // EAX should not have been zeroed out in its entirety
            assert!(state_cmp_base_leaf.eax != 0);
            // The TILECFG state bit should be unset
            assert_eq!(state_cmp_base_leaf.eax & TILECFG_MASK, 0);
            // The TILEDATA state bit should be unset
            assert_eq!(state_cmp_base_leaf.eax & TILEDATA_MASK, 0);
        }

        // Since all remaining entries we placed in `cpuid` are purely AMX related we now
        // expect them to be zeroed out
        for entry in adjusted_cpuid {
            if entry.function == 0 || (entry.function == 0xd && entry.index == 0x0) {
                continue;
            }
            assert_eq!(entry.eax, 0);
            assert_eq!(entry.ebx, 0);
            assert_eq!(entry.ecx, 0);
            assert_eq!(entry.edx, 0);
        }
    }

    // Check that if `amx = false` then missing purely AMX related leaves
    // do not lead to failure
    #[test]
    fn adjust_cpuid_no_amx_missing_amx_leaves_accepted() {
        let cpuid = vec![CpuIdEntry {
            function: 0x0,
            index: 0x0,
            eax: 0x20,
            ebx: 0x756e6547,
            ecx: 0x6c65746e,
            edx: 0x49656e69,
            flags: 0,
        }];

        let _ = adjust_cpuid(
            CpuidProfileData {
                adjustments: amx_related_adjustments(),
            },
            cpuid,
            false,
            CpuVendor::Intel,
        )
        .unwrap();
    }

    // Note that the tests for required_msr_updates within this module tend to use much simpler inputs
    // than what it will be called with at runtime within Cloud hypervisor. We do this here in order
    // to keep each test focused on the behavioral aspect under test.

    proptest! {
    #[test]
    fn failure_on_missing_msrs(
        host_feature_msrs in prop::collection::hash_set(any::<(u32,u64)>(), 20),
        mut host_permitted_msrs in prop::collection::vec(any::<u32>(), 200),
        feature_msr_removal_idx in  any::<usize>(),
        permitted_msr_removal_idx in any::<usize>(),
    ) {
        // Let our adjustments just retain whatever we have got in this test
        let adjustments = host_feature_msrs
            .iter()
            .map(|(idx, _)| {
                (
                    RegisterAddress(*idx),
                    FeatureMsrAdjustment {
                        replacements: 0,
                        mask: u64::MAX,
                    },
                )
            })
            .collect();

        // Make sure that host_permitted_msrs has at least one MSR that is not a feature MSR
        for i in 0.. u32::try_from(host_feature_msrs.len()).unwrap()  + 1 {
            if !host_feature_msrs.iter().any(|entry| entry.0 == i) {
                host_permitted_msrs.push(i);
            }
        }

        let mut host_feature_msrs: Vec<MsrEntry> = host_feature_msrs
            .into_iter()
            .map(|(idx, data)| MsrEntry {
                index: idx,
                data,
            })
            .collect();


        // Make sure that the permitted MSRs contain the feature MSRs
        host_permitted_msrs.extend(host_feature_msrs.iter().map(|entry| entry.index));
        host_permitted_msrs.sort();
        host_permitted_msrs.dedup();

        let permitted_msrs = host_permitted_msrs
            .iter()
            .map(|addr| RegisterAddress(*addr))
            .collect();

        let profile_data = MsrProfileData {
            adjustments,
            permitted_msrs,
        };

        // Reality check that the current host_feature_msrs and host_permitted_msrs are accepted by the artificial profile
        let required_updates = required_msr_updates(
            profile_data.clone(),
            &host_feature_msrs,
            &host_permitted_msrs,
            true,
        )
        .unwrap();

        // Small additional reality check that the required feature MSRs stay the same
        let random_idx = feature_msr_removal_idx % host_feature_msrs.len();
        let random_feature_msr = required_updates.feature_msrs[random_idx];
        assert!(
            host_feature_msrs
                .iter()
                .any(|entry| entry.index == random_feature_msr.index
                    && entry.data == random_feature_msr.data)
        );

        // Now we try again, but with one of the host's feature MSRs removed this should not work
        let removed_feature_msr = host_feature_msrs.remove(random_idx);
        let _ = required_msr_updates(
            profile_data.clone(),
            &host_feature_msrs,
            &host_permitted_msrs,
            true,
        )
        .unwrap_err();

        // Re-insert the removed feature MSR, but remove one of the host's permitted MSRs that is not a
        // feature MSR and try again. If the removed MSR is not a feature MSR then we must have
        // an error, otherwise the function should succeed.
        host_feature_msrs.insert(random_idx, removed_feature_msr);

        let random_idx = permitted_msr_removal_idx % host_permitted_msrs.len();
        let removed_msr = host_permitted_msrs.remove(random_idx);
        if host_feature_msrs.iter().any(|entry| entry.index == removed_msr) {
            prop_assert!(required_msr_updates(profile_data, &host_feature_msrs, &host_permitted_msrs, true).is_ok());
        } else {
            let _ = required_msr_updates(profile_data, &host_feature_msrs, &host_permitted_msrs, true)
                .unwrap_err();
            }
        }
    }

    // This test is very contrived. It's only purpose is to illustrate behavior with regards to missing hyper-V MSRs.
    #[test]
    fn required_msr_updates_hyperv() {
        let hyperv_msrs = HYPERV_MSRS.to_vec();
        let profile_data = MsrProfileData {
            adjustments: Vec::new(),
            permitted_msrs: hyperv_msrs
                .iter()
                .map(|msr| RegisterAddress(*msr))
                .collect(),
        };

        // If the host doesn't have the hyper-V related MSR that are permitted by the CPU profile then the call to required_msr_updates
        // must fail
        let _ = required_msr_updates(profile_data.clone(), &[], &[0x10], true).unwrap_err();

        // If kvm_hyperv is false, then missing such MSRs is permitted however
        let _ = required_msr_updates(profile_data, &[], &[0x10], false).unwrap();
    }

    // Check that the CPU profile adjustments satisfy our expectations.
    //
    // We only focus on two feature MSRs in this test. Realistically
    // there would be a few more, but we only want to illustrate that MSR
    // adjustments required by the CPU profile have the expected behavior.
    #[test]
    fn required_msr_updates_expected_adjustments() {
        const IA32_BIOS_SIGN_ID: u32 = 0x8b;
        const IA32_VMX_MISC: u32 = 0x485;

        let host_feature_msrs = [
            MsrEntry {
                index: IA32_BIOS_SIGN_ID,
                data: 1 << 42,
            },
            // Extracted from KVM on a Granite Rapids CPU
            MsrEntry {
                index: IA32_VMX_MISC,
                data: 0x20000165,
            },
        ];

        // Example where the profile decides to retain the patch signature ID
        // thus keeping whatever the host has. Zeroing the value out would also
        // make sense since guests should not rely on this MSR anyway.
        let bios_sign_id_msr_adjustment = (
            RegisterAddress(IA32_BIOS_SIGN_ID),
            FeatureMsrAdjustment {
                replacements: 0,
                mask: 0xffffffff00000000,
            },
        );

        // We zero out IA32_VMX_MISC[8] (wait-for-SIPI), but otherwise set exactly
        // what we extracted from a Sapphire Rapids machine
        let vmx_misc_msr_adjustment = (
            RegisterAddress(IA32_VMX_MISC),
            FeatureMsrAdjustment {
                replacements: 0x20000065,
                mask: 0,
            },
        );

        let profile_data = MsrProfileData {
            adjustments: vec![bios_sign_id_msr_adjustment, vmx_misc_msr_adjustment.clone()],
            permitted_msrs: vec![
                RegisterAddress(IA32_BIOS_SIGN_ID),
                RegisterAddress(IA32_VMX_MISC),
            ],
        };

        let required_updates = required_msr_updates(
            profile_data,
            &host_feature_msrs,
            &[IA32_BIOS_SIGN_ID, IA32_VMX_MISC],
            false,
        )
        .unwrap();

        assert_eq!(required_updates.feature_msrs.len(), host_feature_msrs.len());

        for feat_msr in required_updates.feature_msrs {
            match feat_msr.index {
                IA32_BIOS_SIGN_ID => {
                    // The original value should be retained
                    assert_eq!(feat_msr.data, host_feature_msrs[0].data);
                }
                IA32_VMX_MISC => {
                    // In this case the value should match the replacement
                    assert_eq!(feat_msr.data, vmx_misc_msr_adjustment.1.replacements);
                }
                _ => unreachable!(),
            }
        }
    }
}
