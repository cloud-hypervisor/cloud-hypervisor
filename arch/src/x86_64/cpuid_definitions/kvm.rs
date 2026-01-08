//! This module contains CPUID definitions for the KVM hypervisor.

use std::ops::RangeInclusive;

use crate::x86_64::CpuidReg;
use crate::x86_64::cpuid_definitions::{
    CpuidDefinitions, Parameters, ProfilePolicy, ValueDefinition, ValueDefinitions,
};

/// CPUID features defined for the KVM hypervisor.
///
/// See https://www.kernel.org/doc/html/latest/virt/kvm/x86/cpuid.html
pub const KVM_CPUID_DEFINITIONS: CpuidDefinitions<6> = const {
    CpuidDefinitions([
        //=====================================================================
        //                        KVM CPUID Signature
        // ===================================================================
        (
            Parameters {
                leaf: 0x4000_0000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "max_hypervisor_leaf",
                description: "The maximum valid leaf between 0x4000_0000 and 0x4FFF_FFF",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x4000_0000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "hypervisor_string_ebx",
                description: "Part of the hypervisor string",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x4000_0000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "hypervisor_string_ecx",
                description: "Part of the hypervisor string",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x4000_0000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "hypervisor_string_edx",
                description: "Part of the hypervisor string",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        //=====================================================================
        //                        KVM CPUID Features
        // ===================================================================
        (
            Parameters {
                leaf: 0x4000_0001,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "kvm_feature_clocksource",
                    description: "kvmclock available at MSRs 0x11 and 0x12",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_nop_io_delay",
                    description: "Not necessary to perform delays on PIO operations",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_mmu_op",
                    description: "Deprecated",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_clocksource2",
                    description: "kvmclock available at MSRs 0x4b564d00 and 0x4b564d01",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_async_pf",
                    description: "async pf can be enabled by writing to MSR 0x4b564d02",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_steal_time",
                    description: "steal time can be enabled by writing to msr 0x4b564d03",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_pv_eoi",
                    description: "paravirtualized end of interrupt handler can be enabled by writing to msr 0x4b564d04",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_pv_unhalt",
                    description: "guest checks this feature bit before enabling paravirtualized spinlock support",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_pv_tlb_flush",
                    description: "guest checks this feature bit before enabling paravirtualized tlb flush",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_async_pf_vmexit",
                    description: "paravirtualized async PF VM EXIT can be enabled by setting bit 2 when writing to msr 0x4b564d02",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_pv_send_ipi",
                    description: "guest checks this feature bit before enabling paravirtualized send IPIs",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_poll_control",
                    description: "host-side polling on HLT can be disabled by writing to msr 0x4b564d05.",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_pv_sched_yield",
                    description: "guest checks this feature bit before using paravirtualized sched yield.",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_async_pf_int",
                    description: "guest checks this feature bit before using the second async pf control msr 0x4b564d06 and async pf acknowledgment msr 0x4b564d07.",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_msi_ext_dest_id",
                    description: "guest checks this feature bit before using extended destination ID bits in MSI address bits 11-5.",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_hc_map_gpa_range",
                    description: "guest checks this feature bit before using the map gpa range hypercall to notify the page state change",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_migration_control",
                    description: "guest checks this feature bit before using MSR_KVM_MIGRATION_CONTROL",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "kvm_feature_clocksource_stable_bit",
                    description: "host will warn if no guest-side per-cpu warps are expected in kvmclock",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x4000_0001,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "kvm_hints_realtime",
                description: "guest checks this feature bit to determine that vCPUs are never preempted for an unlimited time allowing optimizations",
                bits_range: (0, 0),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
    ])
};
