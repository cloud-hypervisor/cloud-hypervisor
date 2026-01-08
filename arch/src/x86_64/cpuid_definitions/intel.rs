//! This module contains CPUID definitions for Intel CPUs.
use std::ops::RangeInclusive;

use super::{
    CpuidDefinitions, CpuidReg, Parameters, ProfilePolicy, ValueDefinition, ValueDefinitions,
};

/// Contains CPUID definitions described in "Intel Architecture Instruction Set Extensions and Future Features"
///
/// ## Missing leaves
///
/// The following known CPUID leaves are left out of this table:
/// - 0x3 (Only relevant for Intel Pentium III),
/// - 0x12 (Only relevant for SGX which is deprecated),
/// - 0x19 (Key locker leaf. These features are not in scope for CPU profiles for the time being)
/// - 0x1a (Native Model ID Enumeration leaf),
/// - 0x1b (PCONFIG Information Sub-leaf. This is not in scope for CPU profiles for the time being),
/// - 0x27 (L3 Cache Intel RDT Monitoring Capability Asymmetric Enumeration),
/// - 0x28 (Intel Resource Director Technology Allocation Asymmetric Enumeration),
/// - 0x21 (Only relevant for Intel TDX which is not in scope fore CPU profiles for the time being),
/// - 0x40000000 - 0x4FFFFFFF (Reserved for hypervisors),
///
/// ### How we produced this table
///
/// We first ran the [`cpuidgen` tool](https://gitlab.com/x86-cpuid.org/x86-cpuid-db), whose
/// output is licensed under the SPDX Creative Commons Zero 1.0 Universal License. We then wrote a
/// throw-away Rust script to modify the output into something more similar to Rust code. Following
/// this we used macros and other functionality in the [Helix editor](https://helix-editor.com/) to
/// get actual Rust code.
///
/// We then read through the CPUID section (1.4) of the Intel Architecture Instruction Set
/// Extensions and Future Features manual and manually inserted several leaf definitions that
/// we noticed were missing from the table we had produced. During this process we also changed
/// a few of the short names and descriptions to be more inline with what is written in the
/// aforementioned Intel manual. Finally we decided on a [`ProfilePolicy`] to be set for every
/// single [`ValueDefinition`] and manually appended those.
pub static INTEL_CPUID_DEFINITIONS: CpuidDefinitions<154> = const {
    CpuidDefinitions([
        // =========================================================================================
        //                           Basic CPUID Information
        // =========================================================================================
        (
            Parameters {
                leaf: 0x0,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "max_std_leaf",
                description: "Maximum Input value for Basic CPUID Information",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x0,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_vendorid_0",
                description: "CPU vendor ID string bytes 0 - 3",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x0,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_vendorid_2",
                description: "CPU vendor ID string bytes 8 - 11",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x0,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_vendorid_1",
                description: "CPU vendor ID string bytes 4 - 7",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        // TODO: Do we really want to inherit these values from the corresponding CPU, or should we zero it out or set something else here?
        (
            Parameters {
                leaf: 0x1,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "stepping",
                    description: "Stepping ID",
                    bits_range: (0, 3),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "base_model",
                    description: "Base CPU model ID",
                    bits_range: (4, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "base_family_id",
                    description: "Base CPU family ID",
                    bits_range: (8, 11),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cpu_type",
                    description: "CPU type",
                    bits_range: (12, 13),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "ext_model",
                    description: "Extended CPU model ID",
                    bits_range: (16, 19),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "ext_family",
                    description: "Extended CPU family ID",
                    bits_range: (20, 27),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "brand_id",
                    description: "Brand index",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "clflush_size",
                    description: "CLFLUSH instruction cache line size",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                // This is set by cloud hypervisor
                ValueDefinition {
                    short: "n_logical_cpu",
                    description: "Logical CPU count",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Static(0),
                },
                // This is set by cloud hypervisor
                ValueDefinition {
                    short: "local_apic_id",
                    description: "Initial local APIC physical ID",
                    bits_range: (24, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "sse3",
                    description: "Streaming SIMD Extensions 3 (SSE3)",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pclmulqdq",
                    description: "PCLMULQDQ instruction support",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "dtes64",
                    description: "64-bit DS save area",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "monitor",
                    description: "MONITOR/MWAIT support",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ds_cpl",
                    description: "CPL Qualified Debug Store",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                // TODO: Ideally configurable by the user (host must have this otherwise CHV will not run)
                ValueDefinition {
                    short: "vmx",
                    description: "Virtual Machine Extensions",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(1),
                },
                ValueDefinition {
                    short: "smx",
                    description: "Safer Mode Extensions",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "est",
                    description: "Enhanced Intel SpeedStep",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "tm2",
                    description: "Thermal Monitor 2",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ssse3",
                    description: "Supplemental SSE3",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "cnxt_id",
                    description: "L1 Context ID",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "sdbg",
                    description: "Silicon Debug",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "fma",
                    description: "FMA extensions using YMM state",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cx16",
                    description: "CMPXCHG16B instruction support",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "xtpr",
                    description: "xTPR Update Control",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Static(0),
                },
                // MSR related
                ValueDefinition {
                    short: "pdcm",
                    description: "Perfmon and Debug Capability",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pcid",
                    description: "Process-context identifiers",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "dca",
                    description: "Direct Cache Access",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sse4_1",
                    description: "SSE4.1",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sse4_2",
                    description: "SSE4.2",
                    bits_range: (20, 20),
                    policy: ProfilePolicy::Inherit,
                },
                // Set by Cloud hypervisor
                ValueDefinition {
                    short: "x2apic",
                    description: "X2APIC support",
                    bits_range: (21, 21),
                    policy: ProfilePolicy::Static(1),
                },
                ValueDefinition {
                    short: "movbe",
                    description: "MOVBE instruction support",
                    bits_range: (22, 22),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "popcnt",
                    description: "POPCNT instruction support",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Inherit,
                },
                // Set by Cloud hypervisor
                ValueDefinition {
                    short: "tsc_deadline_timer",
                    description: "APIC timer one-shot operation",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "aes",
                    description: "AES instructions",
                    bits_range: (25, 25),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xsave",
                    description: "XSAVE (and related instructions) support",
                    bits_range: (26, 26),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "osxsave",
                    description: "XSAVE (and related instructions) are enabled by OS",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx",
                    description: "AVX instructions support",
                    bits_range: (28, 28),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "f16c",
                    description: "Half-precision floating-point conversion support",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "rdrand",
                    description: "RDRAND instruction support",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Inherit,
                },
                // TODO: If set by CHV set to 0 and write comment
                ValueDefinition {
                    short: "guest_status",
                    description: "System is running as guest; (para-)virtualized system",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "fpu",
                    description: "Floating-Point Unit on-chip (x87)",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "vme",
                    description: "Virtual-8086 Mode Extensions",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "de",
                    description: "Debugging Extensions",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pse",
                    description: "Page Size Extension",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "tsc",
                    description: "Time Stamp Counter",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "msr",
                    description: "Model-Specific Registers (RDMSR and WRMSR support)",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pae",
                    description: "Physical Address Extensions",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "mce",
                    description: "Machine Check Exception",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cx8",
                    description: "CMPXCHG8B instruction",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "apic",
                    description: "APIC on-chip",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Static(1),
                },
                // MSR related (maybe not necessary to look into which ones)
                ValueDefinition {
                    short: "sep",
                    description: "SYSENTER, SYSEXIT, and associated MSRs",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "mtrr",
                    description: "Memory Type Range Registers",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pge",
                    description: "Page Global Extensions",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "mca",
                    description: "Machine Check Architecture",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cmov",
                    description: "Conditional Move Instruction",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pat",
                    description: "Page Attribute Table",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pse36",
                    description: "Page Size Extension (36-bit)",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "psn",
                    description: "Processor Serial Number",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "clfsh",
                    description: "CLFLUSH instruction",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "ds",
                    description: "Debug Store",
                    bits_range: (21, 21),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "acpi",
                    description: "Thermal monitor and clock control",
                    bits_range: (22, 22),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "mmx",
                    description: "MMX instructions",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "fxsr",
                    description: "FXSAVE and FXRSTOR instructions",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sse",
                    description: "SSE instructions",
                    bits_range: (25, 25),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sse2",
                    description: "SSE2 instructions",
                    bits_range: (26, 26),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "ss",
                    description: "Self Snoop",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "htt",
                    description: "Hyper-threading",
                    bits_range: (28, 28),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "tm",
                    description: "Thermal Monitor",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Static(0),
                },
                // TODO: Not really sure what the default should be for PBE. It seems like it is something that needs to be enabled via the IA32_MISC_ENABLE MSR hence perhaps this should be set via CPU features?
                // MSR related
                ValueDefinition {
                    short: "pbe",
                    description: "Pending Break Enable",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // =========================================================================================
        //                           Cache and TLB Information
        // =========================================================================================
        (
            Parameters {
                leaf: 0x2,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "iteration_count",
                    description: "Number of times this leaf must be queried",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc1",
                    description: "Descriptor #1",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc2",
                    description: "Descriptor #2",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc3",
                    description: "Descriptor #3",
                    bits_range: (24, 30),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "eax_invalid",
                    description: "Descriptors 1-3 are invalid if set",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x2,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "desc4",
                    description: "Descriptor #4",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc5",
                    description: "Descriptor #5",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc6",
                    description: "Descriptor #6",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc7",
                    description: "Descriptor #7",
                    bits_range: (24, 30),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "ebx_invalid",
                    description: "Descriptors 4-7 are invalid if set",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x2,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "desc8",
                    description: "Descriptor #8",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc9",
                    description: "Descriptor #9",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc10",
                    description: "Descriptor #10",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc11",
                    description: "Descriptor #11",
                    bits_range: (24, 30),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "ecx_invalid",
                    description: "Descriptors 8-11 are invalid if set",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x2,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "desc12",
                    description: "Descriptor #12",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc13",
                    description: "Descriptor #13",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc14",
                    description: "Descriptor #14",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "desc15",
                    description: "Descriptor #15",
                    bits_range: (24, 30),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "edx_invalid",
                    description: "Descriptors 12-15 are invalid if set",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        // =========================================================================================
        //                         Deterministic Cache Parameters
        // =========================================================================================
        (
            Parameters {
                leaf: 0x4,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cache_type",
                    description: "Cache type field",
                    bits_range: (0, 4),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "cache_level",
                    description: "Cache level (1-based)",
                    bits_range: (5, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                // TODO: Could there be a problem migrating from a CPU with self-initializing cache to one without?
                ValueDefinition {
                    short: "cache_self_init",
                    description: "Self-initializing cache level",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "fully_associative",
                    description: "Fully-associative cache",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "num_threads_sharing",
                    description: "Number logical CPUs sharing this cache",
                    bits_range: (14, 25),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "num_cores_on_die",
                    description: "Number of cores in the physical package",
                    bits_range: (26, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x4,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cache_linesize",
                    description: "System coherency line size (0-based)",
                    bits_range: (0, 11),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "cache_npartitions",
                    description: "Physical line partitions (0-based)",
                    bits_range: (12, 21),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "cache_nways",
                    description: "Ways of associativity (0-based)",
                    bits_range: (22, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x4,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cache_nsets",
                description: "Cache number of sets (0-based)",
                bits_range: (0, 30),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x4,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "wbinvd_rll_no_guarantee",
                    description: "WBINVD/INVD not guaranteed for Remote Lower-Level caches",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "ll_inclusive",
                    description: "Cache is inclusive of Lower-Level caches",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "complex_indexing",
                    description: "Not a direct-mapped cache (complex function)",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        // =========================================================================================
        //                                 MONITOR/MWAIT
        // =========================================================================================
        (
            Parameters {
                leaf: 0x5,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "min_mon_size",
                description: "Smallest monitor-line size, in bytes",
                bits_range: (0, 15),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x5,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "max_mon_size",
                description: "Largest monitor-line size, in bytes",
                bits_range: (0, 15),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x5,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "mwait_ext",
                    description: "Enumeration of MONITOR/MWAIT extensions is supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "mwait_irq_break",
                    description: "Interrupts as a break-event for MWAIT is supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x5,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "n_c0_substates",
                    description: "Number of C0 sub C-states supported using MWAIT",
                    bits_range: (0, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c1_substates",
                    description: "Number of C1 sub C-states supported using MWAIT",
                    bits_range: (4, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c2_substates",
                    description: "Number of C2 sub C-states supported using MWAIT",
                    bits_range: (8, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c3_substates",
                    description: "Number of C3 sub C-states supported using MWAIT",
                    bits_range: (12, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c4_substates",
                    description: "Number of C4 sub C-states supported using MWAIT",
                    bits_range: (16, 19),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c5_substates",
                    description: "Number of C5 sub C-states supported using MWAIT",
                    bits_range: (20, 23),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c6_substates",
                    description: "Number of C6 sub C-states supported using MWAIT",
                    bits_range: (24, 27),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "n_c7_substates",
                    description: "Number of C7 sub C-states supported using MWAIT",
                    bits_range: (28, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // =========================================================================================
        //                                 Thermal and Power Management
        // =========================================================================================
        (
            Parameters {
                leaf: 0x6,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "dtherm",
                    description: "Digital temperature sensor",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "turbo_boost",
                    description: "Intel Turbo Boost",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "arat",
                    description: "Always-Running APIC Timer (not affected by p-state)",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pln",
                    description: "Power Limit Notification (PLN) event",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ecmd",
                    description: "Clock modulation duty cycle extension",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pts",
                    description: "Package thermal management",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp",
                    description: "HWP (Hardware P-states) base registers are supported",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_notify",
                    description: "HWP notification (IA32_HWP_INTERRUPT MSR)",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_act_window",
                    description: "HWP activity window (IA32_HWP_REQUEST[bits 41:32]) supported",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_epp",
                    description: "HWP Energy Performance Preference",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_pkg_req",
                    description: "HWP Package Level Request",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hdc_base_regs",
                    description: "HDC base registers are supported",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "turbo_boost_3_0",
                    description: "Intel Turbo Boost Max 3.0",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_capabilities",
                    description: "HWP Highest Performance change",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_peci_override",
                    description: "HWP PECI override",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_flexible",
                    description: "Flexible HWP",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_fast",
                    description: "IA32_HWP_REQUEST MSR fast access mode",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hfi",
                    description: "HW_FEEDBACK MSRs supported",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "hwp_ignore_idle",
                    description: "Ignoring idle logical CPU HWP req is supported",
                    bits_range: (20, 20),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "thread_director",
                    description: "Intel thread director support",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "therm_interrupt_bit25",
                    description: "IA32_THERM_INTERRUPT MSR bit 25 is supported",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x6,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "n_therm_thresholds",
                description: "Digital thermometer thresholds",
                bits_range: (0, 3),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x6,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                // MSR related
                ValueDefinition {
                    short: "aperfmperf",
                    description: "MPERF/APERF MSRs (effective frequency interface)",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                // MSR related
                ValueDefinition {
                    short: "epb",
                    description: "IA32_ENERGY_PERF_BIAS MSR support",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "thrd_director_nclasses",
                    description: "Number of classes, Intel thread director",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x6,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "perfcap_reporting",
                    description: "Performance capability reporting",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "encap_reporting",
                    description: "Energy efficiency capability reporting",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "feedback_sz",
                    description: "Feedback interface structure size, in 4K pages",
                    bits_range: (8, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "this_lcpu_hwfdbk_idx",
                    description: "This logical CPU hardware feedback interface index",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                                 Structured Extended Feature Flags Enumeration Main Leaf
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "leaf7_n_subleaves",
                description: "Number of leaf 0x7 subleaves",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "fsgsbase",
                    description: "FSBASE/GSBASE read/write support",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "tsc_adjust",
                    description: "IA32_TSC_ADJUST MSR supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                // SGX is deprecated so we disable it unconditionally for all CPU profiles
                ValueDefinition {
                    short: "sgx",
                    description: "Intel SGX (Software Guard Extensions)",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "bmi1",
                    description: "Bit manipulation extensions group 1",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                // TSX related which is riddled with CVEs. Consider two profiles, or making it opt-in/out. QEMU always has a CPU model with and without TSX.
                ValueDefinition {
                    short: "hle",
                    description: "Hardware Lock Elision",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx2",
                    description: "AVX2 instruction set",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                /*The KVM docs recommend always setting this (https://docs.kernel.org/virt/kvm/x86/errata.html#kvm-get-supported-cpuid-issues).

                Keep in mind however that in my limited understanding this isn't about enabling or disabling a feature, but it describes critical behaviour.
                Hence I am wondering whether it should be a hard error if the host does not have this bit set, but the desired CPU profile does?

                TODO: Check what KVM_GET_SUPPORTED_CPUID actually gives here (on the Skylake server)
                */
                ValueDefinition {
                    short: "fdp_excptn_only",
                    description: "FPU Data Pointer updated only on x87 exceptions",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "smep",
                    description: "Supervisor Mode Execution Protection",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "bmi2",
                    description: "Bit manipulation extensions group 2",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "erms",
                    description: "Enhanced REP MOVSB/STOSB",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Inherit,
                },
                /*
                  The instruction enabled by this seems rather powerful. Are we sure that doesn't have security implications?
                  I included this because it seems like QEMU does (to the best of my understanding).
                */
                ValueDefinition {
                    short: "invpcid",
                    description: "INVPCID instruction (Invalidate Processor Context ID)",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Inherit,
                },
                // This is TSX related. TSX is riddled with CVEs: Consider two profiles (one with it disabled) or an opt-in/out feature.
                ValueDefinition {
                    short: "rtm",
                    description: "Intel restricted transactional memory",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "rdt_m",
                    description: "Supports Intel Resource Director Technology Monitoring Capability if 1",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Static(0),
                },
                // The KVM docs recommend always setting this (https://docs.kernel.org/virt/kvm/x86/errata.html#kvm-get-supported-cpuid-issues). TODO: Is it OK to just set this to 1?
                ValueDefinition {
                    short: "zero_fcs_fds",
                    description: "Deprecates FPU CS and FPU DS values if 1",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Passthrough,
                },
                // This has been deprecated
                ValueDefinition {
                    short: "mpx",
                    description: "Intel memory protection extensions",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Static(0),
                },
                // This might be useful for certain high performance applications, but it also seems like a rather niche and advanced feature. QEMU does also not automatically enable this from what we can tell.
                // TODO: Should we make this OPT-IN?
                ValueDefinition {
                    short: "rdt_a",
                    description: "Intel RDT-A. Supports Intel Resource Director Technology Allocation Capability if 1",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Static(0),
                },
                // TODO: Do the wider avx512 zmm registers work out of the box when the hardware supports it?
                ValueDefinition {
                    short: "avx512f",
                    description: "AVX-512 foundation instructions",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512dq",
                    description: "AVX-512 double/quadword instructions",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "rdseed",
                    description: "RDSEED instruction",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "adx",
                    description: "ADCX/ADOX instructions",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "smap",
                    description: "Supervisor mode access prevention",
                    bits_range: (20, 20),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512ifma",
                    description: "AVX-512 integer fused multiply add",
                    bits_range: (21, 21),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "clflushopt",
                    description: "CLFLUSHOPT instruction",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "clwb",
                    description: "CLWB instruction",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "intel_pt",
                    description: "Intel processor trace",
                    bits_range: (25, 25),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx512pf",
                    description: "AVX-512 prefetch instructions",
                    bits_range: (26, 26),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512er",
                    description: "AVX-512 exponent/reciprocal instructions",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512cd",
                    description: "AVX-512 conflict detection instructions",
                    bits_range: (28, 28),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sha_ni",
                    description: "SHA/SHA256 instructions",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512bw",
                    description: "AVX-512 byte/word instructions",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512vl",
                    description: "AVX-512 VL (128/256 vector length) extensions",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "prefetchwt1",
                    description: "PREFETCHWT1 (Intel Xeon Phi only)",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx512vbmi",
                    description: "AVX-512 Vector byte manipulation instructions",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                // Also set by QEMU for CPU models from what we can tell
                ValueDefinition {
                    short: "umip",
                    description: "User mode instruction protection",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                // Also set by QEMU for CPU models from what we can tell
                ValueDefinition {
                    short: "pku",
                    description: "Protection keys for user-space",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "ospke",
                    description: "OS protection keys enable",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "waitpkg",
                    description: "WAITPKG instructions",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512_vbmi2",
                    description: "AVX-512 vector byte manipulation instructions group 2",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cet_ss",
                    description: "CET shadow stack features",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "gfni",
                    description: "Galois field new instructions",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "vaes",
                    description: "Vector AES instructions",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "vpclmulqdq",
                    description: "VPCLMULQDQ 256-bit instruction support",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512_vnni",
                    description: "Vector neural network instructions",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512_bitalg",
                    description: "AVX-512 bitwise algorithms",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Inherit,
                },
                // Seems to be TDX related which is experimental in CHV. We disable this for CPU profiles for now, but could potentially add it as an opt-in feature eventually.
                ValueDefinition {
                    short: "tme",
                    description: "Intel total memory encryption",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx512_vpopcntdq",
                    description: "AVX-512: POPCNT for vectors of DWORD/QWORD",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "la57",
                    description: "57-bit linear addresses (five-level paging)",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "mawau_val_lm",
                    description: "BNDLDX/BNDSTX MAWAU value in 64-bit mode",
                    bits_range: (17, 21),
                    policy: ProfilePolicy::Static(0),
                },
                // MSR related
                ValueDefinition {
                    short: "rdpid",
                    description: "RDPID instruction",
                    bits_range: (22, 22),
                    policy: ProfilePolicy::Inherit,
                },
                // We leave key locker support out for CPU profiles for the time being. We may want this to be opt-in in the future though
                ValueDefinition {
                    short: "key_locker",
                    description: "Intel key locker support",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "bus_lock_detect",
                    description: "OS bus-lock detection",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cldemote",
                    description: "CLDEMOTE instruction",
                    bits_range: (25, 25),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "movdiri",
                    description: "MOVDIRI instruction",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "movdir64b",
                    description: "MOVDIR64B instruction",
                    bits_range: (28, 28),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "enqcmd",
                    description: "Enqueue stores supported (ENQCMD{,S})",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Static(0),
                },
                // SGX support is deprecated so we disable it unconditionally for CPU profiles
                ValueDefinition {
                    short: "sgx_lc",
                    description: "Intel SGX launch configuration",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pks",
                    description: "Protection keys for supervisor-mode pages",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                // SGX is deprecated
                ValueDefinition {
                    short: "sgx_keys",
                    description: "Intel SGX attestation services",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx512_4vnniw",
                    description: "AVX-512 neural network instructions (Intel Xeon Phi only?)",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512_4fmaps",
                    description: "AVX-512 multiply accumulation single precision (Intel Xeon Phi only?)",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "fsrm",
                    description: "Fast short REP MOV",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "uintr",
                    description: "CPU supports user interrupts",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx512_vp2intersect",
                    description: "VP2INTERSECT{D,Q} instructions",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "srdbs_ctrl",
                    description: "SRBDS mitigation MSR available: If 1, enumerates support for the IA32_MCU_OPT_CTRL MSR and indicates that its bit 0 (RNGDS_MITG_DIS) is also supported.",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "md_clear",
                    description: "VERW MD_CLEAR microcode support",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "rtm_always_abort",
                    description: "XBEGIN (RTM transaction) always aborts",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "tsx_force_abort",
                    description: "MSR TSX_FORCE_ABORT, RTM_ABORT bit, supported",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "serialize",
                    description: "SERIALIZE instruction",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "hybrid_cpu",
                    description: "The CPU is identified as a 'hybrid part'",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Inherit,
                },
                // TODO: This is TSX related which is riddled with CVEs. We could consider an additional profile enabling TSX in the future, but we leave it out for now.
                ValueDefinition {
                    short: "tsxldtrk",
                    description: "TSX suspend/resume load address tracking",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Static(0),
                },
                // Might be relevant for confidential computing
                ValueDefinition {
                    short: "pconfig",
                    description: "PCONFIG instruction",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Static(0),
                },
                // MSR related
                ValueDefinition {
                    short: "arch_lbr",
                    description: "Intel architectural LBRs",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ibt",
                    description: "CET indirect branch tracking",
                    bits_range: (20, 20),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_bf16",
                    description: "AMX-BF16: tile bfloat16 support",
                    bits_range: (22, 22),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512_fp16",
                    description: "AVX-512 FP16 instructions",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_tile",
                    description: "AMX-TILE: tile architecture support",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_int8",
                    description: "AMX-INT8: tile 8-bit integer support",
                    bits_range: (25, 25),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "spec_ctrl",
                    description: "Speculation Control (IBRS/IBPB: indirect branch restrictions)",
                    bits_range: (26, 26),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "intel_stibp",
                    description: "Single thread indirect branch predictors",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Passthrough,
                },
                // MSR related
                ValueDefinition {
                    short: "flush_l1d",
                    description: "FLUSH L1D cache: IA32_FLUSH_CMD MSR",
                    bits_range: (28, 28),
                    policy: ProfilePolicy::Passthrough,
                },
                // MSR related
                ValueDefinition {
                    short: "arch_capabilities",
                    description: "Intel IA32_ARCH_CAPABILITIES MSR",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "core_capabilities",
                    description: "IA32_CORE_CAPABILITIES MSR",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "spec_ctrl_ssbd",
                    description: "Speculative store bypass disable",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // ===================================================================================================================
        //                                 Structured Extended Feature Flags Enumeration Sub-Leaf 1
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "sha512",
                    description: "SHA-512 extensions",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sm3",
                    description: "SM3 instructions",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "sm4",
                    description: "SM4 instructions",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                // RAO-INT is deprecated and removed from most compilers as far as we are aware
                ValueDefinition {
                    short: "RAO-INT",
                    description: "RAO-INT instructions",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx_vnni",
                    description: "AVX-VNNI instructions",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx512_bf16",
                    description: "AVX-512 bfloat16 instructions",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                /*
                  Not set in QEMU from what we can tell, but according seems to be fine to expose this to guests
                  if we understood https://www.phoronix.com/news/Intel-Linux-LASS-KVM correctly. It is also
                  our understanding that this feature can enable guests opting in to more security (possibly at the cost of some performance).
                */
                ValueDefinition {
                    short: "lass",
                    description: "Linear address space separation",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "cmpccxadd",
                    description: "CMPccXADD instructions",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "arch_perfmon_ext",
                    description: "ArchPerfmonExt: leaf 0x23 is supported",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "fzrm",
                    description: "Fast zero-length REP MOVSB",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "fsrs",
                    description: "Fast short REP STOSB",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "fsrc",
                    description: "Fast Short REP CMPSB/SCASB",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "fred",
                    description: "FRED: Flexible return and event delivery transitions",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "lkgs",
                    description: "LKGS: Load 'kernel' (userspace) GS",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "wrmsrns",
                    description: "WRMSRNS instruction (WRMSR-non-serializing)",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "nmi_src",
                    description: "NMI-source reporting with FRED event data",
                    bits_range: (20, 20),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "amx_fp16",
                    description: "AMX-FP16: FP16 tile operations",
                    bits_range: (21, 21),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "hreset",
                    description: "History reset support",
                    bits_range: (22, 22),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "avx_ifma",
                    description: "Integer fused multiply add",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "lam",
                    description: "Linear address masking",
                    bits_range: (26, 26),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "rd_wr_msrlist",
                    description: "RDMSRLIST/WRMSRLIST instructions",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "invd_disable_post_bios_done",
                    description: "If 1, supports INVD execution prevention after BIOS Done",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "movrs",
                    description: "MOVRS",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "intel_ppin",
                    description: "Protected processor inventory number (PPIN{,_CTL} MSRs)",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                // MSR related
                ValueDefinition {
                    short: "pbndkb",
                    description: "PBNDKB instruction supported and enumerates the existence of the IA32_TSE_CAPABILITY MSR",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // TODO: Missing entry for (0x7, 1, ECX)
        // Make the whole register zero though
        //
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "avx_vnni_int8",
                    description: "AVX-VNNI-INT8 instructions",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx_ne_convert",
                    description: "AVX-NE-CONVERT instructions",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                // NOTE: AMX currently requires opt-in, even for the host CPU profile. We still inherit this value for profiles as the value will be zeroed out if the user has not opted in for "amx" via CpuFeatures.
                ValueDefinition {
                    short: "amx_complex",
                    description: "AMX-COMPLEX instructions (starting from Granite Rapids)",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx_vnni_int16",
                    description: "AVX-VNNI-INT16 instructions",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "utmr",
                    description: "If 1, supports user-timer events",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "prefetchit_0_1",
                    description: "PREFETCHIT0/1 instructions",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "user_msr",
                    description: "If 1, supports the URDMSR and UWRMSR instructions",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "uiret_uif",
                    description: "If 1, UIRET sets UIF to the value of bit 1 of the RFLAGS image loaded from the stack",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cet_sss",
                    description: "CET supervisor shadow stacks safe to use",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx10",
                    description: "If 1, supports the Intel AVX10 instructions and indicates the presence of leaf 0x24",
                    bits_range: (19, 19),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "apx_f",
                    description: "If 1, the processor provides foundational support for Intel Advanced Performance Extensions",
                    bits_range: (21, 21),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "mwait",
                    description: "If 1, MWAIT is supported even if (0x1 ECX bit 3 (monitor) is enumerated as 0)",
                    bits_range: (23, 23),
                    policy: ProfilePolicy::Static(0),
                },
                // MSR related
                ValueDefinition {
                    short: "slsm",
                    description: "If 1, indicates bit 0 of the IA32_INTEGRITY_STATUS MSR is supported. Bit 0 of this MSR indicates whether static lockstep is active on this logical processor",
                    bits_range: (24, 24),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                                 Structured Extended Feature Flags Enumeration Sub-Leaf 2
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x7,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                // MSR related
                ValueDefinition {
                    short: "intel_psfd",
                    description: "If 1, indicates bit 7 of the IA32_SPEC_CTRL_MSR is supported. Bit 7 of this MSR disables fast store forwarding predictor without disabling speculative store bypass",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "ipred_ctrl",
                    description: "MSR bits IA32_SPEC_CTRL.IPRED_DIS_{U,S}",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "rrsba_ctrl",
                    description: "MSR bits IA32_SPEC_CTRL.RRSBA_DIS_{U,S}",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "ddp_ctrl",
                    description: "MSR bit  IA32_SPEC_CTRL.DDPD_U",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "bhi_ctrl",
                    description: "MSR bit  IA32_SPEC_CTRL.BHI_DIS_S",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "mcdt_no",
                    description: "MCDT mitigation not needed",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "uclock_disable",
                    description: "UC-lock disable is supported",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // ===================================================================================================================
        //                                 Direct Cache Access Information
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x9,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                // MSR related
                ValueDefinition {
                    short: "dca_cap_msr_value",
                    description: "Value of bits [31:0] of IA32_PLATFORM_DCA_CAP MSR (address 1f8H)",
                    bits_range: (0, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                                 Architectural Performance Monitoring
        // ===================================================================================================================
        // We will just zero out everything to do with PMU for CPU profiles
        (
            Parameters {
                leaf: 0xa,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "pmu_version",
                    description: "Performance monitoring unit version ID",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pmu_n_gcounters",
                    description: "Number of general PMU counters per logical CPU",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pmu_gcounters_nbits",
                    description: "Bitwidth of PMU general counters",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pmu_cpuid_ebx_bits",
                    description: "Length of leaf 0xa EBX bit vector",
                    bits_range: (24, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xa,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "no_core_cycle_evt",
                    description: "Core cycle event not available",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_insn_retired_evt",
                    description: "Instruction retired event not available",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_refcycle_evt",
                    description: "Reference cycles event not available",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_llc_ref_evt",
                    description: "LLC-reference event not available",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_llc_miss_evt",
                    description: "LLC-misses event not available",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_br_insn_ret_evt",
                    description: "Branch instruction retired event not available",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_br_mispredict_evt",
                    description: "Branch mispredict retired event not available",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "no_td_slots_evt",
                    description: "Topdown slots event not available",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xa,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pmu_fcounters_bitmap",
                description: "Fixed-function PMU counters support bitmap",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xa,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "pmu_n_fcounters",
                    description: "Number of fixed PMU counters",
                    bits_range: (0, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "pmu_fcounters_nbits",
                    description: "Bitwidth of PMU fixed counters",
                    bits_range: (5, 12),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "anythread_depr",
                    description: "AnyThread deprecation",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                                   Extended Topology Enumeration
        // ===================================================================================================================

        // Leaf 0xB must be set by CHV itself (and do all necessary checks)
        (
            Parameters {
                leaf: 0xb,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "x2apic_id_shift",
                description: "Bit width of this level (previous levels inclusive)",
                bits_range: (0, 4),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        // Set by VMM/user provided config
        (
            Parameters {
                leaf: 0xb,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "domain_lcpus_count",
                description: "Logical CPUs count across all instances of this domain",
                bits_range: (0, 15),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        // Set by VMM/user provided config
        (
            Parameters {
                leaf: 0xb,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "domain_nr",
                    description: "This domain level (subleaf ID)",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "domain_type",
                    description: "This domain type",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        // Set by VMM/user provided config
        (
            Parameters {
                leaf: 0xb,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "x2apic_id",
                description: "x2APIC ID of current logical CPU",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        // ===================================================================================================================
        //                                    Processor Extended State Enumeration Main Leaf
        // ===================================================================================================================
        // TODO: Implement CPUID compatibility checks in CHV for this leaf
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "xcr0_x87",
                    description: "XCR0.X87 (bit 0) supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_sse",
                    description: "XCR0.SEE (bit 1) supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_avx",
                    description: "XCR0.AVX (bit 2) supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                // MPX is deprecated
                ValueDefinition {
                    short: "xcr0_mpx_bndregs",
                    description: "XCR0.BNDREGS (bit 3) supported (MPX BND0-BND3 registers)",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                // MPX is deprecated
                ValueDefinition {
                    short: "xcr0_mpx_bndcsr",
                    description: "XCR0.BNDCSR (bit 4) supported (MPX BNDCFGU/BNDSTATUS registers)",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "xcr0_avx512_opmask",
                    description: "XCR0.OPMASK (bit 5) supported (AVX-512 k0-k7 registers)",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_avx512_zmm_hi256",
                    description: "XCR0.ZMM_Hi256 (bit 6) supported (AVX-512 ZMM0->ZMM7/15 registers)",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_avx512_hi16_zmm",
                    description: "XCR0.HI16_ZMM (bit 7) supported (AVX-512 ZMM16->ZMM31 registers)",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Inherit,
                },
                // MSR related
                ValueDefinition {
                    short: "xcr0_ia32_xss",
                    description: "XCR0.IA32_XSS (bit 8) used for IA32_XSS",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_pkru",
                    description: "XCR0.PKRU (bit 9) supported (XSAVE PKRU registers)",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_ia32_xss_bits",
                    description: "XCR0.IA32_XSS (bit 10 - 16) used for IA32_XSS",
                    bits_range: (10, 16),
                    policy: ProfilePolicy::Inherit,
                },
                // NOTE: AMX currently requires opt-in, even for the host CPU profile. We still inherit this value for profiles and modify this value at runtime if AMX is not enabled by the user.
                ValueDefinition {
                    short: "xcr0_tileconfig",
                    description: "XCR0.TILECONFIG (bit 17) supported (AMX can manage TILECONFIG)",
                    bits_range: (17, 17),
                    policy: ProfilePolicy::Inherit,
                },
                // NOTE: AMX currently requires opt-in, even for the host CPU profile. We still inherit this value for profiles and modify this value at runtime if AMX is not ebabled by the user.
                ValueDefinition {
                    short: "xcr0_tiledata",
                    description: "XCR0.TILEDATA (bit 18) supported (AMX can manage TILEDATA)",
                    bits_range: (18, 18),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            // This value can be changed by the OS and must thus be passthrough
            ValueDefinitions::new(&[ValueDefinition {
                short: "xsave_sz_xcr0_enabled",
                description: "XSAVE/XRSTOR area byte size, for XCR0 enabled features",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            // This may be passthrough because we restrict each individual state component
            ValueDefinitions::new(&[ValueDefinition {
                short: "xsave_sz_max",
                description: "XSAVE/XRSTOR area max byte size, all CPU features",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            // TODO: Do we know of any state components corresponding to the upper bits in XCR0? Perhaps it would be
            // better to have `ProfilePolicy::Static(0)` here?
            ValueDefinitions::new(&[ValueDefinition {
                short: "xcr0_upper_bits",
                description: "Reports the valid bit fields of the upper 32 bits of the XCR0 register",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        // ===================================================================================================================
        //                                    Processor Extended State Enumeration Sub-leaf 1
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "xsaveopt",
                    description: "XSAVEOPT instruction",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xsavec",
                    description: "XSAVEC instruction",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xgetbv1",
                    description: "XGETBV instruction with ECX = 1",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                // TODO: Can this have security implications in terms of supervisor state getting exposed?
                ValueDefinition {
                    short: "xsaves",
                    description: "XSAVES/XRSTORS instructions (and XSS MSR)",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xfd",
                    description: "Extended feature disable support",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                /*NOTE: This will depend on which CPU features (in CHV) are enabled and pre-computation can potentially lead to a combinatorial explosion. Luckily we can deal with each component (and its size) separately, hence we can just passthrough whatever we get from the host here.*/
                ValueDefinition {
                    short: "xsave_sz_xcr0_xmms_enabled",
                    description: "XSAVE area size, all XCR0 and IA32_XSS features enabled",
                    bits_range: (0, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::ECX,
            },
            /* Reports the supported bits of the lower IA32_XSS MSR. IA32_XSS[n] can be set to 1 only if ECX[n] = 1*/
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "xcr0_7bits",
                    description: "Used for XCR0",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_pt",
                    description: "PT state, supported",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_bit9",
                    description: "Used for XCR0",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_pasid",
                    description: "PASID state, supported",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_cet_u",
                    description: "CET user state, supported",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_cet_p",
                    description: "CET supervisor state, supported",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_hdc",
                    description: "HDC state, supported",
                    bits_range: (13, 13),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_uintr",
                    description: "UINTR state, supported",
                    bits_range: (14, 14),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_lbr",
                    description: "LBR state, supported",
                    bits_range: (15, 15),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xss_hwp",
                    description: "HWP state, supported",
                    bits_range: (16, 16),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xcr0_bits",
                    description: "Used for XCR0",
                    bits_range: (17, 18),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EDX,
            },
            /* Reports the supported bits of the upper 32 bits of the IA32_XSS MSR. IA32_XSS[n + 32 ] can be set to 1 only if EDX[n] = 1*/
            ValueDefinitions::new(&[ValueDefinition {
                short: "ia32_xss_upper",
                description: " Reports the supported bits of the upper 32 bits of the IA32_XSS MSR. IA32_XSS[n + 32 ] can be set to 1 only if EDX[n] = 1",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        // ===================================================================================================================
        //                                    Processor Extended State Enumeration Sub-leaves
        // ===================================================================================================================

        /* LEAF 0xd sub-leaf n >=2 :
         If ECX contains an invalid sub-leaf index, EAX/EBX/ECX/EDX return 0. Sub-leaf n (0 ≤ n ≤ 31) is
        invalid if sub-leaf 0 returns 0 in EAX[n] and sub-leaf 1 returns 0 in ECX[n]. Sub-leaf n (32 ≤ n ≤ 63)
        is invalid if sub-leaf 0 returns 0 in EDX[n-32] and sub-leaf 1 returns 0 in EDX[n-32].
        */
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "xsave_sz",
                description: "Size of save area for subleaf-N feature, in bytes",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "xsave_offset",
                description: "Offset of save area for subleaf-N feature, in bytes",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "is_xss_bit",
                    description: "Subleaf N describes an XSS bit, otherwise XCR0 bit",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "compacted_xsave_64byte_aligned",
                    description: "When compacted, subleaf-N feature XSAVE area is 64-byte aligned",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xfd_faulting",
                    description: "Indicates support for xfd faulting",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // Intel MPX is deprecated hence we zero out these sub-leaves
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(3, 4),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "0xd-3-4-eax-mpx-zero",
                description: "This leaf has been zeroed out because MPX state components are disabled",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(3, 4),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "0xd-3-4-ebx-mpx-zero",
                description: "This leaf has been zeroed out because MPX state components are disabled",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(3, 4),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "0xd-3-4-ecx-mpx-zero",
                description: "This leaf has been zeroed out because MPX state components are disabled",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(3, 4),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "0xd-3-4-edx-mpx-zero",
                description: "This leaf has been zeroed out because MPX state components are disabled",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // NOTE: Sub-leaves 17 & 18 are AMX related and we will alter the adjustments corresponding to
        // the policy declared here at runtime for those values.
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(5, 63),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "xsave_sz",
                description: "Size of save area for subleaf-N feature, in bytes",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(5, 63),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "xsave_offset",
                description: "Offset of save area for subleaf-N feature, in bytes",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0xd,
                sub_leaf: RangeInclusive::new(5, 63),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "is_xss_bit",
                    description: "Subleaf N describes an XSS bit, otherwise XCR0 bit",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "compacted_xsave_64byte_aligned",
                    description: "When compacted, subleaf-N feature XSAVE area is 64-byte aligned",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "xfd_faulting",
                    description: "Indicates support for xfd faulting",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // ===================================================================================================================
        //                                Intel Resource Director Technology Monitoring Enumeration
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0xf,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "core_rmid_max",
                description: "RMID max, within this core, all types (0-based)",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xf,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "l3-cache-rdt-monitoring",
                description: "Supports L3 Cache Intel RDT Monitoring if 1",
                bits_range: (1, 1),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                                Intel Resource Director Technology Monitoring Enumeration Sub-leaf 1
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0xf,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "l3c_qm_bitwidth",
                    description: "L3 QoS-monitoring counter bitwidth (24-based)",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "l3c_qm_overflow_bit",
                    description: "QM_CTR MSR bit 61 is an overflow bit",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "l3c_qm_non_cpu_agent",
                    description: "If 1, indicates the presence of non-CPU agent Intel RDT CTM support",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "l3c_qm_non_cpu_agent",
                    description: "If 1, indicates the presence of non-CPU agent Intel RDT MBM support",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0xf,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "l3c_qm_conver_factor",
                description: "QM_CTR MSR conversion factor to bytes",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xf,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "l3c_qm_rmid_max",
                description: "L3 QoS-monitoring max RMID",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0xf,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cqm_occup_llc",
                    description: "L3 QoS occupancy monitoring supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cqm_mbm_total",
                    description: "L3 QoS total bandwidth monitoring supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cqm_mbm_local",
                    description: "L3 QoS local bandwidth monitoring supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                                Intel Resource Director Technology Allocation Enumeration
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            //TODO: These features may be good for increased performance. Perhaps there needs to be some mechanism to opt-in for non-host CPU profiles?
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cat_l3",
                    description: "L3 Cache Allocation Technology supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cat_l2",
                    description: "L2 Cache Allocation Technology supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "mba",
                    description: "Memory Bandwidth Allocation supported",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                      Intel Resource Director Technology Allocation Enumeration Sub-leaf (ECX = ResID = 1)
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cat_cbm_len",
                description: "L3_CAT capacity bitmask length, minus-one notation",
                bits_range: (0, 4),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cat_units_bitmap",
                description: "L3_CAT bitmap of allocation units",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::ECX,
            },
            //TODO: These feature may be good for increased performance. Perhaps there needs to be some mechanism to opt-in for non-host CPU profiles?
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "l3_cat_non_cpu_agents",
                    description: "L3_CAT for non-CPU agent is supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cdp_l3",
                    description: "L3/L2_CAT CDP (Code and Data Prioritization)",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cat_sparse_1s",
                    description: "L3/L2_CAT non-contiguous 1s value supported",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EDX,
            },
            // TODO: We might need some way to opt in to use Intel cache allocation technology in guests with non-host CPU profiles.
            ValueDefinitions::new(&[ValueDefinition {
                short: "cat_cos_max",
                description: "Highest COS number supported for this ResID",
                bits_range: (0, 15),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                      Intel Resource Director Technology Allocation Enumeration Sub-leaf (ECX = ResID = 2)
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cat_cbm_len",
                description: "L2_CAT capacity bitmask length, minus-one notation",
                bits_range: (0, 4),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cat_units_bitmap",
                description: "L2_CAT bitmap of allocation units",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cat_cos_max",
                description: "Highest COS number supported for this ResID",
                bits_range: (0, 15),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::ECX,
            },
            // TODO: We might need some way to opt in to use Intel cache allocation technology in guests with non-host CPU profiles.
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cdp_l2",
                    description: "L2_CAT CDP (Code and Data Prioritization)",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cat_sparse_1s",
                    description: "L2_CAT non-contiguous 1s value supported",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                      Intel Resource Director Technology Allocation Enumeration Sub-leaf (ECX = ResID = 3)
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(3, 3),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                // TODO: We might need some way to opt in to use Intel MBA technology in guests with non-host CPU profiles.
                ValueDefinition {
                    short: "mba_max_delay",
                    description: "Max MBA throttling value; minus-one notation",
                    bits_range: (0, 11),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(3, 3),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "per_thread_mba",
                    description: "Per-thread MBA controls are supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "mba_delay_linear",
                    description: "Delay values are linear",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(3, 3),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "mba_cos_max",
                description: "MBA max Class of Service supported",
                bits_range: (0, 15),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                      Intel Resource Director Technology Allocation Enumeration Sub-leaf (ECX = ResID = 5)
        // ===================================================================================================================
        //
        // TODO: We may want to have some way to opt-in to use Intel RDT for guests with non-host CPU profiles.
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "core_max_throttle",
                    description: "Max Core throttling level supported by the corresponding ResID",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "core_scope",
                    description: "If 1, indicates the logical processor scope of the IA32_QoS_Core_BW_Thrtl_n MSRs. Other values are reserved",
                    bits_range: (8, 11),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cba_delay_linear",
                description: "The response of the bandwidth control is approximately linear",
                bits_range: (3, 3),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x10,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "core_cos_max",
                description: "Core max Class of Service supported",
                bits_range: (0, 15),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // SGX is already disabled and deprecated so we don't need to worry about leaf 0x12 and its subleaves

        // ===================================================================================================================
        //                      Intel Processor Trace Enumeration Main Leaf
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x14,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pt_max_subleaf",
                description: "Maximum leaf 0x14 subleaf",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x14,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cr3_filtering",
                    description: "IA32_RTIT_CR3_MATCH is accessible",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "psb_cyc",
                    description: "Configurable PSB and cycle-accurate mode",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ip_filtering",
                    description: "IP/TraceStop filtering; Warm-reset PT MSRs preservation",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "mtc_timing",
                    description: "MTC timing packet; COFI-based packets suppression",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ptwrite",
                    description: "PTWRITE support",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "power_event_trace",
                    description: "Power Event Trace support",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "psb_pmi_preserve",
                    description: "PSB and PMI preservation support",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "event_trace",
                    description: "Event Trace packet generation through IA32_RTIT_CTL.EventEn",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "tnt_disable",
                    description: "TNT packet generation disable through IA32_RTIT_CTL.DisTNT",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x14,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "topa_output",
                    description: "ToPA output scheme support",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "topa_multiple_entries",
                    description: "ToPA tables can hold multiple entries",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "single_range_output",
                    description: "Single-range output scheme supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "trance_transport_output",
                    description: "Trace Transport subsystem output support",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ip_payloads_lip",
                    description: "IP payloads have LIP values (CS base included)",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                      Intel Processor Trace Enumeration Sub-leaf 1
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x14,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "num_address_ranges",
                    description: "Filtering number of configurable Address Ranges",
                    bits_range: (0, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "mtc_periods_bmp",
                    description: "Bitmap of supported MTC period encodings",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x14,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "cycle_thresholds_bmp",
                    description: "Bitmap of supported Cycle Threshold encodings",
                    bits_range: (0, 15),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "psb_periods_bmp",
                    description: "Bitmap of supported Configurable PSB frequency encodings",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                      Time Stamp Counter and Core Crystal Clock Information
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x15,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tsc_denominator",
                description: "Denominator of the TSC/'core crystal clock' ratio",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x15,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tsc_numerator",
                description: "Numerator of the TSC/'core crystal clock' ratio",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x15,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_crystal_hz",
                description: "Core crystal clock nominal frequency, in Hz",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        // ===================================================================================================================
        //                                     Processor Frequency Information
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x16,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_base_mhz",
                description: "Processor base frequency, in MHz",
                bits_range: (0, 15),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x16,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_max_mhz",
                description: "Processor max frequency, in MHz",
                bits_range: (0, 15),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x16,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "bus_mhz",
                description: "Bus reference frequency, in MHz",
                bits_range: (0, 15),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        // ===================================================================================================================
        //                     System-On-Chip Vendor Attribute Enumeration Main Leaf
        // ===================================================================================================================

        // System-On-Chip should probably not be supported for CPU profiles for the foreseeable feature.
        (
            Parameters {
                leaf: 0x17,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "soc_max_subleaf",
                description: "Maximum leaf 0x17 subleaf",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                      Deterministic Address Translation Parameters
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x18,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tlb_max_subleaf",
                description: "Maximum leaf 0x18 subleaf",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x18,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "tlb_4k_page",
                    description: "TLB 4KB-page entries supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "tlb_2m_page",
                    description: "TLB 2MB-page entries supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "tlb_4m_page",
                    description: "TLB 4MB-page entries supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "tlb_1g_page",
                    description: "TLB 1GB-page entries supported",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "hard_partitioning",
                    description: "(Hard/Soft) partitioning between logical CPUs sharing this structure",
                    bits_range: (8, 10),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "n_way_associative",
                    description: "Ways of associativity",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x18,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "n_sets",
                description: "Number of sets",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x18,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "tlb_type",
                    description: "Translation cache type (TLB type)",
                    bits_range: (0, 4),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "tlb_cache_level",
                    description: "Translation cache level (1-based)",
                    bits_range: (5, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "is_fully_associative",
                    description: "Fully-associative structure",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "tlb_max_addressable_ids",
                    description: "Max number of addressable IDs for logical CPUs sharing this TLB - 1",
                    bits_range: (14, 25),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        // We don't support key locker for now (leaf 0x19): Hence we zero out leaf 0x19 for CPU profiles We zero LEAF
        // 0x1A (Native Model ID Enumeration) out for CPU profiles LEAF 0x1B (PCONFIG) is zeroed out for CPU profiles
        // for now

        // ===================================================================================================================
        //                                     Last Branch Records Information
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x1c,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "lbr_depth_8",
                    description: "Max stack depth (number of LBR entries) = 8",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_16",
                    description: "Max stack depth (number of LBR entries) = 16",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_24",
                    description: "Max stack depth (number of LBR entries) = 24",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_32",
                    description: "Max stack depth (number of LBR entries) = 32",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_40",
                    description: "Max stack depth (number of LBR entries) = 40",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_48",
                    description: "Max stack depth (number of LBR entries) = 48",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_56",
                    description: "Max stack depth (number of LBR entries) = 56",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_depth_64",
                    description: "Max stack depth (number of LBR entries) = 64",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_deep_c_reset",
                    description: "LBRs maybe cleared on MWAIT C-state > C1",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_ip_is_lip",
                    description: "LBR IP contain Last IP, otherwise effective IP",
                    bits_range: (31, 31),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1c,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "lbr_cpl",
                    description: "CPL filtering (non-zero IA32_LBR_CTL[2:1]) supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_branch_filter",
                    description: "Branch filtering (non-zero IA32_LBR_CTL[22:16]) supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_call_stack",
                    description: "Call-stack mode (IA32_LBR_CTL[3] = 1) supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1c,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "lbr_mispredict",
                    description: "Branch misprediction bit supported (IA32_LBR_x_INFO[63])",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_timed_lbr",
                    description: "Timed LBRs (CPU cycles since last LBR entry) supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_branch_type",
                    description: "Branch type field (IA32_LBR_INFO_x[59:56]) supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_events_gpc_bmp",
                    description: "LBR PMU-events logging support; bitmap for first 4 GP (general-purpose) Counters",
                    bits_range: (16, 19),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                      Tile Information Main Leaf
        // ===================================================================================================================
        // NOTE: AMX is opt-in, but there are no problems with inheriting these values. The CHV will take care of zeroing out the bits userspace applications should check for if the user did not opt-in to amx.
        (
            Parameters {
                leaf: 0x1d,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "amx_max_palette",
                description: "Highest palette ID / subleaf ID",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        // ===================================================================================================================
        //                      Tile Palette 1 Sub-leaf
        // ===================================================================================================================
        // NOTE: AMX is opt-in, but there are no problems with inheriting these values. The CHV will take care of zeroing out the bits userspace applications should check for if the user did not opt-in to amx.
        (
            Parameters {
                leaf: 0x1d,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "amx_palette_size",
                    description: "AMX palette total tiles size, in bytes",
                    bits_range: (0, 15),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_tile_size",
                    description: "AMX single tile's size, in bytes",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1d,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "amx_tile_row_size",
                    description: "AMX tile single row's size, in bytes",
                    bits_range: (0, 15),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_palette_nr_tiles",
                    description: "AMX palette number of tiles",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1d,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "amx_tile_nr_rows",
                description: "AMX tile max number of rows",
                bits_range: (0, 15),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        // ===================================================================================================================
        //                      TMUL Information Main Leaf
        // ===================================================================================================================
        // NOTE: AMX is opt-in, but there are no problems with inheriting these values. The CHV will take care of zeroing out the bits userspace applications should check for if the user did not opt-in to amx.
        (
            Parameters {
                leaf: 0x1e,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tmul_info_max",
                description: "Reports the maximum number of sub-leaves that are supported in leaf 0x1e",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x1e,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "tmul_maxk",
                    description: "TMUL unit maximum height, K (rows or columns)",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "tmul_maxn",
                    description: "TMUL unit maximum SIMD dimension, N (column bytes)",
                    bits_range: (8, 23),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // ===================================================================================================================
        //                            TMUL Information Sub-leaf 1
        // ===================================================================================================================
        // NOTE: AMX is opt-in, but there are no problems with inheriting these values. The CHV will take care of zeroing out the bits userspace applications should check for if the user did not opt-in to amx.
        (
            Parameters {
                leaf: 0x1e,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            // NOTE: AMX currently requires opt-in, even for the host CPU profile. We still inherit this value for profiles as the relevant feature bits that userspace applications must check will be zeroed out if the user has not opted in for "amx" via CpuFeatures.
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "amx_int8",
                    description: "If 1, the processor supports tile computational operations on 8-bit integers",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_bf16",
                    description: "If 1, the processor supports tile computational operations on bfloat16 numbers",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_complex",
                    description: "If 1, the processor supports the AMX-COMPLEX instructions",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_fp16",
                    description: "If 1, the processor supports tile computational operations on FP16 numbers",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_fp8",
                    description: "If 1, the processor supports tile computational operations on FP8 numbers",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_transpose",
                    description: "If 1, the processor supports the AMX-TRANSPOSE instructions",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_tf32",
                    description: "If 1, the processor supports the AMX-TF32 (FP19) instructions",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_avx512",
                    description: "If 1, the processor supports the AMX-AVX512 instructions",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "amx_movrs",
                    description: "If 1, the processor supports the AMX-MOVRS instructions",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // ===================================================================================================================
        //                               V2 Extended Topology Enumeration
        // ===================================================================================================================

        // The values in leaf 0x1f must be set by CHV itself.
        (
            Parameters {
                leaf: 0x1f,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "x2apic_id_shift",
                description: "Bit width of this level (previous levels inclusive)",
                bits_range: (0, 4),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x1f,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "domain_lcpus_count",
                description: "Logical CPUs count across all instances of this domain",
                bits_range: (0, 15),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x1f,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "domain_level",
                    description: "This domain level (subleaf ID)",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "domain_type",
                    description: "This domain type",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x1f,
                sub_leaf: RangeInclusive::new(0, u32::MAX),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "x2apic_id",
                description: "x2APIC ID of current logical CPU",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        // ===================================================================================================================
        //                               Processor History Reset
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x20,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "hreset_nr_subleaves",
                description: "CPUID 0x20 max subleaf + 1",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x20,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "hreset_thread_director",
                description: "HRESET of Intel thread director is supported",
                bits_range: (0, 0),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                               TDX
        // ===================================================================================================================

        // TDX is not supported by CPU profiles for now. We just zero out this leaf for CPU profiles for the time being.
        (
            Parameters {
                leaf: 0x21,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tdx_vendorid_0",
                description: "TDX vendor ID string bytes 0 - 3",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x21,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tdx_vendorid_2",
                description: "CPU vendor ID string bytes 8 - 11",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x21,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "tdx_vendorid_1",
                description: "CPU vendor ID string bytes 4 - 7",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                               Architectural Performance Monitoring Extended Main Leaf
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "subleaf_0",
                    description: "If 1, subleaf 0 exists",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "subleaf_1",
                    description: "If 1, subleaf 1 exists",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "subleaf_2",
                    description: "If 1, subleaf 2 exists",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "subleaf_3",
                    description: "If 1, subleaf 3 exists",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "subleaf_4",
                    description: "If 1, subleaf 4 exists",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "subleaf_5",
                    description: "If 1, subleaf 5 exists. The processor suppots Architectural PEBS. The IA32_PEBS_BASE and IA32_PEBS_INDEX MSRs exist",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "unitmask2",
                    description: "IA32_PERFEVTSELx MSRs UnitMask2 is supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "eq_bit",
                    description: "equal flag in the IA32_PERFEVTSELx MSR is supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "RDPMC_USR_DISABLE",
                    description: "RDPMC_USR_DISABLE",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "num_slots_per_cycle",
                description: "Number of slots per cycle. This number can be multiplied by the number of cycles (from CPU_CLK_UNHALTED.THREAD / CPU_CLK_UNHALTED.CORE or IA32_FIXED_CTR1) to determine the total number of slots",
                bits_range: (0, 7),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                               Architectural Performance Monitoring Extended Sub-leaf 1
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pmu_gp_counters_bitmap",
                description: "General-purpose PMU counters bitmap",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(1, 1),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pmu_f_counters_bitmap",
                description: "Fixed PMU counters bitmap",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                               Architectural Performance Monitoring Extended Sub-leaf 2
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(2, 2),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pmu_acr_bitmap",
                description: "Bitmap of Auto Counter Reload (ACR) general-purpose counters that can be reloaded",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                               Architectural Performance Monitoring Extended Sub-leaf 3
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(3, 3),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "core_cycles_evt",
                    description: "Core cycles event supported",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "insn_retired_evt",
                    description: "Instructions retired event supported",
                    bits_range: (1, 1),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "ref_cycles_evt",
                    description: "Reference cycles event supported",
                    bits_range: (2, 2),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "llc_refs_evt",
                    description: "Last-level cache references event supported",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "llc_misses_evt",
                    description: "Last-level cache misses event supported",
                    bits_range: (4, 4),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "br_insn_ret_evt",
                    description: "Branch instruction retired event supported",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "br_mispr_evt",
                    description: "Branch mispredict retired event supported",
                    bits_range: (6, 6),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "td_slots_evt",
                    description: "Topdown slots event supported",
                    bits_range: (7, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "td_backend_bound_evt",
                    description: "Topdown backend bound event supported",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "td_bad_spec_evt",
                    description: "Topdown bad speculation event supported",
                    bits_range: (9, 9),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "td_frontend_bound_evt",
                    description: "Topdown frontend bound event supported",
                    bits_range: (10, 10),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "td_retiring_evt",
                    description: "Topdown retiring event support",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr_inserts",
                    description: "LBR support",
                    bits_range: (12, 12),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                               Architectural Performance Monitoring Extended Sub-leaf 4
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(4, 4),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "allow_in_record",
                    description: "If 1, indicates that the ALLOW_IN_RECORD bit is available in the IA32_PMC_GPn_CFG_C and IA32_PMC_FXm_CFG_C MSRs",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cntr",
                    description: "Counters group sub-groups general-purpose counters, fixed-function counters, and performance metrics are available",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr",
                    description: "LBR group and both bits [41:40] are available",
                    bits_range: (8, 9),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "xer",
                    description: "These bits correspond to XER group bits [55:49]",
                    bits_range: (17, 23),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "grp",
                    description: "If 1, the GRP group is available",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "aux",
                    description: "If 1, the AUX group is available",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(4, 4),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "allow_in_record",
                    description: "If 1, indicates that the ALLOW_IN_RECORD bit is available in the IA32_PMC_GPn_CFG_C and IA32_PMC_FXm_CFG_C MSRs",
                    bits_range: (3, 3),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "cntr",
                    description: "Counters group sub-groups general-purpose counters, fixed-function counters, and performance metrics are available",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "lbr",
                    description: "LBR group and both bits [41:40] are available",
                    bits_range: (8, 9),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "xer",
                    description: "These bits correspond to XER group bits [55:49]",
                    bits_range: (17, 23),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "grp",
                    description: "If 1, the GRP group is available",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Static(0),
                },
                ValueDefinition {
                    short: "aux",
                    description: "If 1, the AUX group is available",
                    bits_range: (30, 30),
                    policy: ProfilePolicy::Static(0),
                },
            ]),
        ),
        // ===================================================================================================================
        //                               Architectural Performance Monitoring Extended Sub-leaf 5
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "architectural_pebs_counters",
                description: "General-purpose counters support Architectural PEBS. Bit vector of general-purpose counters for which the Architectural PEBS mechanism is available",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pebs_pdist_counters",
                description: "General-purpose counters for which PEBS support PDIST",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pebs_fixed_function_counters",
                description: "Fixed-function counters support Architectural PEBS. Bit vector of fixed-function counters for which the Architectural PEBS mechanism is available. If ECX[x] == 1, then the IA32_PMC_FXm_CFG_C MSR is available, and PEBS is supported",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        (
            Parameters {
                leaf: 0x23,
                sub_leaf: RangeInclusive::new(5, 5),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "pebs_fixed_function_pdist_counters",
                description: "Fixed-function counters for which PEBS supports PDIST",
                bits_range: (0, 31),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
        // ===================================================================================================================
        //                              Converged Vector ISA Main Leaf
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x24,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "converged_vector_isa_max_sub_leaves",
                description: "Reports the maximum number of sub-leaves that are supported in leaf 0x24",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x24,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "avx_10_version",
                    description: "Reports the intel AVX10 Converged Vector ISA version",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "avx_10_lengths",
                    description: "Reserved at 111",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // Hypervisor reserved CPUID leaves are set elsewhere

        // ===================================================================================================================
        //                              Extended Function CPUID Information
        // ===================================================================================================================
        (
            Parameters {
                leaf: 0x80000000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "max_ext_leaf",
                description: "Maximum extended CPUID leaf supported",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_vendorid_0",
                description: "Vendor ID string bytes 0 - 3",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_vendorid_2",
                description: "Vendor ID string bytes 8 - 11",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000000,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_vendorid_1",
                description: "Vendor ID string bytes 4 - 7",
                bits_range: (0, 31),
                policy: ProfilePolicy::Passthrough,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000001,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            // TODO: Would inherit be better than passthrough? Currently CHV manually copies these over from the host ...
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "e_stepping_id",
                    description: "Stepping ID",
                    bits_range: (0, 3),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "e_base_model",
                    description: "Base processor model",
                    bits_range: (4, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "e_base_family",
                    description: "Base processor family",
                    bits_range: (8, 11),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "e_base_type",
                    description: "Base processor type (Transmeta)",
                    bits_range: (12, 13),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "e_ext_model",
                    description: "Extended processor model",
                    bits_range: (16, 19),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "e_ext_family",
                    description: "Extended processor family",
                    bits_range: (20, 27),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x80000001,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "brand_id",
                    description: "Brand ID",
                    bits_range: (0, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "pkg_type",
                    description: "Package type",
                    bits_range: (28, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x80000001,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "lahf_lm",
                    description: "LAHF and SAHF in 64-bit mode",
                    bits_range: (0, 0),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "lzcnt",
                    description: "LZCNT advanced bit manipulation",
                    bits_range: (5, 5),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "prefetchw",
                    description: "3DNow PREFETCH/PREFETCHW support",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x80000001,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "syscall",
                    description: "SYSCALL and SYSRET instructions",
                    bits_range: (11, 11),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "nx",
                    description: "Execute Disable Bit available",
                    bits_range: (20, 20),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "pdpe1gb",
                    description: "1-GB large page support",
                    bits_range: (26, 26),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "rdtscp",
                    description: "RDTSCP instruction and IA32_TSC_AUX are available",
                    bits_range: (27, 27),
                    policy: ProfilePolicy::Inherit,
                },
                ValueDefinition {
                    short: "lm",
                    description: "Long mode (x86-64, 64-bit support)",
                    bits_range: (29, 29),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        // The profile generation tool will actually modify the brand id string before
        // acting on the policy set here.
        (
            Parameters {
                leaf: 0x80000002,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_0",
                description: "CPU brand ID string, bytes 0 - 3",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000002,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_1",
                description: "CPU brand ID string, bytes 4 - 7",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000002,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_2",
                description: "CPU brand ID string, bytes 8 - 11",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000002,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_3",
                description: "CPU brand ID string, bytes 12 - 15",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000003,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_4",
                description: "CPU brand ID string bytes, 16 - 19",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000003,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_5",
                description: "CPU brand ID string bytes, 20 - 23",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000003,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_6",
                description: "CPU brand ID string bytes, 24 - 27",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000003,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_7",
                description: "CPU brand ID string bytes, 28 - 31",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000004,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_8",
                description: "CPU brand ID string, bytes 32 - 35",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000004,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_9",
                description: "CPU brand ID string, bytes 36 - 39",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000004,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_10",
                description: "CPU brand ID string, bytes 40 - 43",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000004,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "cpu_brandid_11",
                description: "CPU brand ID string, bytes 44 - 47",
                bits_range: (0, 31),
                policy: ProfilePolicy::Inherit,
            }]),
        ),
        (
            Parameters {
                leaf: 0x80000006,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::ECX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "l2_line_size",
                    description: "L2 cache line size, in bytes",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "l2_nlines",
                    description: "L2 cache number of lines per tag",
                    bits_range: (8, 11),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "l2_assoc",
                    description: "L2 cache associativity",
                    bits_range: (12, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "l2_size_kb",
                    description: "L2 cache size, in KB",
                    bits_range: (16, 31),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        // EAX, EBX and ECX of 0x8000_0007 are all reserved (=0) on Intel
        (
            Parameters {
                leaf: 0x80000007,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EDX,
            },
            ValueDefinitions::new(&[
                // TODO: We may want some mechanism to let users opt-in to using an invariant TSC provided by the hardware (when available).
                // TODO: Probably unconditionally set by CHV
                ValueDefinition {
                    short: "constant_tsc",
                    description: "TSC ticks at constant rate across all P and C states",
                    bits_range: (8, 8),
                    policy: ProfilePolicy::Inherit,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x80000008,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EAX,
            },
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "phys_addr_bits",
                    description: "Max physical address bits",
                    bits_range: (0, 7),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "virt_addr_bits",
                    description: "Max virtual address bits",
                    bits_range: (8, 15),
                    policy: ProfilePolicy::Passthrough,
                },
                ValueDefinition {
                    short: "guest_phys_addr_bits",
                    description: "Max nested-paging guest physical address bits",
                    bits_range: (16, 23),
                    policy: ProfilePolicy::Passthrough,
                },
            ]),
        ),
        (
            Parameters {
                leaf: 0x80000008,
                sub_leaf: RangeInclusive::new(0, 0),
                register: CpuidReg::EBX,
            },
            ValueDefinitions::new(&[ValueDefinition {
                short: "wbnoinvd",
                description: "WBNOINVD supported",
                bits_range: (9, 9),
                policy: ProfilePolicy::Static(0),
            }]),
        ),
    ])
};
