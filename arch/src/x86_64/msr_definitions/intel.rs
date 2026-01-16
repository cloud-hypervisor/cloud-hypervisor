use crate::x86_64::msr_definitions::{
    MsrDefinitions, ProfilePolicy, RegisterAddress, ValueDefinition, ValueDefinitions,
};

impl RegisterAddress {
    const IA32_BIOS_SIGN_ID: Self = Self(0x8b);
    const IA32_ARCH_CAPABILITIES: Self = Self(0x10a);
    const IA32_PERF_CAPABILITIES: Self = Self(0x345);
    const IA32_VMX_BASIC: Self = Self(0x480);
    const IA32_VMX_PINBASED_CTLS: Self = Self(0x481);
    const IA32_VMX_PROCBASED_CTLS: Self = Self(0x482);
    const IA32_VMX_EXIT_CTLS: Self = Self(0x483);
    const IA32_VMX_ENTRY_CTLS: Self = Self(0x484);
    const IA32_VMX_MISC: Self = Self(0x485);
    const IA32_VMX_CR0_FIXED0: Self = Self(0x486);
    const IA32_VMX_CR0_FIXED1: Self = Self(0x487);
    const IA32_VMX_CR4_FIXED0: Self = Self(0x488);
    const IA32_VMX_CR4_FIXED1: Self = Self(0x489);
    const IA32_VMX_VMCS_ENUM: Self = Self(0x48a);
    const IA32_VMX_PROCBASED_CTLS2: Self = Self(0x48b);
    const IA32_VMX_EPT_VPID_CAP: Self = Self(0x48c);
    const IA32_VMX_TRUE_PINBASED_CTLS: Self = Self(0x48d);
    const IA32_VMX_TRUE_PROCBASED_CTLS: Self = Self(0x48e);
    const IA32_VMX_TRUE_EXIT_CTLS: Self = Self(0x48f);
    const IA32_VMX_TRUE_ENTRY_CTLS: Self = Self(0x490);
    const IA32_VMX_VMFUNC: Self = Self(0x491);
    const IA32_VMX_PROCBASED_CTLS3: Self = Self(0x492);
    const IA32_VMX_EXIT_CTLS2: Self = Self(0x493);
}

/// This table contains descriptions of all the MSRs whose register addresses can be contained in
/// the list returned by `KVM_GET_MSR_FEATURE_INDEX_LIST` when executed on an Intel CPU.
///
/// The values described here are based on the Intel 64 and IA-32 Architectures Software Developer's
/// Manual Combined Volumes: 1,2A, 2B, 2C, 2D, 3A, 3B, 3C, 3D, and 4 from October 2025.
///
/// We try to use the same short descriptions as Intel, but in the cases where we could not find an
/// official name for the bit field(s) we invented our own based on the description.
///
/// The descriptions written here are based on those found in the aforementioned manual, but often less
/// detailed. We recommend consulting the official Intel documentation whenever more information
/// is required.
///
///
/// ## Future-proofing
///
/// Future processors and/or KVM versions may of course introduce more MSR-based features than those listed here at this time of writing.
/// In order to make sure that this is taken into account, the CPU profile generation tool will error when this is detected. The person
/// attempting to create a new CPU profile should then update this table accordingly and try again.
pub static INTEL_MSR_FEATURE_DEFINITIONS: MsrDefinitions<23> = const {
    MsrDefinitions([
        (
            RegisterAddress::IA32_BIOS_SIGN_ID,
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "PATCH_SIGN_ID",
                    description: "Any non-zero value is the microcode update signature patch signature ID",
                    bits_range: (32, 63),
                    policy: ProfilePolicy::Passthrough
                }
            ])
        ),

        (
        RegisterAddress::IA32_ARCH_CAPABILITIES,
        ValueDefinitions::new(&[
            ValueDefinition {
                short: "RDCL_NO",
                description: "The processor is not susceptible to Rogue Data Cache Load (RDCL)",
                bits_range: (0, 0),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "IBRS_ALL",
                description: "The processor supports enhanced IBRS",
                bits_range: (1, 1),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "RSBA",
                description: "The processor supports RSB Alternate",
                bits_range: (2, 2),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "SKIP_L1DFL_VMENTRY",
                description: "A value of 1 indicates the hypervisor need not flush the L1D on VM entry",
                bits_range: (3, 3),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "SSB_NO",
                description: "Processor is not susceptible to Speculation Store Bypass",
                bits_range: (4, 4),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "MDS_NO",
                description: "Processor is not susceptible to Microarchitectural Data Sampling (MDS)",
                bits_range: (5, 5),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "IF_PSCHANGE_MC_NO",
                description: "The processor is not susceptible to a machine check error due to modifying the size of a code page without TLB invalidation",
                bits_range: (6, 6),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "TSX_CTRL",
                description: "If 1, indicates presence of IA32_TSX_CTRL MSR",
                bits_range: (7, 7),
                // TSX is riddled with CVEs
                // TODO: Check that this is indeed the right policy
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "TAA_NO",
                description: "If 1, processor is not affected by TAA",
                bits_range: (8, 8),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "MCU_CONTROL",
                description: "If 1, the processor supports the IA32_MCU_CONTROL MSR",
                bits_range: (9, 9),
                // TODO: Check what the IA32_MCU_CONTROL MSR is
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "MISC_PACKAGE_CTLS",
                description: "The processor supports IA32_MISC_PACKAGE_CTLS MSR",
                bits_range: (10, 10),
                // TODO: Check that this is the right policy
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "ENERGY_FILTERING_CTL",
                description: "The processor supports setting and reading the IA32_MISC_PACKAGE_CTLS[0] (ENERGY_FILTERING_ENABLE) bit",
                bits_range: (11, 11),
                policy: ProfilePolicy::Static(0),
            },
            ValueDefinition {
                short: "DOITM:",
                description: "If 1, the processor supports Data Operand Independent Timing Mode",
                bits_range: (12, 12),
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "SBDR_SSDP_NO",
                description: "The processor is not affected by either the Shared Buffers Data Read (SBDR) vulnerability or the Sideband Stale Data Propagator (SSDP)",
                bits_range: (13, 13),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "FBSDP_NO",
                description: "The processor is not affected by the Fill Buffer Stale Data Propagator (DBSDP)",
                bits_range: (14, 14),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "PSDP_NO",
                description: "The processor is not affected by vulnerabilities involving the Primary Stale Data Propagator (PSDP)",
                bits_range: (15, 15),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "MCU_ENUMERATION",
                description: "If 1, the processor supportss the IA32_MCU_ENUMERATION and IA32_MCU_STATUS MSRs",
                bits_range: (16, 16),
                // TODO: Check policy
                policy: ProfilePolicy::Inherit,
            },
            ValueDefinition {
                short: "FB_CLEAR",
                description: "If 1, the processor supports overwrite of fill buffer values as part of MD_CLEAR operations with the VERW instruction.
                On these processors L1D_FLUSH does not overwrite fill buffer values",
                bits_range: (17, 17),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "FB_CLEAR_CTRL",
                description: "If 1, the processor supports the IA32_MCU_OPT_CTRL MSR and allows software to set bit 3 of that MSR (FB_CLEAR_DIS)",
                bits_range: (18, 18),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "RRSBA",
                description: "A value of 1 indicates the processor may have the RRSBA alternate prediction behavior, if not disabled by RRSBA_DIS_U or RRSBA_DIS_S",
                bits_range: (19, 19),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "BHI_NO",
                description: "A value of 1 indicates BHI_NO branch prediction behavior, regardless of the value of IA32_SPEC_CTRL[BHI_DIS_S] MSR bit",
                bits_range: (20, 20),
                policy: ProfilePolicy::Passthrough,
            },

            ValueDefinition {
                short: "XAPIC_DISABLE_STATUS",
                description: "Enumerates that the IA32_XAPIC_DISABLE_STATUS MSR exists, and that bit 0 specifies whether the legacy xAPIC is disabled and APIC state is locked to x2APIC",
                bits_range: (21, 21),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "MCU_EXTENDED_SERVICE",
                description: "If 1, the processor supports MCU extended servicing - IA32_MCU_EXT_SERVICE MSR",
                bits_range: (22, 22),
                // TODO: Check
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "OVERCLOCKING_STATUS",
                description: "If set, the IA32_OVERCLOCKING_STATUS MSR exists",
                bits_range: (23, 23),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "PBRSB_NO",
                description: "If 1, the processor is not affected by issues related to Post-Barrier Return Stack Buffer Predictions",
                bits_range: (24, 24),
                policy: ProfilePolicy::Passthrough,
            },
            ValueDefinition {
                short: "GDS_CTRL",
                description: "If 1, the processor supports the GDS_MITG_DIS and GDS_MITG_LOCK bits of the IA32_MCU_OPT_CTRL MSR",
                bits_range: (25, 25),
                // TODO: Check
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "GDS_NO",
                description: "If 1, the processor is not affected by Gather Data Sampling",
                bits_range: (26, 26),
                policy: ProfilePolicy::Passthrough,
            },

            ValueDefinition {
                short: "RFDS_NO",
                description: "If 1, processor is not affected by Register File Data Sampling",
                bits_range: (27, 27),
                policy: ProfilePolicy::Passthrough,
            },

            ValueDefinition {
                short: "RFDS_CLEAR",
                description: "If 1, when VERW is executed the processor will clear stale data from register files affected by Register File Data Sampling",
                bits_range: (28, 28),
                policy: ProfilePolicy::Passthrough,
            },

            ValueDefinition {
                short: "IGN_UMONITOR_SUPPORT",
                description: "If 0, IA32_MCU_OPT_CTRL bit 6 (IGN_UMONITOR) is not supported. If 1, it indicates support of IA32_MCU_OPT_CTRL bit 6 (IGN_UMONITOR)",
                bits_range: (29, 29),
                // TODO: Check
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "MON_UMON_MITG_SUPPORT",
                description: "If 1, indicates support for IA32_MCU_OPT_CTRL bit 7 (MON_UMON_MITG), otherwise it is not supported",
                bits_range: (30, 30),
                policy: ProfilePolicy::Inherit,
            },


            ValueDefinition {
                short: "PBOPT_SUPPORT",
                description: "If 1, IA32_PBOPT_CTRL bit 0 (Prediction Barrier Option (PBOPT)) is supported, otherwise it is not",
                bits_range: (32, 32),
                policy: ProfilePolicy::Inherit,
            },

            ValueDefinition {
                short: "ITS_NO",
                description: "If 0, the hypervisor indicates that the system is not affected by indirect Target Selection. If 1, then the hypervisor
                indicates that the system may be affected by indirect Target Selection",
                bits_range: (62, 62),
                policy: ProfilePolicy::Inherit,

            },

        ]),
    ),

    (
            RegisterAddress::IA32_PERF_CAPABILITIES,
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "IA32_PERF_CAPABILITIES",
                    description: "Read Only MSR that enumerates the existence of performance monitoring features",
                    bits_range: (0, 63),
                    // This MSR is only valid if CPUID 0x1.ECX[15] is set, but that bit is always zeroed out for CPU profiles different from host
                    policy: ProfilePolicy::Deny
                }
            ])
        ),

        (
            RegisterAddress::IA32_VMX_BASIC,
            ValueDefinitions::new(&[
                ValueDefinition {
                    short: "VMCS_REV_ID",
                    description: "31-bit VMCS revision identifier. Processors that use the same VMCS revision identifier
                    use the same size for VMCS regions",
                    bits_range: (0,31),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "REGION_SIZE",
                    description: "Number of bytes that software should allocate for the VMXON region and any VMCS region. It is a value greater than
                    0 and at most 4096",
                    bits_range: (32, 44),
                    policy: ProfilePolicy::Inherit,
                },

                ValueDefinition {
                    short: "DUAL_MON",
                    description: " If 1, the logical processor supports the dual-monitor treatment of system-management
                    interrupts and system-management mode. See Section 33.15 for details of this treatment",
                    bits_range: (49, 49),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "MEM_TYPE",
                    description: "The memory type that should be used for the VMCS, for data structures referenced by pointers
                    in the VMCS (I/O bitmaps, virtual-APIC page, MSR areas for VMX transitions), and for the MSEG header",
                    bits_range: (50, 53),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "VM_EXIT_INFO_INS_OUTS",
                    description: " If 1, the processor reports information in the VM-exit instruction-information field on VM exits
                    due to execution of the INS and OUTS instructions.
                    ",
                    bits_range: (54, 54),
                    policy: ProfilePolicy::Inherit
                },

                ValueDefinition {
                    short: "VMX_CTRLS_DEFAULT_MUT",
                    description: "Any VMX controls that default to 1 nay be cleared to 0",
                    bits_range: (55,55),
                    policy: ProfilePolicy::Inherit
                },
                ValueDefinition {
                    short: "VM_ENTRY_HARDWARE_EXCEPTIONS",
                    description: "If 1, then software can use VM entry to deliver a hardware exception",
                    bits_range: (56, 56),
                    policy: ProfilePolicy::Inherit
                }
        ])
            ),

            (
              RegisterAddress::IA32_VMX_PINBASED_CTLS,
              ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_PROCBASED_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_EXIT_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_ENTRY_CTLS,
                ValueDefinitions::new(&[
                   ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_MISC,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "VMX_PREEMPTION_TSC_REL",
                        description: "specifies the relationship between the rate of the VMX-preemption timer and that of the timestamp counter (TSC)",
                        bits_range: (0, 4),
                        policy: ProfilePolicy::Passthrough
                    },
                    ValueDefinition {
                        short: "IA32_EFER.LMA_STORE",
                        description: "If 1, then VM exits store the value of IA32_EFER.LMA into the IA32-e mode guest VM-entry control",
                        bits_range: (5,5),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "HLT_STATE",
                        description: "Activity state 1 (HLT) is supported",
                        bits_range: (6,6),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "SHUTDOWN_STATE",
                        description: "Activity state 2 (shutdown) is supported",
                        bits_range: (7,7),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "WAIT_FOR_SIPI__STATE",
                        description: "Activity state 3 (wait-for-SIPI) is supported",
                        bits_range: (8,8),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "VMX_INTEL_PT",
                        description: "If 1 then Intel Processor Trace can be used in VMX operation",
                        bits_range: (14,14),
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "RDMSR_SMM",
                        description: "If 1 then the RDMSR instruction can be used in system management mode (SMM) to read the IA32_SMBASE MSR",
                        bits_range: (15,15),
                        // TODO: Is this a reasonable policy?
                        policy: ProfilePolicy::Static(0)
                    },
                    ValueDefinition {
                        short: "VMX_NUM_CR3",
                        description: "The number of CR3-target values supported by the processor",
                        bits_range: (16,24),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "MAX_MSR_STORE_LISTS",
                        description: "If N then 512*(N +1) is the recommended maximum number of MSRs to be included each of the VM-exit MSR-store list, VM-exit-MSR-load-list, VM-entry MSR-load list",
                        bits_range: (25, 27),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "SMM_MONITOR_CTL_BIT2",
                        description: "If set then bit 2 of the IA32_SMM_MONITOR_CTL can be set to 1",
                        bits_range: (28, 28),
                        policy: ProfilePolicy::Inherit,
                    },
                    ValueDefinition {
                        short: "VM_WRITE_EXIT_FIELDS",
                        description: "If 1 then software can use VMWRITE to write to any supported field in the VMCS",
                        bits_range: (29,29),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "VM_ENTRY_INJECTION",
                        description: "If 1 then VM entry permits injection of the following: software interrupt, software exception, or privileged software exception with an instruction length of 0",
                        bits_range: (30,30),
                        policy: ProfilePolicy::Inherit
                    },
                    ValueDefinition {
                        short: "MSEG_REV_ID",
                        description: "MSEG revision identifier used by the processor",
                        bits_range: (32,63),
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

            (
                RegisterAddress::IA32_VMX_CR0_FIXED0,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED0",
                        description: "Reports bits allowed to be 0 in CR0",
                        bits_range: (0, 63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_CR0_FIXED1,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "IA32_VMX_CR0_FIXED1",
                        description: "Reports bits allowed to be 1 in CR0",
                        bits_range: (0, 63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_CR4_FIXED0,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "IA32_VMX_CR4_FIXED0",
                        description: "Reports bits allowed to be 0 in CR4",
                        bits_range: (0, 63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_CR4_FIXED1,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "IA32_VMX_CR4_FIXED1",
                        description: "Reports bits allowed to be 1 in CR4",
                        bits_range: (0, 63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_VMCS_ENUM,
                ValueDefinitions::new(&[
                    ValueDefinition{
                        short: "MAX_INDEX",
                        description: "highest index value used for any VCMS encoding",
                        bits_range: (1, 9),
                        policy: ProfilePolicy::Inherit
                    }
                ])

            ),

            (
                RegisterAddress::IA32_VMX_PROCBASED_CTLS2,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_EPT_VPID_CAP,
                ValueDefinitions::new(&[
                    ValueDefinition{
                        short: "EPT_EXECUTE_ONLY",
                        description: "The processor supports execute-only translations by EPT",
                        bits_range: (0, 0),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "PAGE_WALK_LENGTH_4",
                        description: "Support for Page-walk length of 4",
                        bits_range: (6, 6),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "PAGE_WALK_LENGTH_5",
                        description: "Support for Page-walk length of 5",
                        bits_range: (7, 7),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_MEM_TYPE_UC",
                        description: "Software can configure the EPT paging structure to memory type to be unreachable (UC)",
                        bits_range: (8, 8),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_MEM_TYPE_WB",
                        description: "Software can configure the EPT paging structure to memory type to be write-back (WB)",
                        bits_range: (14, 14),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_PDE_2M",
                        description: "Software can configure the EPT PDE to map a 2-Mbyte page",
                        bits_range: (16, 16),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "EPT_PDPTE_1G",
                        description: "Software can configure the EPT PDPTE to map a 1-Gbyte page",
                        bits_range: (17, 17),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "INVEPT",
                        description: "INVEPT instruction is supported",
                        bits_range: (20, 20),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "FLAGS_EPT",
                        description: "Accessed and dirty flags for EPT are supported",
                        bits_range: (21, 21),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "VM_EXIT_VIOLATIONS_INFO",
                        description: "If set, the processors advanced VM-exit information for EPT violations",
                        bits_range: (22, 22),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition {
                        short: "SHADOW_STACK_CTL",
                        description: "Supervisor shadow-stack control is supported",
                        bits_range: (23, 23),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "SINGLE_CONTEXT_INVEPT",
                        description: "The single-context INVEPT type is supported",
                        bits_range: (25, 25),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "ALL_CONTEXT_INVEPT",
                        description: "The all-context INVEPT type is supported",
                        bits_range: (26, 26),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "INVVPID",
                        description: "INVVPID instruction is supported",
                        bits_range: (32, 32),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "INDIVIDUAL_ADDRESS_INVVPID",
                        description: "The individual address INVVPID type is supported",
                        bits_range: (40, 40),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "SINGLE_CONTEXT_INVVPID",
                        description: "The single-context INVVPID type is supported",
                        bits_range: (41, 41),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "ALL_CONTEXT_INVVPID",
                        description: "The all-context INVEPT type is supported",
                        bits_range: (42, 42),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "SINGLE_CONTEXT_RETAINING_GLOBALS_INVVPID",
                        description: "The single-context-retaining-globals INVVPID type is supported",
                        bits_range: (43, 43),
                        policy: ProfilePolicy::Inherit
                    },

                    ValueDefinition{
                        short: "MAX_HLAT_PREFIX",
                        description: "Enumerates the maximum HLAT prefix size",
                        bits_range: (48, 53),
                        policy: ProfilePolicy::Inherit
                    },
                ])
            ),

            (

                RegisterAddress::IA32_VMX_TRUE_PINBASED_CTLS,
                ValueDefinitions::new(&[

                    ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },
                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_TRUE_PROCBASED_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_TRUE_EXIT_CTLS,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_TRUE_ENTRY_CTLS,
                ValueDefinitions::new(&[
                   ValueDefinition {
                      short: "ALLOWED_ZERO",
                      description: "VM entry allows control X to be 0 if bit X in this MSR is zero",
                      bits_range: (0, 31),
                      policy: ProfilePolicy::Inherit
                  },

                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X + 32 in this MSR is 1",
                      bits_range: (32, 64),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),

            (
              RegisterAddress::IA32_VMX_VMFUNC,
              ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "IA32_VMX_VMFUNC MSR",
                      description: "VM entry allows bit X of the VM-function controls to be 1 if bit X in this MSR is 1",
                      bits_range: (0, 63),
                      policy: ProfilePolicy::Inherit
                  }
              ])
            ),

            (
                RegisterAddress::IA32_VMX_PROCBASED_CTLS3,
                ValueDefinitions::new(&[
                    ValueDefinition {
                        short: "ALLOWED_ONE",
                        description: "VM entry allows control X to be 1 if bit X is 1 in this MSR",
                        bits_range: (0,63),
                        policy: ProfilePolicy::Inherit
                    }
                ])
            ),

            (
                RegisterAddress::IA32_VMX_EXIT_CTLS2,
                ValueDefinitions::new(&[
                  ValueDefinition {
                      short: "ALLOWED_ONE",
                      description:"VM entry allows control X to be 1 if bit X is 1",
                      bits_range: (0, 64),
                      policy: ProfilePolicy::Inherit
                  }
                ])
            ),
        ])
};
