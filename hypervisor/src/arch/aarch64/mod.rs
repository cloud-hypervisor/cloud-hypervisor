// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.

pub mod gic;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct StandardRegisters {
    pub gpr: [u64; 31usize],    // 31 General Purpose Registers
    pub sp: u64,                // Stack Pointer
    pub pc: u64,                // Program Counter
    pub pstate: u64,            // Program Status Register
    pub sp_el1: u64,            // Stack Pointer for EL1
    pub elr_el1: u64,           // Exception Link Register for EL1
    pub spsr: [u64; 5usize],    // Saved Program Status Registers
    pub vregs: [u128; 32usize], // 32 Floating Point Registers
    pub fpsr: u64,              // Floating point status register
    pub fpcr: u64,              // Floating point control register
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct Register {
    pub id: u64,
    pub addr: u64,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct VcpuInit {
    pub target: u32,
    pub features: [u32; 7usize],
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(Deserialize, Serialize))]
pub struct RegList(pub Vec<u64>);
