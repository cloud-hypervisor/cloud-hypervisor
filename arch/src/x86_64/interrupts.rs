// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::io::Cursor;
use std::mem;
use std::result;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use hypervisor::x86_64::LapicState;

#[derive(Debug)]
pub enum Error {
    GetLapic(anyhow::Error),
    SetLapic(anyhow::Error),
}

pub type Result<T> = result::Result<T, hypervisor::HypervisorCpuError>;

// Defines poached from apicdef.h kernel header.
const APIC_LVT0: usize = 0x350;
const APIC_LVT1: usize = 0x360;
const APIC_MODE_NMI: u32 = 0x4;
const APIC_MODE_EXTINT: u32 = 0x7;

fn get_klapic_reg(klapic: &LapicState, reg_offset: usize) -> u32 {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        mem::transmute::<&[i8], &[u8]>(&klapic.regs[reg_offset..])
    };
    let mut reader = Cursor::new(sliceu8);
    // Following call can't fail if the offsets defined above are correct.
    reader
        .read_u32::<LittleEndian>()
        .expect("Failed to read klapic register")
}

fn set_klapic_reg(klapic: &mut LapicState, reg_offset: usize, value: u32) {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        mem::transmute::<&mut [i8], &mut [u8]>(&mut klapic.regs[reg_offset..])
    };
    let mut writer = Cursor::new(sliceu8);
    // Following call can't fail if the offsets defined above are correct.
    writer
        .write_u32::<LittleEndian>(value)
        .expect("Failed to write klapic register")
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    ((reg) & !0x700) | ((mode) << 8)
}

/// Configures LAPICs.  LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
///
/// # Arguments
/// * `vcpu` - The VCPU object to configure.
pub fn set_lint(vcpu: &Arc<dyn hypervisor::Vcpu>) -> Result<()> {
    let mut klapic = vcpu.get_lapic()?;

    let lvt_lint0 = get_klapic_reg(&klapic, APIC_LVT0);
    set_klapic_reg(
        &mut klapic,
        APIC_LVT0,
        set_apic_delivery_mode(lvt_lint0, APIC_MODE_EXTINT),
    );
    let lvt_lint1 = get_klapic_reg(&klapic, APIC_LVT1);
    set_klapic_reg(
        &mut klapic,
        APIC_LVT1,
        set_apic_delivery_mode(lvt_lint1, APIC_MODE_NMI),
    );

    vcpu.set_lapic(&klapic)
}

#[cfg(test)]
mod tests {

    extern crate rand;
    use self::rand::Rng;

    use super::*;

    const KVM_APIC_REG_SIZE: usize = 0x400;

    #[test]
    fn test_set_and_get_klapic_reg() {
        let reg_offset = 0x340;
        let mut klapic = LapicState::default();
        set_klapic_reg(&mut klapic, reg_offset, 3);
        let value = get_klapic_reg(&klapic, reg_offset);
        assert_eq!(value, 3);
    }

    #[test]
    #[should_panic]
    fn test_set_and_get_klapic_out_of_bounds() {
        let reg_offset = KVM_APIC_REG_SIZE + 10;
        let mut klapic = LapicState::default();
        set_klapic_reg(&mut klapic, reg_offset, 3);
    }

    #[test]
    fn test_apic_delivery_mode() {
        let mut rng = rand::thread_rng();
        let mut v: Vec<u32> = (0..20).map(|_| rng.gen::<u32>()).collect();

        v.iter_mut()
            .for_each(|x| *x = set_apic_delivery_mode(*x, 2));
        let after: Vec<u32> = v.iter().map(|x| ((*x & !0x700) | ((2) << 8))).collect();
        assert_eq!(v, after);
    }

    #[test]
    fn test_setlint() {
        let hv = hypervisor::new().unwrap();
        let vm = hv.create_vm().expect("new VM fd creation failed");
        assert!(hv.check_capability(hypervisor::kvm::Cap::Irqchip));
        // Calling get_lapic will fail if there is no irqchip before hand.
        assert!(vm.create_irq_chip().is_ok());
        let vcpu = vm.create_vcpu(0).unwrap();
        let klapic_before: LapicState = vcpu.get_lapic().unwrap();

        // Compute the value that is expected to represent LVT0 and LVT1.
        let lint0 = get_klapic_reg(&klapic_before, APIC_LVT0);
        let lint1 = get_klapic_reg(&klapic_before, APIC_LVT1);
        let lint0_mode_expected = set_apic_delivery_mode(lint0, APIC_MODE_EXTINT);
        let lint1_mode_expected = set_apic_delivery_mode(lint1, APIC_MODE_NMI);

        set_lint(&vcpu).unwrap();

        // Compute the value that represents LVT0 and LVT1 after set_lint.
        let klapic_actual: LapicState = vcpu.get_lapic().unwrap();
        let lint0_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT0);
        let lint1_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT1);
        assert_eq!(lint0_mode_expected, lint0_mode_actual);
        assert_eq!(lint1_mode_expected, lint1_mode_actual);
    }
}
