//
// Copyright © 2021 Microsoft
//
// SPDX-License-Identifier: Apache-2.0
//

#![expect(non_camel_case_types)]

//
// OR - Logical inclusive OR
//

use crate::arch::x86::emulator::instructions::*;
use crate::arch::x86::regs::*;

// OR clears OF and CF and sets SF, ZF and PF according to the result. AF is
// undefined, it is cleared as hardware and QEMU do.
const FLAGS_MASK: u64 = CF | PF | AF | ZF | SF | OF;

fn calc_rflags_pzs(result: u64, op_size: usize) -> u64 {
    let msb_shift = op_size * 8 - 1;

    // PF only needs the least significant byte, see calc_rflags_cpazso() in cmp.rs.
    let pf = ((0x9669 >> ((result ^ (result >> 4)) & 0xf)) & 0x1) << PF_SHIFT;

    let zf = u64::from(result & (!0u64 >> (63 - msb_shift)) == 0) << ZF_SHIFT;

    let sf = ((result >> msb_shift) & 0x1) << SF_SHIFT;

    pf | zf | sf
}

macro_rules! or_rm_r {
    ($bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError> {
            let src_reg_value = get_op(&insn, 1, size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            let dst_value = get_op(&insn, 0, size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            let result = src_reg_value | dst_value;

            set_op(&insn, 0, size_of::<$bound>(), state, platform, result)
                .map_err(EmulationError::PlatformEmulationError)?;

            let pzs = calc_rflags_pzs(result, size_of::<$bound>());
            state.set_flags((state.flags() & !FLAGS_MASK) | pzs);

            Ok(())
        }
    };
}

pub(crate) struct Or_rm8_r8;
impl<T: CpuStateManager> InstructionHandler<T> for Or_rm8_r8 {
    or_rm_r!(u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86::emulator::mock_vmm::*;

    #[test]
    // or byte ptr [rax+1h], sil
    fn test_or_rm8_r8() {
        let rax = 0;
        let insn = [0x40, 0x08, 0x70, 0x1];
        let cpu_id = 0;
        let ip: u64 = 0x1000;
        let sil = 0xaa;
        let memory = [0x0, 0x55];

        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::SIL, sil), (Register::RAX, rax)],
            Some((0, &memory)),
        );

        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut out: [u8; 1] = [0; 1];

        vmm.read_memory(rax + 1, &mut out).unwrap();
        assert_eq!(u8::from_le_bytes(out), 0xff);
    }

    #[test]
    fn test_or_rm8_r8_flags() {
        // (memory, sil, expected flags)
        let data = [
            (0x0, 0x0, 0b100_0100),    // ZF, PF
            (0x55, 0xaa, 0b1000_0100), // SF, PF
            (0x10, 0x01, 0b100),       // PF
            (0x40, 0x01, 0b100),       // PF
            (0x80, 0x00, 0b1000_0000), // SF
        ];

        for d in data.iter() {
            let insn = [0x40, 0x08, 0x30]; // or byte ptr [rax], sil
            let memory = [d.0];

            let mut vmm = MockVmm::new(
                0x1000,
                vec![(Register::SIL, d.1), (Register::RAX, 0)],
                Some((0, &memory)),
            );

            // CF, OF and AF must be cleared, other flags must be left untouched.
            let mut state = vmm.cpu_state(0).unwrap();
            state.set_flags(state.flags() | FLAGS_MASK | DF);
            vmm.set_cpu_state(0, state).unwrap();

            vmm.emulate_first_insn(0, &insn).unwrap();

            let rflags = vmm.cpu_state(0).unwrap().flags();
            assert_eq!(d.2, rflags & FLAGS_MASK);
            assert_eq!(DF, rflags & DF);
        }
    }
}
