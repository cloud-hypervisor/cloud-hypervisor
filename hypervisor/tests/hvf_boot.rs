// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! End-to-end boot + snapshot/restore test for the Apple Hypervisor.framework
//! backend, driven entirely through the hypervisor-agnostic `Hypervisor` /
//! `Vm` / `Vcpu` trait objects (i.e. the same surface the VMM uses).
//!
//! The test binary must be code-signed with the `com.apple.security.hypervisor`
//! entitlement before it can create a VM. See `hypervisor/tests/data/`.
#![cfg(all(feature = "hvf", target_os = "macos", target_arch = "aarch64"))]

use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hypervisor::{CpuState, HypervisorVmConfig, HypervisorVmError, Vcpu, Vm, VmExit, VmOps};

type VmOpsResult<T> = std::result::Result<T, HypervisorVmError>;

const RAM_BASE: u64 = 0x4000_0000;
const RAM_SIZE: usize = 0x20_0000; // 2 MiB, multiple of the 16 KiB page size
const MMIO_TX: u64 = 0x1000_0000;

/// A bare-metal arm64 guest:
///   x9 = 0; x10 = 0x10000000
///   loop: x9 += 1; *(u32*)x10 = x9; if x9 < 6 goto loop
///   x0 = 0x84000008 (PSCI SYSTEM_OFF); hvc #0; spin
/// Each store to MMIO_TX traps as a stage-2 data abort and is serviced by the
/// backend via `VmOps::mmio_write`, so the host observes the sequence 1..=6.
#[rustfmt::skip]
const GUEST_CODE: [u8; 40] = [
    0x09, 0x00, 0x80, 0xd2, // mov  x9, #0
    0x0a, 0x00, 0xa2, 0xd2, // movz x10, #0x1000, lsl #16
    0x29, 0x05, 0x00, 0x91, // add  x9, x9, #1
    0x49, 0x01, 0x00, 0xb9, // str  w9, [x10]
    0x3f, 0x19, 0x00, 0xf1, // cmp  x9, #6
    0xab, 0xff, 0xff, 0x54, // b.lt loop
    0x00, 0x01, 0x80, 0xd2, // movz x0, #0x8
    0x00, 0x80, 0xb0, 0xf2, // movk x0, #0x8400, lsl #16
    0x02, 0x00, 0x00, 0xd4, // hvc  #0
    0x00, 0x00, 0x00, 0x14, // b    .
];

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_PRIVATE: i32 = 0x0002;
const MAP_ANON: i32 = 0x1000;

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

/// Page-aligned host RAM backing the guest, freed on drop.
struct HostRam {
    ptr: *mut u8,
    size: usize,
}

impl HostRam {
    fn new(size: usize) -> Self {
        // SAFETY: standard anonymous RWX mapping; validated below.
        let p = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        assert!(
            !p.is_null() && p != usize::MAX as *mut c_void,
            "mmap failed"
        );
        HostRam {
            ptr: p as *mut u8,
            size,
        }
    }

    fn load(&self, offset: usize, bytes: &[u8]) {
        // SAFETY: offset + len fits within the mapping.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(offset), bytes.len());
        }
    }
}

impl Drop for HostRam {
    fn drop(&mut self) {
        // SAFETY: unmapping our own mapping exactly once.
        unsafe {
            munmap(self.ptr as *mut c_void, self.size);
        }
    }
}

/// Minimal VmOps: records every MMIO write to MMIO_TX as a u32.
struct RecordingVmOps {
    writes: Mutex<Vec<u32>>,
}

impl VmOps for RecordingVmOps {
    fn guest_mem_write(&self, _gpa: u64, buf: &[u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }
    fn guest_mem_read(&self, _gpa: u64, buf: &mut [u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }
    fn mmio_read(&self, _gpa: u64, data: &mut [u8]) -> VmOpsResult<()> {
        data.fill(0);
        Ok(())
    }
    fn mmio_write(&self, gpa: u64, data: &[u8]) -> VmOpsResult<()> {
        if gpa == MMIO_TX {
            let n = data.len().min(4);
            let mut v = [0u8; 4];
            v[..n].copy_from_slice(&data[..n]);
            self.writes.lock().unwrap().push(u32::from_le_bytes(v));
        }
        Ok(())
    }
}

/// Build a VM, map `ram`, and create a single vCPU wired to `vm_ops`.
fn build_vm(ram: &HostRam, vm_ops: Arc<RecordingVmOps>) -> (Arc<dyn Vm>, Box<dyn Vcpu>) {
    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");
    // SAFETY: ram outlives the mapping (caller keeps it alive).
    unsafe {
        vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
            .expect("map ram");
    }
    let vcpu = vm.create_vcpu(0, Some(vm_ops)).expect("create_vcpu");
    (vm, vcpu)
}

/// Run until the guest powers off (or a safety bound is hit), returning the exit.
fn run_to_shutdown(vcpu: &mut dyn Vcpu) -> VmExit {
    for _ in 0..10_000 {
        match vcpu.run().expect("vcpu run") {
            VmExit::Ignore => continue,
            other => return other,
        }
    }
    panic!("guest did not power off within the step budget");
}

#[test]
fn hvf_cold_boot_mmio_sequence() {
    let ram = HostRam::new(RAM_SIZE);
    ram.load(0, &GUEST_CODE);
    let vm_ops = Arc::new(RecordingVmOps {
        writes: Mutex::new(Vec::new()),
    });

    let (_vm, mut vcpu) = build_vm(&ram, vm_ops.clone());
    vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

    let exit = run_to_shutdown(vcpu.as_mut());
    assert!(
        matches!(exit, VmExit::Shutdown),
        "expected Shutdown, got {exit:?}"
    );
    assert_eq!(*vm_ops.writes.lock().unwrap(), vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn hvf_snapshot_restore_midflight() {
    // Phase A: cold boot, run until 3 MMIO writes have been observed, then
    // capture full vCPU state and tear the VM completely down.
    let snapshot: CpuState;
    {
        let ram = HostRam::new(RAM_SIZE);
        ram.load(0, &GUEST_CODE);
        let vm_ops = Arc::new(RecordingVmOps {
            writes: Mutex::new(Vec::new()),
        });
        let (_vm, mut vcpu) = build_vm(&ram, vm_ops.clone());
        vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

        loop {
            let exit = vcpu.run().expect("vcpu run");
            assert!(
                matches!(exit, VmExit::Ignore),
                "unexpected early exit {exit:?}"
            );
            if vm_ops.writes.lock().unwrap().len() == 3 {
                break;
            }
        }
        assert_eq!(*vm_ops.writes.lock().unwrap(), vec![1, 2, 3]);
        snapshot = vcpu.state().expect("capture state");
        // _vm and vcpu drop here: hv_vcpu_destroy then hv_vm_destroy.
    }

    // Phase B: brand-new VM in the same process, restore the snapshot, and
    // continue. The guest must resume mid-loop and emit exactly 4, 5, 6.
    {
        let ram = HostRam::new(RAM_SIZE);
        ram.load(0, &GUEST_CODE);
        let vm_ops = Arc::new(RecordingVmOps {
            writes: Mutex::new(Vec::new()),
        });
        let (_vm, mut vcpu) = build_vm(&ram, vm_ops.clone());
        vcpu.set_state(&snapshot).expect("restore state");

        let exit = run_to_shutdown(vcpu.as_mut());
        assert!(
            matches!(exit, VmExit::Shutdown),
            "expected Shutdown, got {exit:?}"
        );
        assert_eq!(
            *vm_ops.writes.lock().unwrap(),
            vec![4, 5, 6],
            "guest did not resume from the restored register state"
        );
    }
}

/// Create a managed GICv3 through the real `Vm::create_vgic` trait path, prove
/// it is live by reading `GICD_TYPER`, then round-trip its state through
/// `state()`/`set_state()` — the same mechanism guest-interrupt snapshots use.
#[test]
fn hvf_vgic_create_and_state_roundtrip() {
    use hypervisor::arch::aarch64::gic::VgicConfig;
    use hypervisor::hvf::gic::HvfGicV3;

    // GICv3 layout in guest-physical space, clear of the RAM window and
    // 16 KiB-page aligned.
    let config = VgicConfig {
        vcpu_count: 1,
        dist_addr: 0x1000_0000,
        dist_size: 0x1_0000,
        redists_addr: 0x1010_0000,
        redists_size: 0x20_0000,
        msi_addr: 0,
        msi_size: 0,
        nr_irqs: 256,
    };

    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");

    // Ordering matters: hv_gic_create must run after the VM exists but before
    // any vCPU is created.
    let gic = vm.create_vgic(&config).expect("create_vgic");

    // GICD_TYPER (offset 0x4) must be readable from the live distributor and
    // advertise a non-empty SPI space (ITLinesNumber in bits [4:0]).
    let typer = {
        let mut guard = gic.lock().unwrap();
        let concrete = guard
            .as_any_concrete_mut()
            .downcast_mut::<HvfGicV3>()
            .expect("HVF GIC concrete type");
        let typer = concrete
            .distributor_reg(hypervisor::hvf::gic::GICD_TYPER)
            .expect("read GICD_TYPER from live GIC");
        // SPI assertion is also driven through the public set_spi path.
        concrete.set_spi(32, true).expect("assert SPI 32");
        concrete.set_spi(32, false).expect("deassert SPI 32");
        typer
    };
    assert_ne!(typer & 0x1f, 0, "GICD_TYPER reported zero interrupt lines");

    // Snapshot the controller and restore it — the rehydration round-trip.
    let snap = gic.lock().unwrap().state().expect("GIC state()");
    let snap_clone = snap.clone();
    assert!(
        matches!(&snap, hypervisor::arch::aarch64::gic::GicState::Hvf(s) if !s.data.is_empty()),
        "expected non-empty HVF GIC state blob"
    );
    gic.lock()
        .unwrap()
        .set_state(&snap_clone)
        .expect("GIC set_state() restore");
}

// ===================================================================
// End-to-end interrupt delivery: a real GICv3 guest takes an injected SPI.
// ===================================================================

// GICv3 layout for the interrupt test, clear of the RAM window (0x4000_0000)
// and the marker MMIO page, all 16 KiB-aligned.
const IRQ_GICD_BASE: u64 = 0x0800_0000;
const IRQ_REDIST_BASE: u64 = 0x0801_0000;
const IRQ_MARKER: u64 = 0x0900_0000;
const IRQ_READY: u64 = 0x0a00_0000;
const IRQ_SPI_INTID: u32 = 32;

// A GICv3 guest (source kept in the session notes as gicv3_guest.S). It brings
// up the GICv3 CPU interface and distributor, enables SPI 32, unmasks IRQs and
// idles in WFI. On the injected interrupt it acknowledges (ICC_IAR1_EL1),
// writes the INTID to IRQ_MARKER (a trapping MMIO store the host records),
// EOIs, and PSCI-offs.
//
// The three slices are loaded at their respective offsets into the
// zero-initialized guest RAM (boot at 0, IRQ vector at 0x1280, handler at
// 0x1800); VBAR_EL1 is set by the guest to RAM_BASE + 0x1000.
#[rustfmt::skip]
const IRQ_BOOT: [u8; 248] = [
    0x00, 0x00, 0xa8, 0xd2, 0x00, 0x00, 0x42, 0x91,
    0x1f, 0x00, 0x00, 0x91, 0x01, 0x00, 0xa8, 0xd2,
    0x21, 0x04, 0x40, 0x91, 0x01, 0xc0, 0x18, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x20, 0x00, 0x80, 0xd2,
    0xa0, 0xcc, 0x18, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
    0x00, 0x1e, 0x80, 0xd2, 0x00, 0x46, 0x18, 0xd5,
    0x20, 0x00, 0x80, 0xd2, 0xe0, 0xcc, 0x18, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x02, 0x00, 0xa1, 0xd2,
    0x60, 0x02, 0x80, 0x52, 0x40, 0x00, 0x00, 0xb9,
    0x20, 0x00, 0x80, 0x52, 0x40, 0x84, 0x00, 0xb9,
    0x5f, 0x20, 0x04, 0xb9, 0x03, 0x20, 0x8c, 0xd2,
    0x43, 0x00, 0x03, 0x8b, 0xa4, 0x00, 0x38, 0xd5,
    0xe5, 0xff, 0x9f, 0xd2, 0xe5, 0x1f, 0xa0, 0xf2,
    0xe5, 0x1f, 0xc0, 0xf2, 0x84, 0x00, 0x05, 0x8a,
    0x64, 0x00, 0x00, 0xf9, 0x20, 0x00, 0x80, 0x52,
    0x40, 0x04, 0x01, 0xb9, 0x9f, 0x3f, 0x03, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x07, 0x40, 0xa1, 0xd2,
    0xff, 0x00, 0x00, 0xb9, 0xff, 0x42, 0x03, 0xd5,
    0x06, 0x00, 0xa8, 0xd2, 0xc6, 0x04, 0x00, 0xf1,
    0xe1, 0xff, 0xff, 0x54, 0x01, 0x20, 0xa1, 0xd2,
    0x40, 0xcc, 0x38, 0xd5, 0x00, 0x00, 0x62, 0xb2,
    0x20, 0x00, 0x00, 0xb9, 0xe0, 0xcc, 0x38, 0xd5,
    0x00, 0x00, 0x62, 0xb2, 0x20, 0x00, 0x00, 0xb9,
    0x00, 0x46, 0x38, 0xd5, 0x00, 0x00, 0x62, 0xb2,
    0x20, 0x00, 0x00, 0xb9, 0x80, 0xcc, 0x38, 0xd5,
    0x00, 0x00, 0x62, 0xb2, 0x20, 0x00, 0x00, 0xb9,
    0xa0, 0xcc, 0x38, 0xd5, 0x00, 0x00, 0x62, 0xb2,
    0x20, 0x00, 0x00, 0xb9, 0x60, 0xcb, 0x38, 0xd5,
    0x00, 0x00, 0x62, 0xb2, 0x20, 0x00, 0x00, 0xb9,
    0x00, 0x01, 0x80, 0xd2, 0x00, 0x80, 0xb0, 0xf2,
    0x02, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14,
];
// `b irq_handler` installed at the "Current EL SPx, IRQ" vector (offset 0x280).
#[rustfmt::skip]
const IRQ_VECTOR: [u8; 4] = [0x60, 0x01, 0x00, 0x14];
// `b sync_handler` installed at the synchronous vectors (offsets 0x000/0x200).
#[rustfmt::skip]
const SYNC_VECTOR_0X000: [u8; 4] = [0xc0, 0x01, 0x00, 0x14];
#[rustfmt::skip]
const SYNC_VECTOR_0X200: [u8; 4] = [0x40, 0x01, 0x00, 0x14];
// Diagnostic synchronous-fault reporter at offset 0x1700: writes ESR_EL1 (with
// the high bit set so it can't be mistaken for an INTID) to the marker, then
// powers off — so an unexpected fault surfaces as data instead of a hang.
#[rustfmt::skip]
const SYNC_HANDLER: [u8; 32] = [
    0x00, 0x52, 0x38, 0xd5, 0x00, 0x00, 0x61, 0xb2, // mrs x0,ESR_EL1; orr x0,x0,#0x80000000
    0x01, 0x20, 0xa1, 0xd2, 0x20, 0x00, 0x00, 0xb9, // mov x1,#0x09000000; str w0,[x1]
    0x00, 0x01, 0x80, 0xd2, 0x00, 0x80, 0xb0, 0xf2, // mov x0,#8; movk x0,#0x8400,lsl#16
    0x02, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14, // hvc #0; b .
];
#[rustfmt::skip]
const IRQ_HANDLER: [u8; 32] = [
    0x00, 0xcc, 0x38, 0xd5, 0x01, 0x20, 0xa1, 0xd2, // mrs x0,ICC_IAR1_EL1; mov x1,#0x09000000
    0x20, 0x00, 0x00, 0xb9, 0x20, 0xcc, 0x18, 0xd5, // str w0,[x1]; msr ICC_EOIR1_EL1,x0
    0x00, 0x01, 0x80, 0xd2, 0x00, 0x80, 0xb0, 0xf2, // mov x0,#8; movk x0,#0x8400,lsl#16
    0x02, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14, // hvc #0; b .
];

// ---- Virtual-timer (CNTV) PPI-27 delivery guest ----
// Same skeleton as the SPI guest, but instead of waiting for a host-injected
// SPI it enables PPI 27 (the EL1 virtual timer) in its OWN redistributor SGI
// frame via MMIO, arms CNTV to fire shortly, unmasks IRQs and spins. On the
// timer IRQ it acknowledges (ICC_IAR1_EL1 -> expected INTID 27), records it at
// the marker, masks CNTV (so it cannot re-fire), EOIs and PSCI-offs. On timeout
// it dumps {ICC_HPPIR1, CNTV_CTL, CNTV_TVAL, ICC_IGRPEN1} (bit30-tagged) so a
// delivery failure surfaces as data: CNTV_CTL bit2 (ISTATUS) set with HPPIR1=
// 1023 means the timer fired but never reached the GIC; HPPIR1=27 means the GIC
// has it pending but the CPU interface never took it. Source kept in the
// session notes as vtimer_guest.S.
//
// VBAR_EL1 = RAM_BASE + 0x1000; redistributor SGI/PPI frame at GICR_BASE+0x10000
// (0x0802_0000). Loaded at offset 0; shares the SPI guest's vectors + sync
// handler (byte-identical) and differs only in this boot block and IRQ handler.
#[rustfmt::skip]
const VT_BOOT: [u8; 224] = [
    0x00, 0x00, 0xa8, 0xd2, 0x00, 0x00, 0x42, 0x91, // movz x0,#0x4000<<16; add x0,#0x80000 (SP)
    0x1f, 0x00, 0x00, 0x91, 0x01, 0x00, 0xa8, 0xd2, // mov sp,x0; movz x1,#0x4000<<16
    0x21, 0x04, 0x40, 0x91, 0x01, 0xc0, 0x18, 0xd5, // add x1,#0x1000; msr VBAR_EL1,x1
    0xdf, 0x3f, 0x03, 0xd5, 0x20, 0x00, 0x80, 0xd2, // isb; mov x0,#1
    0xa0, 0xcc, 0x18, 0xd5, 0xdf, 0x3f, 0x03, 0xd5, // msr ICC_SRE_EL1,x0; isb
    0x00, 0x1e, 0x80, 0xd2, 0x00, 0x46, 0x18, 0xd5, // mov x0,#0xf0; msr ICC_PMR_EL1,x0
    0x20, 0x00, 0x80, 0xd2, 0xe0, 0xcc, 0x18, 0xd5, // mov x0,#1; msr ICC_IGRPEN1_EL1,x0
    0xdf, 0x3f, 0x03, 0xd5, 0x02, 0x00, 0xa1, 0xd2, // isb; movz x2,#0x0800<<16 (GICD)
    0x60, 0x02, 0x80, 0x52, 0x40, 0x00, 0x00, 0xb9, // mov w0,#0x13; str w0,[x2] (GICD_CTLR)
    0x9f, 0x3f, 0x03, 0xd5, 0x23, 0x00, 0xa1, 0xd2, // dsb sy; movz x3,#0x0801<<16 (GICR)
    0x63, 0x40, 0x40, 0x91, 0x00, 0x00, 0xa1, 0x52, // add x3,#0x10<<12 (SGI frame); mov w0,#1<<27
    0x60, 0x80, 0x00, 0xb9, 0x7f, 0x18, 0x04, 0xb9, // str w0,[x3,#0x80] IGROUPR0; str wzr,[x3,#0x418] PRIO
    0x00, 0x00, 0xa1, 0x52, 0x60, 0x00, 0x01, 0xb9, // mov w0,#1<<27; str w0,[x3,#0x100] ISENABLER0
    0x9f, 0x3f, 0x03, 0xd5, 0xdf, 0x3f, 0x03, 0xd5, // dsb sy; isb
    0x07, 0x40, 0xa1, 0xd2, 0xff, 0x00, 0x00, 0xb9, // movz x7,#0x0a00<<16; str wzr,[x7] (READY)
    0x80, 0x00, 0xa0, 0xd2, 0x00, 0xe3, 0x1b, 0xd5, // movz x0,#0x4<<16 (0x40000); msr CNTV_TVAL_EL0,x0
    0x20, 0x00, 0x80, 0xd2, 0x20, 0xe3, 0x1b, 0xd5, // mov x0,#1; msr CNTV_CTL_EL0,x0 (enable)
    0xdf, 0x3f, 0x03, 0xd5, 0xff, 0x42, 0x03, 0xd5, // isb; msr DAIFClr,#2
    0x06, 0x00, 0xb0, 0xd2, 0xc6, 0x04, 0x00, 0xf1, // movz x6,#0x8000<<16; subs x6,x6,#1
    0xe1, 0xff, 0xff, 0x54, 0x01, 0x20, 0xa1, 0xd2, // b.ne spin; mov x1,#0x09000000
    0x40, 0xcc, 0x38, 0xd5, 0x00, 0x00, 0x62, 0xb2, // mrs x0,ICC_HPPIR1_EL1; orr x0,#0x40000000
    0x20, 0x00, 0x00, 0xb9, 0x20, 0xe3, 0x3b, 0xd5, // str w0,[x1]; mrs x0,CNTV_CTL_EL0
    0x00, 0x00, 0x62, 0xb2, 0x20, 0x00, 0x00, 0xb9, // orr x0,#0x40000000; str w0,[x1]
    0x00, 0xe3, 0x3b, 0xd5, 0x00, 0x00, 0x62, 0xb2, // mrs x0,CNTV_TVAL_EL0; orr x0,#0x40000000
    0x20, 0x00, 0x00, 0xb9, 0xe0, 0xcc, 0x38, 0xd5, // str w0,[x1]; mrs x0,ICC_IGRPEN1_EL1
    0x00, 0x00, 0x62, 0xb2, 0x20, 0x00, 0x00, 0xb9, // orr x0,#0x40000000; str w0,[x1]
    0x00, 0x01, 0x80, 0xd2, 0x00, 0x80, 0xb0, 0xf2, // mov x0,#8; movk x0,#0x8400,lsl#16
    0x02, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14, // hvc #0 (PSCI off); b .
];
// IRQ handler that masks CNTV before EOI so the timer cannot immediately re-fire.
#[rustfmt::skip]
const VT_IRQ_HANDLER: [u8; 32] = [
    0x00, 0xcc, 0x38, 0xd5, 0x01, 0x20, 0xa1, 0xd2, // mrs x0,ICC_IAR1_EL1; mov x1,#0x09000000
    0x20, 0x00, 0x00, 0xb9, 0x3f, 0xe3, 0x1b, 0xd5, // str w0,[x1]; msr CNTV_CTL_EL0,xzr
    0x20, 0xcc, 0x18, 0xd5, 0x00, 0x01, 0x80, 0xd2, // msr ICC_EOIR1_EL1,x0; mov x0,#8
    0x00, 0x80, 0xb0, 0xf2, 0x02, 0x00, 0x00, 0xd4, // movk x0,#0x8400,lsl#16; hvc #0
];

/// Records the first 32-bit MMIO write to `IRQ_MARKER` — the value the guest's
/// IRQ handler wrote (the acknowledged INTID) — and, on the guest's "GIC
/// configured" signal (`IRQ_READY`), asserts SPI 32 from the vCPU's OWNING
/// thread via `hv_gic_set_spi`. Injecting on the owning thread (inside the MMIO
/// exit handler) is what actually wires the pending SPI into this vCPU's
/// virtual CPU interface; a cross-thread assert updates distributor state but
/// never reaches the interface.
struct MarkerVmOps {
    marker: Mutex<Vec<u32>>,
    gic: Mutex<Option<Arc<Mutex<dyn hypervisor::arch::aarch64::gic::Vgic>>>>,
    injected: Mutex<bool>,
}

impl VmOps for MarkerVmOps {
    fn guest_mem_write(&self, _gpa: u64, buf: &[u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }
    fn guest_mem_read(&self, _gpa: u64, buf: &mut [u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }
    fn mmio_read(&self, _gpa: u64, data: &mut [u8]) -> VmOpsResult<()> {
        data.fill(0);
        Ok(())
    }
    fn mmio_write(&self, gpa: u64, data: &[u8]) -> VmOpsResult<()> {
        if gpa == IRQ_READY {
            // Owning-thread injection: the guest has finished configuring the
            // GIC and is about to unmask IRQs. Assert SPI 32 now.
            if let Some(gic) = self.gic.lock().unwrap().as_ref() {
                let mut guard = gic.lock().unwrap();
                let concrete = guard
                    .as_any_concrete_mut()
                    .downcast_mut::<hypervisor::hvf::gic::HvfGicV3>()
                    .expect("HVF GIC concrete type");
                concrete.set_spi(IRQ_SPI_INTID, true).expect("assert SPI 32");
                *self.injected.lock().unwrap() = true;
            }
        } else if gpa == IRQ_MARKER {
            let n = data.len().min(4);
            let mut v = [0u8; 4];
            v[..n].copy_from_slice(&data[..n]);
            self.marker.lock().unwrap().push(u32::from_le_bytes(v));
        }
        Ok(())
    }
}

/// Boot a real GICv3 guest, inject SPI 32 from the host via `hv_gic_set_spi`,
/// and prove the guest actually *took* the interrupt: its IRQ handler runs,
/// acknowledges INTID 32, records it through MMIO, EOIs, and powers off.
///
/// This converts the previously-UNVERIFIED interrupt-injection path into a
/// hardware-verified end-to-end delivery test.
#[test]
fn hvf_guest_takes_injected_spi() {
    let ram = HostRam::new(RAM_SIZE);
    load_irq_guest(&ram);

    let vm_ops = Arc::new(MarkerVmOps {
        marker: Mutex::new(Vec::new()),
        gic: Mutex::new(None),
        injected: Mutex::new(false),
    });

    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");
    // SAFETY: ram outlives the mapping.
    unsafe {
        vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
            .expect("map ram");
    }

    let config = irq_vgic_config();
    // GIC must be created before the vCPU.
    let gic = vm.create_vgic(&config).expect("create_vgic");
    // Hand the GIC to the VmOps so the guest's "configured" signal can assert
    // the SPI from the vCPU's owning thread (inside the MMIO exit handler).
    *vm_ops.gic.lock().unwrap() = Some(gic.clone());

    let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
    vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

    let exit = run_to_shutdown(vcpu.as_mut());
    let marker = vm_ops.marker.lock().unwrap().clone();
    assert!(
        *vm_ops.injected.lock().unwrap(),
        "guest never signalled GIC-configured / SPI was not injected"
    );
    assert!(
        matches!(exit, VmExit::Shutdown),
        "expected Shutdown after IRQ handler, got {exit:?}"
    );
    assert_eq!(
        marker.first().copied(),
        Some(IRQ_SPI_INTID),
        "guest IRQ handler did not run / acknowledged the wrong INTID"
    );
}

/// Boot the same GICv3 guest but deliver SPI 32 from a SEPARATE host thread
/// while the vCPU thread is blocked inside `hv_vcpu_run` executing the guest's
/// idle spin — the realistic device-model path (a device/IRQ thread asserting
/// an interrupt asynchronously, NOT the vCPU's owning thread inside an exit
/// handler). The injector sleeps briefly so the guest has reached its post-
/// unmask spin, then asserts SPI 32 via the shared `Arc<Mutex<dyn Vgic>>`.
///
/// This closes the M2 open question of whether `hv_gic_set_spi` reaches a
/// RUNNING vCPU's CPU interface cross-thread. A pass proves the managed GIC
/// forwards an asynchronously-asserted SPI into a vCPU that is live in the
/// kernel, which is the property every real device backend depends on.
#[test]
fn hvf_guest_takes_cross_thread_spi() {
    let ram = HostRam::new(RAM_SIZE);
    load_irq_guest(&ram);

    // gic = None: no owning-thread injection in the MMIO exit handler. The only
    // path to the interrupt is the cross-thread injector below.
    let vm_ops = Arc::new(MarkerVmOps {
        marker: Mutex::new(Vec::new()),
        gic: Mutex::new(None),
        injected: Mutex::new(false),
    });

    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");
    // SAFETY: ram outlives the mapping.
    unsafe {
        vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
            .expect("map ram");
    }

    let config = irq_vgic_config();
    let gic = vm.create_vgic(&config).expect("create_vgic");

    let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
    vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

    // Device-style injector: a different thread asserts the SPI while the vCPU
    // is live in hv_vcpu_run. `hv_gic_set_spi` is VM-global and thread-safe, so
    // no vCPU handle is needed. The shared GIC is Send+Sync.
    let injector_gic = gic.clone();
    let injector = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        let mut guard = injector_gic.lock().unwrap();
        let concrete = guard
            .as_any_concrete_mut()
            .downcast_mut::<hypervisor::hvf::gic::HvfGicV3>()
            .expect("HVF GIC concrete type");
        concrete
            .set_spi(IRQ_SPI_INTID, true)
            .expect("assert SPI 32 cross-thread");
    });

    let exit = run_to_shutdown(vcpu.as_mut());
    injector.join().expect("injector thread");
    let marker = vm_ops.marker.lock().unwrap().clone();
    assert!(
        matches!(exit, VmExit::Shutdown),
        "expected Shutdown after the cross-thread IRQ, got {exit:?} (marker={marker:#x?})"
    );
    assert_eq!(
        marker.first().copied(),
        Some(IRQ_SPI_INTID),
        "guest did not take the cross-thread SPI as INTID 32 (marker={marker:#x?})"
    );
}

/// Load the GICv3 interrupt guest into a fresh RAM image.
fn load_irq_guest(ram: &HostRam) {
    ram.load(0x0000, &IRQ_BOOT);
    ram.load(0x1000, &SYNC_VECTOR_0X000);
    ram.load(0x1200, &SYNC_VECTOR_0X200);
    ram.load(0x1280, &IRQ_VECTOR);
    ram.load(0x1700, &SYNC_HANDLER);
    ram.load(0x1800, &IRQ_HANDLER);
}

// Boot block of the WFI-idle variant (source: session notes wfi_guest.S). It is
// byte-identical to IRQ_BOOT through GIC setup + the IRQ unmask, then replaces
// the bounded spin with a real `wfi; b idle` loop so the vCPU genuinely parks
// in the kernel idle path. It shares the IRQ guest's vectors and handlers.
#[rustfmt::skip]
const WFI_BOOT: [u8; 152] = [
    0x00, 0x00, 0xa8, 0xd2, 0x00, 0x00, 0x42, 0x91,
    0x1f, 0x00, 0x00, 0x91, 0x01, 0x00, 0xa8, 0xd2,
    0x21, 0x04, 0x40, 0x91, 0x01, 0xc0, 0x18, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x20, 0x00, 0x80, 0xd2,
    0xa0, 0xcc, 0x18, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
    0x00, 0x1e, 0x80, 0xd2, 0x00, 0x46, 0x18, 0xd5,
    0x20, 0x00, 0x80, 0xd2, 0xe0, 0xcc, 0x18, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x02, 0x00, 0xa1, 0xd2,
    0x60, 0x02, 0x80, 0x52, 0x40, 0x00, 0x00, 0xb9,
    0x20, 0x00, 0x80, 0x52, 0x40, 0x84, 0x00, 0xb9,
    0x5f, 0x20, 0x04, 0xb9, 0x03, 0x20, 0x8c, 0xd2,
    0x43, 0x00, 0x03, 0x8b, 0xa4, 0x00, 0x38, 0xd5,
    0xe5, 0xff, 0x9f, 0xd2, 0xe5, 0x1f, 0xa0, 0xf2,
    0xe5, 0x1f, 0xc0, 0xf2, 0x84, 0x00, 0x05, 0x8a,
    0x64, 0x00, 0x00, 0xf9, 0x20, 0x00, 0x80, 0x52,
    0x40, 0x04, 0x01, 0xb9, 0x9f, 0x3f, 0x03, 0xd5,
    0xdf, 0x3f, 0x03, 0xd5, 0x07, 0x40, 0xa1, 0xd2,
    0xff, 0x00, 0x00, 0xb9, 0xff, 0x42, 0x03, 0xd5,
    0x7f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0x17, // wfi; b idle
];

/// Load the WFI-idle GICv3 guest (WFI boot block + the shared IRQ vectors).
fn load_wfi_guest(ram: &HostRam) {
    ram.load(0x0000, &WFI_BOOT);
    ram.load(0x1000, &SYNC_VECTOR_0X000);
    ram.load(0x1200, &SYNC_VECTOR_0X200);
    ram.load(0x1280, &IRQ_VECTOR);
    ram.load(0x1700, &SYNC_HANDLER);
    ram.load(0x1800, &IRQ_HANDLER);
}

fn irq_vgic_config() -> hypervisor::arch::aarch64::gic::VgicConfig {
    hypervisor::arch::aarch64::gic::VgicConfig {
        vcpu_count: 1,
        dist_addr: IRQ_GICD_BASE,
        dist_size: 0x1_0000,
        redists_addr: IRQ_REDIST_BASE,
        redists_size: 0x2_0000,
        msi_addr: 0,
        msi_size: 0,
        nr_irqs: 256,
    }
}

/// Prove a *pending, in-flight* interrupt survives an HVF snapshot/restore.
///
/// This is the rehydration property the whole port depends on: a guest captured
/// mid-flight with an interrupt asserted-but-not-yet-taken must, on restore,
/// still take that interrupt. Apple's managed GIC exposes its state only as an
/// opaque blob (`hv_gic_state`), so the open question is whether that blob
/// actually carries distributor/redistributor *pending* state — not just static
/// configuration. If it does not, KVM->HVF snapshot translation (M3) is
/// impossible; this test answers that question on real hardware.
///
/// Phase A boots the GICv3 guest just far enough to configure the distributor
/// and get SPI 32 asserted-pending (the host injects on the `IRQ_READY` signal,
/// which lands PC exactly on the guest's `DAIFClr` unmask), then snapshots the
/// vCPU and GIC *before* the guest unmasks — so the IRQ is pending but untaken.
/// Phase B restores both into a brand-new VM and runs: the guest must resume at
/// the unmask, take the SPI purely from restored GIC state (the host wires NO
/// re-injection in Phase B), acknowledge INTID 32, and power off.
#[test]
fn hvf_gic_pending_irq_survives_snapshot() {
    let config = irq_vgic_config();

    // Phase A: capture a vCPU + GIC snapshot with SPI 32 pending but untaken.
    let vcpu_snap: CpuState;
    let gic_snap: hypervisor::arch::aarch64::gic::GicState;
    {
        let ram = HostRam::new(RAM_SIZE);
        load_irq_guest(&ram);
        let vm_ops = Arc::new(MarkerVmOps {
            marker: Mutex::new(Vec::new()),
            gic: Mutex::new(None),
            injected: Mutex::new(false),
        });

        let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
        let vm = hv
            .create_vm(HypervisorVmConfig {
                nested: false,
                smt_enabled: false,
            })
            .expect("create_vm");
        // SAFETY: ram outlives the mapping.
        unsafe {
            vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
                .expect("map ram");
        }
        let gic = vm.create_vgic(&config).expect("create_vgic");
        // Wire the GIC so the guest's READY signal injects SPI 32 on the owning
        // thread (the proven owning-thread injection path).
        *vm_ops.gic.lock().unwrap() = Some(gic.clone());

        let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
        vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

        // Run until the guest signals READY (SPI 32 injected). Stop there: PC is
        // on the DAIFClr, the SPI is pending+enabled, and the guest has NOT yet
        // unmasked or taken it.
        loop {
            let exit = vcpu.run().expect("vcpu run");
            assert!(
                matches!(exit, VmExit::Ignore),
                "unexpected early exit {exit:?}"
            );
            if *vm_ops.injected.lock().unwrap() {
                break;
            }
        }
        assert!(
            vm_ops.marker.lock().unwrap().is_empty(),
            "guest took the IRQ before the snapshot point"
        );

        vcpu_snap = vcpu.state().expect("capture vCPU state");
        gic_snap = gic.lock().unwrap().state().expect("capture GIC state");
        // vm, gic, vcpu drop here: full teardown (hv_vcpu_destroy, hv_vm_destroy).
    }

    // Phase B: brand-new VM. Restore the snapshot and continue. The pending SPI
    // must come entirely from the restored GIC state — no host re-injection.
    {
        let ram = HostRam::new(RAM_SIZE);
        load_irq_guest(&ram);
        let vm_ops = Arc::new(MarkerVmOps {
            marker: Mutex::new(Vec::new()),
            gic: Mutex::new(None),
            injected: Mutex::new(false),
        });

        let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
        let vm = hv
            .create_vm(HypervisorVmConfig {
                nested: false,
                smt_enabled: false,
            })
            .expect("create_vm");
        // SAFETY: ram outlives the mapping.
        unsafe {
            vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
                .expect("map ram");
        }
        let gic = vm.create_vgic(&config).expect("create_vgic");
        // Deliberately leave vm_ops.gic = None: the restored PC is past the
        // READY store, so no injection should occur — and if it somehow did, a
        // None GIC means it cannot, keeping this an honest test of restored
        // pending state.

        let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
        // Restore the vCPU first: this re-establishes MPIDR affinity (which
        // hv_gic_set_state asserts on) and then the CPU-interface (ICC)
        // registers, before loading the GIC distributor/redistributor blob.
        vcpu.set_state(&vcpu_snap).expect("restore vCPU state");
        gic.lock()
            .unwrap()
            .set_state(&gic_snap)
            .expect("restore GIC state");

        let exit = run_to_shutdown(vcpu.as_mut());
        let marker = vm_ops.marker.lock().unwrap().clone();
        assert!(
            !*vm_ops.injected.lock().unwrap(),
            "Phase B must not re-inject; the pending SPI must come from restored state"
        );
        assert!(
            matches!(exit, VmExit::Shutdown),
            "expected Shutdown after the restored IRQ, got {exit:?}"
        );
        assert_eq!(
            marker.first().copied(),
            Some(IRQ_SPI_INTID),
            "restored guest did not take the snapshot's pending SPI (marker={marker:#x?})"
        );
    }
}

/// Prove the KVM⇄HVF register translation (M3) preserves a *real, executable*
/// vCPU state on this Mac — the foundation of rehydrating a cloud arm64 KVM
/// snapshot locally.
///
/// Same shape as `hvf_gic_pending_irq_survives_snapshot`, but in Phase B the
/// captured HVF vCPU state is lowered to its KVM ONE_REG representation
/// (`lower_to_kvm`) and raised back (`raise_from_kvm`) before restore. If the
/// translation drops or corrupts any load-bearing register — a GPR, PC, PSTATE,
/// SP, an EL1 system register, or a per-vCPU GIC CPU-interface (ICC) register —
/// the restored guest would fault or fail to take the pending SPI. It instead
/// resumes at the unmask, takes INTID 32 purely from translated+restored state,
/// and powers off. (The GIC distributor/redistributor blob is restored
/// unchanged; its KVM-format translation is the remaining M3 work.)
#[test]
fn hvf_kvm_register_translation_roundtrip() {
    use hypervisor::hvf::translate::{lower_to_kvm, raise_from_kvm};

    let config = irq_vgic_config();

    // Phase A: capture a vCPU + GIC snapshot with SPI 32 pending but untaken.
    let vcpu_snap: CpuState;
    let gic_snap: hypervisor::arch::aarch64::gic::GicState;
    {
        let ram = HostRam::new(RAM_SIZE);
        load_irq_guest(&ram);
        let vm_ops = Arc::new(MarkerVmOps {
            marker: Mutex::new(Vec::new()),
            gic: Mutex::new(None),
            injected: Mutex::new(false),
        });

        let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
        let vm = hv
            .create_vm(HypervisorVmConfig {
                nested: false,
                smt_enabled: false,
            })
            .expect("create_vm");
        // SAFETY: ram outlives the mapping.
        unsafe {
            vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
                .expect("map ram");
        }
        let gic = vm.create_vgic(&config).expect("create_vgic");
        *vm_ops.gic.lock().unwrap() = Some(gic.clone());

        let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
        vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

        loop {
            let exit = vcpu.run().expect("vcpu run");
            assert!(matches!(exit, VmExit::Ignore), "unexpected early exit {exit:?}");
            if *vm_ops.injected.lock().unwrap() {
                break;
            }
        }
        assert!(
            vm_ops.marker.lock().unwrap().is_empty(),
            "guest took the IRQ before the snapshot point"
        );

        vcpu_snap = vcpu.state().expect("capture vCPU state");
        gic_snap = gic.lock().unwrap().state().expect("capture GIC state");
    }

    // Translate the captured HVF vCPU state through the KVM representation.
    #[allow(irrefutable_let_patterns)]
    let CpuState::Hvf(hvf_state) = vcpu_snap
    else {
        panic!("expected an HVF CpuState");
    };
    let kvm = lower_to_kvm(&hvf_state);
    // Sanity: the translation actually carried the GIC CPU-interface state that
    // makes the pending SPI deliverable (PMR/IGRPEN1 live in the ICC block).
    assert!(
        !kvm.gic_icc.is_empty(),
        "translation lost the per-vCPU GIC ICC registers"
    );
    let translated = CpuState::Hvf(raise_from_kvm(&kvm));

    // Phase B: brand-new VM. Restore the TRANSLATED vCPU state + the GIC blob.
    {
        let ram = HostRam::new(RAM_SIZE);
        load_irq_guest(&ram);
        let vm_ops = Arc::new(MarkerVmOps {
            marker: Mutex::new(Vec::new()),
            gic: Mutex::new(None),
            injected: Mutex::new(false),
        });

        let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
        let vm = hv
            .create_vm(HypervisorVmConfig {
                nested: false,
                smt_enabled: false,
            })
            .expect("create_vm");
        // SAFETY: ram outlives the mapping.
        unsafe {
            vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
                .expect("map ram");
        }
        let gic = vm.create_vgic(&config).expect("create_vgic");

        let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
        vcpu.set_state(&translated)
            .expect("restore translated vCPU state");
        gic.lock()
            .unwrap()
            .set_state(&gic_snap)
            .expect("restore GIC state");

        let exit = run_to_shutdown(vcpu.as_mut());
        let marker = vm_ops.marker.lock().unwrap().clone();
        assert!(
            !*vm_ops.injected.lock().unwrap(),
            "Phase B must not re-inject; delivery must come from translated state"
        );
        assert!(
            matches!(exit, VmExit::Shutdown),
            "expected Shutdown after the translated+restored IRQ, got {exit:?}"
        );
        assert_eq!(
            marker.first().copied(),
            Some(IRQ_SPI_INTID),
            "translated guest did not take the pending SPI (marker={marker:#x?})"
        );
    }
}

/// Load the virtual-timer guest into a fresh RAM image. Shares the SPI guest's
/// exception vectors and synchronous-fault reporter (byte-identical); only the
/// boot block and IRQ handler differ.
fn load_vtimer_guest(ram: &HostRam) {
    ram.load(0x0000, &VT_BOOT);
    ram.load(0x1000, &SYNC_VECTOR_0X000);
    ram.load(0x1200, &SYNC_VECTOR_0X200);
    ram.load(0x1280, &IRQ_VECTOR);
    ram.load(0x1700, &SYNC_HANDLER);
    ram.load(0x1800, &VT_IRQ_HANDLER);
}

/// Prove the EL1 virtual timer is delivered to a guest as GIC PPI 27.
///
/// A real kernel arms the arch virtual timer within the first instants of boot
/// and relies on taking its interrupt to schedule, so timer-PPI delivery is the
/// gateway to booting anything real. This guest enables PPI 27 in its own
/// redistributor SGI frame via MMIO (exercising guest redistributor access on
/// the managed GIC), arms `CNTV_TVAL_EL0`/`CNTV_CTL_EL0`, unmasks IRQs and
/// spins. The test asserts the guest takes the timer through the GIC —
/// acknowledging INTID 27 (not the spurious 1023 a raw IRQ line would yield) —
/// then masks the timer, EOIs and powers off.
#[test]
fn hvf_guest_takes_virtual_timer() {
    let ram = HostRam::new(RAM_SIZE);
    load_vtimer_guest(&ram);

    let vm_ops = Arc::new(MarkerVmOps {
        marker: Mutex::new(Vec::new()),
        gic: Mutex::new(None),
        injected: Mutex::new(false),
    });

    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");
    // SAFETY: ram outlives the mapping.
    unsafe {
        vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
            .expect("map ram");
    }

    let config = irq_vgic_config();
    let _gic = vm.create_vgic(&config).expect("create_vgic");

    let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
    vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

    let exit = run_to_shutdown(vcpu.as_mut());
    let marker = vm_ops.marker.lock().unwrap().clone();
    assert!(
        matches!(exit, VmExit::Shutdown),
        "expected Shutdown after the timer IRQ, got {exit:?} (marker={marker:#x?})"
    );
    assert_eq!(
        marker.first().copied(),
        Some(27),
        "guest did not take the virtual timer as GIC INTID 27 (marker={marker:#x?})"
    );
}

/// Run until the guest powers off or `deadline` elapses. Unlike
/// `run_to_shutdown` (a fixed step budget), this bounds by wall-clock so a
/// vCPU parked in the WFI idle path cannot turn a failure into a multi-minute
/// hang: each `run()` may block up to the backend's WFI poll interval.
fn run_to_shutdown_deadline(vcpu: &mut dyn Vcpu, deadline: Duration) -> VmExit {
    let start = std::time::Instant::now();
    loop {
        match vcpu.run().expect("vcpu run") {
            VmExit::Ignore => {
                if start.elapsed() > deadline {
                    panic!("guest did not power off within {deadline:?}");
                }
            }
            other => return other,
        }
    }
}

/// Prove the WFI idle + cross-thread wakeup path end to end on this Mac.
///
/// The guest configures the GIC, unmasks IRQs and parks in a real `wfi` loop —
/// so the vCPU thread genuinely blocks in the HVF backend's idle path (EC_WFX
/// -> wait on the wake fd), NOT a busy spin. A separate injector thread then
/// asserts SPI 32 cross-thread via the shared GIC and `write()`s the vCPU's
/// wake handle. The parked vCPU wakes, re-enters the guest, takes INTID 32,
/// records it and powers off.
///
/// This closes the last M2 device-model gap: an asynchronously-asserted
/// interrupt waking a vCPU that is idle in WFI — the property every real
/// device backend (and the eventual irqfd/vmm event loop) depends on.
#[test]
fn hvf_guest_wfi_woken_by_cross_thread_irq() {
    let ram = HostRam::new(RAM_SIZE);
    load_wfi_guest(&ram);

    // gic = None: no owning-thread injection. The only path to the interrupt is
    // the cross-thread injector, which must also wake the parked vCPU.
    let vm_ops = Arc::new(MarkerVmOps {
        marker: Mutex::new(Vec::new()),
        gic: Mutex::new(None),
        injected: Mutex::new(false),
    });

    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");
    // SAFETY: ram outlives the mapping.
    unsafe {
        vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
            .expect("map ram");
    }

    let config = irq_vgic_config();
    let gic = vm.create_vgic(&config).expect("create_vgic");

    let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
    vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

    // Obtain the vCPU's wake handle before running. A device/IRQ thread holds it
    // alongside the GIC and signals it right after asserting an interrupt.
    let wake = vcpu
        .as_any_concrete_mut()
        .downcast_mut::<hypervisor::hvf::HvfVcpu>()
        .expect("HVF vCPU concrete type")
        .wake_handle();

    let injector_gic = gic.clone();
    let injector = thread::spawn(move || {
        // Let the guest reach its WFI park first.
        thread::sleep(Duration::from_millis(150));
        {
            let mut guard = injector_gic.lock().unwrap();
            let concrete = guard
                .as_any_concrete_mut()
                .downcast_mut::<hypervisor::hvf::gic::HvfGicV3>()
                .expect("HVF GIC concrete type");
            concrete
                .set_spi(IRQ_SPI_INTID, true)
                .expect("assert SPI 32 cross-thread");
        }
        // Wake the parked vCPU thread.
        wake.write(1).expect("kick vCPU wake fd");
    });

    let exit = run_to_shutdown_deadline(vcpu.as_mut(), Duration::from_secs(5));
    injector.join().expect("injector thread");
    let marker = vm_ops.marker.lock().unwrap().clone();
    assert!(
        matches!(exit, VmExit::Shutdown),
        "expected Shutdown after the WFI wakeup IRQ, got {exit:?} (marker={marker:#x?})"
    );
    assert_eq!(
        marker.first().copied(),
        Some(IRQ_SPI_INTID),
        "guest did not take the cross-thread SPI as INTID 32 after WFI (marker={marker:#x?})"
    );
}

/// Prove on real hardware that the GIC distributor + redistributor halves of a
/// REAL cloud-hypervisor KVM snapshot can be rehydrated field-by-field through
/// Apple's per-register API — NO opaque `hv_gic` state blob required.
///
/// This is the empirical answer to "can we work the GIC blob out without
/// reverse-engineering Apple's private layout?": yes. KVM dumps the
/// distributor/redistributor register space as `dist`/`rdist` u32 vectors;
/// `gic_ingest::{dist_to_hvf,redist_to_hvf}` re-walk them onto the architectural
/// GICD/GICR offsets, which ARE Apple's `hv_gic_{distributor,redistributor}_reg_t`
/// enum values. Here we translate the committed real-snapshot fixture, write
/// every pair into a live managed GIC via `set_distributor_reg` /
/// `HvfVcpu::set_redistributor_reg`, read them back, and assert the load-bearing
/// interrupt-routing state survived — including PPI 27 (the EL1 virtual timer
/// M2 proved a restored guest must keep) in the per-vCPU redistributor.
///
/// Writes are applied in the translator's emission order (which mirrors KVM's
/// restore order: ICENABLER before ISENABLER, etc.) so the set/clear-register
/// aliasing resolves to the captured enable state.
#[cfg(feature = "kvm-snapshot")]
#[test]
fn hvf_gic_dist_redist_per_register_rehydration() {
    use hypervisor::hvf::gic::HvfGicV3;
    use hypervisor::hvf::translate::gic_ingest::{dist_to_hvf, redist_to_hvf};

    // Parse the REAL captured GIC node (same fixture the unit tests use).
    let gic_json = include_str!("data/kvm_arm64_gic.json");
    let v: serde_json::Value = serde_json::from_str(gic_json).expect("parse gic fixture");
    let to_u32 = |k: &str| -> Vec<u32> {
        v["Kvm"][k]
            .as_array()
            .expect("array field")
            .iter()
            .map(|n| n.as_u64().expect("u64") as u32)
            .collect()
    };
    let dist = to_u32("dist");
    let rdist = to_u32("rdist");

    let dist_pairs = dist_to_hvf(&dist).expect("translate distributor dump");
    let redist_pairs = redist_to_hvf(&rdist).expect("translate redistributor dump");

    // Bring up a live managed GICv3 + one vCPU (the redistributor is keyed by
    // the vCPU's MPIDR affinity, which setup_regs establishes).
    let ram = HostRam::new(RAM_SIZE);
    let config = irq_vgic_config();
    let vm_ops = Arc::new(RecordingVmOps {
        writes: Mutex::new(Vec::new()),
    });

    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .expect("create_vm");
    // SAFETY: ram outlives the mapping.
    unsafe {
        vm.create_user_memory_region(0, RAM_BASE, ram.size, ram.ptr, false, false)
            .expect("map ram");
    }
    let gic = vm.create_vgic(&config).expect("create_vgic");
    let mut vcpu = vm.create_vcpu(0, Some(vm_ops.clone())).expect("create_vcpu");
    vcpu.setup_regs(0, RAM_BASE, 0).expect("setup_regs");

    // --- Distributor: write every translated pair, then read load-bearing regs.
    {
        let mut guard = gic.lock().unwrap();
        let concrete = guard
            .as_any_concrete_mut()
            .downcast_mut::<HvfGicV3>()
            .expect("HVF GIC concrete type");

        let mut write_failures = Vec::new();
        for &(reg, val) in &dist_pairs {
            if concrete.set_distributor_reg(reg, val).is_err() {
                write_failures.push(reg);
            }
        }
        assert!(
            write_failures.is_empty(),
            "GIC rejected distributor writes at offsets {write_failures:#x?}"
        );

        // GICD_IGROUPR1 (0x84): SPIs 32..63 routed to group 1 (non-secure).
        assert_eq!(
            concrete.distributor_reg(0x84).expect("read GICD_IGROUPR1") as u32,
            0xffff_ffff,
            "GICD_IGROUPR1 group routing did not survive rehydration"
        );
        // GICD_ISENABLER1 (0x104): virtio SPIs 42/43 enabled in the live guest.
        assert_eq!(
            concrete.distributor_reg(0x104).expect("read GICD_ISENABLER1") as u32,
            0xc00,
            "GICD_ISENABLER1 enable state did not survive rehydration"
        );
        // GICD_IPRIORITYR8 (0x420): first SPI priority block (0xa0 each).
        assert_eq!(
            concrete.distributor_reg(0x420).expect("read GICD_IPRIORITYR8") as u32,
            0xa0a0_a0a0,
            "GICD_IPRIORITYR8 priorities did not survive rehydration"
        );
        // GICD_IROUTER32 (0x6100): the first SPI's 64-bit affinity route.
        let expected_irouter = dist_pairs
            .iter()
            .find(|&&(reg, _)| reg == 0x6100)
            .map(|&(_, v)| v)
            .expect("IROUTER32 present in translation");
        assert_eq!(
            concrete.distributor_reg(0x6100).expect("read GICD_IROUTER32"),
            expected_irouter,
            "GICD_IROUTER32 affinity route did not survive rehydration"
        );
    }

    // --- Redistributor: per-vCPU, written through the vCPU's own handle.
    {
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<hypervisor::hvf::HvfVcpu>()
            .expect("HVF vCPU concrete type");

        let mut write_failures = Vec::new();
        for &(reg, val) in &redist_pairs {
            if concrete.set_redistributor_reg(reg, val).is_err() {
                write_failures.push(reg);
            }
        }
        assert!(
            write_failures.is_empty(),
            "GIC rejected redistributor writes at offsets {write_failures:#x?}"
        );

        // GICR_IGROUPR0 (0x10080): all SGIs/PPIs group 1.
        assert_eq!(
            concrete.redistributor_reg(0x10080).expect("read GICR_IGROUPR0") as u32,
            0xffff_ffff,
            "GICR_IGROUPR0 group routing did not survive rehydration"
        );
        // GICR_ISENABLER0 (0x10100): SGIs 0..7 (0xff) AND PPI 27 (bit 27) — the
        // EL1 virtual-timer interrupt M2 proved a restored guest must keep.
        assert_eq!(
            concrete.redistributor_reg(0x10100).expect("read GICR_ISENABLER0") as u32,
            0x0800_00ff,
            "GICR_ISENABLER0 (SGIs + PPI27 vtimer) did not survive rehydration"
        );
        // GICR_IPRIORITYR0 (0x10400): first SGI/PPI priority block.
        assert_eq!(
            concrete.redistributor_reg(0x10400).expect("read GICR_IPRIORITYR0") as u32,
            0xa0a0_a0a0,
            "GICR_IPRIORITYR0 priorities did not survive rehydration"
        );
    }
}

// ===================================================================
// M4: end-to-end rehydration of a REAL cloud-hypervisor KVM snapshot.
// ===================================================================

/// VmOps that records every device (MMIO) access the rehydrated guest makes —
/// the observation point that proves it is executing real captured code.
#[cfg(feature = "kvm-snapshot")]
struct DeviceTraceVmOps {
    /// (gpa, is_write) for each access, in order.
    accesses: Mutex<Vec<(u64, bool)>>,
}

#[cfg(feature = "kvm-snapshot")]
impl VmOps for DeviceTraceVmOps {
    fn guest_mem_write(&self, _gpa: u64, buf: &[u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }
    fn guest_mem_read(&self, _gpa: u64, buf: &mut [u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }
    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> VmOpsResult<()> {
        self.accesses.lock().unwrap().push((gpa, false));
        // Return all-ones for ID/status registers so the firmware/kernel device
        // probe makes forward progress instead of spinning on a zero read.
        data.fill(0);
        Ok(())
    }
    fn mmio_write(&self, gpa: u64, data: &[u8]) -> VmOpsResult<()> {
        self.accesses.lock().unwrap().push((gpa, true));
        let _ = data;
        Ok(())
    }
}

/// Rehydrate a REAL cloud-hypervisor arm64 KVM snapshot on this Mac and prove
/// the reconstructed vCPU executes its real captured guest code from the real
/// captured 1 GiB of guest RAM.
///
/// This is the end-to-end payoff of the port: it loads the captured guest RAM,
/// rebuilds the GICv3 (distributor + per-vCPU redistributor + CPU interface)
/// and the vCPU register file purely from the snapshot's KVM-format state via
/// `hvf::rehydrate`, then resumes. A correctly-translated guest runs its real
/// code with the MMU on (virtual addresses resolving through the restored
/// TTBRs/SCTLR) until it touches a device this minimal harness does not model —
/// at which point the access traps to `DeviceTraceVmOps`, giving concrete
/// evidence of live execution. A broken translation would instead fault
/// immediately at a bogus PC or never reach a device.
///
/// The 1 GiB memory image is far too large to commit, so the test is gated on
/// `CH_SNAPSHOT_DIR` pointing at a snapshot directory laid out as
/// `state.json` + `snapshot/memory-ranges` (what `scripts/hvf` captures). It is
/// skipped (passes trivially) when the variable is unset.
#[cfg(feature = "kvm-snapshot")]
#[test]
fn hvf_rehydrate_real_cloud_snapshot_executes() {
    use std::path::PathBuf;

    use hypervisor::hvf::rehydrate::{rehydrate, Snapshot};

    let Ok(dir) = std::env::var("CH_SNAPSHOT_DIR") else {
        eprintln!("CH_SNAPSHOT_DIR unset; skipping real-snapshot rehydration test");
        return;
    };
    let dir = PathBuf::from(dir);
    let state_json = std::fs::read_to_string(dir.join("state.json")).expect("read state.json");
    let mem_ranges = dir.join("snapshot").join("memory-ranges");

    // --- Parse + translate the whole snapshot (CPU + GIC + memory layout). ---
    let snap = Snapshot::from_state_json(&state_json).expect("parse snapshot");
    assert!(snap.num_vcpus() >= 1, "snapshot has no vCPUs");
    assert!(
        !snap.mem_mappings.is_empty(),
        "snapshot has no guest-RAM mappings"
    );
    let total_ram: u64 = snap.mem_mappings.iter().map(|m| m.size).sum();
    eprintln!(
        "rehydrating: {} vCPU(s), {} GiB guest RAM, {}-IRQ GICv3",
        snap.num_vcpus(),
        total_ram >> 30,
        snap.num_irq
    );

    // --- Rebuild the live VM from the snapshot. ------------------------------
    let hv = hypervisor::new().expect("hypervisor::new() — is the test binary codesigned?");
    let tracer = Arc::new(DeviceTraceVmOps {
        accesses: Mutex::new(Vec::new()),
    });
    let vm_ops: Arc<dyn VmOps> = tracer.clone();
    let mut rvm = rehydrate(hv.as_ref(), &snap, &mem_ranges, &vm_ops).expect("rehydrate VM");
    assert_eq!(rvm.vcpus.len(), snap.num_vcpus() as usize);

    // Capture the restored entry PC — execution must begin exactly here.
    let entry_pc = match rvm.vcpus[0].state().expect("read restored state") {
        CpuState::Hvf(s) => s.pc,
        #[allow(unreachable_patterns)]
        _ => panic!("expected HVF CpuState"),
    };
    eprintln!("restored vCPU0 entry PC = {entry_pc:#x}");

    // --- Resume vCPU0 and watch it execute real guest code. -----------------
    let vcpu = rvm.vcpus[0].as_mut();
    let mut steps = 0u64;
    let mut shutdown = false;
    for _ in 0..200_000 {
        steps += 1;
        match vcpu.run().expect("rehydrated vCPU run") {
            VmExit::Ignore => {}
            VmExit::Shutdown | VmExit::Reset => {
                shutdown = true;
                break;
            }
            other => panic!("unexpected exit from rehydrated guest: {other:?}"),
        }
        // Stop as soon as we have solid evidence of device-level execution.
        if tracer.accesses.lock().unwrap().len() >= 8 {
            break;
        }
    }

    let trace = tracer.accesses.lock().unwrap().clone();
    eprintln!(
        "executed {steps} guest entries; {} device access(es); first few: {:#x?}",
        trace.len(),
        &trace[..trace.len().min(8)]
    );

    // The rehydrated guest must have made progress: either it touched a device
    // (the overwhelmingly common case for a running OS — UART/RTC/virtio/PCI in
    // the MMIO window below the 0x4000_0000 RAM base) or it cleanly powered off.
    // Either outcome proves it executed real, translated guest state rather than
    // faulting on a corrupt register file.
    assert!(
        !trace.is_empty() || shutdown,
        "rehydrated guest neither accessed a device nor halted after {steps} entries \
         (entry PC was {entry_pc:#x}) — translation or memory restore is wrong"
    );
    if let Some(&(gpa, _)) = trace.first() {
        assert!(
            gpa < RAM_BASE,
            "first device access at {gpa:#x} is inside the RAM window — unexpected"
        );
    }
}

/// Documents the Apple managed-GIC base-address ordering constraint that drives
/// the GIC relocation in [`hypervisor::hvf::rehydrate`].
///
/// Empirically (verified on macOS 26.x / Apple Silicon), `hv_gic_create`
/// returns `HV_BAD_ARGUMENT` unless the redistributor base sits **above** the
/// distributor base. cloud-hypervisor's arm64 map places the redistributors
/// *below* the distributor, so the managed GIC cannot be created at the guest's
/// original addresses — hence `Snapshot::vgic_config` relocates it. This test
/// pins that behaviour so a future SDK change (or a regression in our config
/// plumbing) is caught.
#[cfg(feature = "kvm-snapshot")]
#[test]
fn hvf_gic_requires_redist_above_dist() {
    use hypervisor::arch::aarch64::gic::VgicConfig;

    let mk = |dist: u64, redist: u64, rsize: u64| VgicConfig {
        vcpu_count: 1,
        dist_addr: dist,
        dist_size: 0x1_0000,
        redists_addr: redist,
        redists_size: rsize,
        msi_addr: 0,
        msi_size: 0,
        nr_irqs: 256,
    };

    // (dist, redist, redist_size, expect_ok)
    let cases: &[(u64, u64, u64, bool)] = &[
        (0x0800_0000, 0x0801_0000, 0x2_0000, true), // redist above dist -> OK
        (0x08ff_0000, 0x08fd_0000, 0x2_0000, false), // cloud layout (redist below) -> reject
        (0x08fd_0000, 0x08ff_0000, 0x2_0000, true), // redist above dist -> OK
    ];

    for &(dist, redist, rsize, expect_ok) in cases {
        let hv = hypervisor::new().expect("hv new");
        let vm = hv
            .create_vm(HypervisorVmConfig {
                nested: false,
                smt_enabled: false,
            })
            .expect("create_vm");
        let ok = vm.create_vgic(&mk(dist, redist, rsize)).is_ok();
        assert_eq!(
            ok, expect_ok,
            "hv_gic_create(dist={dist:#x}, redist={redist:#x}, rsize={rsize:#x}) \
             expected ok={expect_ok}, got ok={ok}"
        );
    }
}
