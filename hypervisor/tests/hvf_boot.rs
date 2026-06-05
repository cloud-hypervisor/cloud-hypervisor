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
