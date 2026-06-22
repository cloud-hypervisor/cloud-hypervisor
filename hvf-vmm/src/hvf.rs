//! Safe-ish Rust wrappers over Apple's Hypervisor.framework (arm64).
//!
//! This is the Phase 2 backend core. The types here mirror the shape of the
//! `hypervisor` crate's `Vm`/`Vcpu` traits so the logic can be lifted into
//! `hypervisor/src/hvf/` during real integration. See INTEGRATION.md.

use std::ffi::c_void;
use std::ptr;

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct HvVcpuExitException {
    pub syndrome: u64,        // ESR_ELx
    pub virtual_address: u64, // FAR_ELx
    pub physical_address: u64, // faulting IPA (stage-2)
}

#[repr(C)]
pub struct HvVcpuExit {
    pub reason: u32,
    pub exception: HvVcpuExitException,
}

// hv_reg_t
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_CPSR: u32 = 34;

// hv_exit_reason_t
pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

// hv_memory_flags_t
pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    fn hv_vm_create(config: *mut c_void) -> i32;
    fn hv_vm_destroy() -> i32;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> i32;
    #[allow(dead_code)] // part of the Vm API surface for the real port
    fn hv_vm_unmap(ipa: u64, size: usize) -> i32;
    fn hv_vcpu_create(vcpu: *mut u64, exit: *mut *mut HvVcpuExit, config: *mut c_void) -> i32;
    fn hv_vcpu_destroy(vcpu: u64) -> i32;
    fn hv_vcpu_set_reg(vcpu: u64, reg: u32, value: u64) -> i32;
    fn hv_vcpu_get_reg(vcpu: u64, reg: u32, value: *mut u64) -> i32;
    fn hv_vcpu_set_sys_reg(vcpu: u64, reg: u16, value: u64) -> i32;
    fn hv_vcpu_get_sys_reg(vcpu: u64, reg: u16, value: *mut u64) -> i32;
    fn hv_vcpu_run(vcpu: u64) -> i32;
}

// libSystem mmap (avoid pulling in the libc crate)
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_PRIVATE: i32 = 0x0002;
const MAP_ANON: i32 = 0x1000;
unsafe extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: i64)
        -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

pub type HvResult<T> = Result<T, HvError>;

#[derive(Debug)]
pub struct HvError {
    pub op: &'static str,
    pub code: i32,
}
impl std::fmt::Display for HvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: hv_return_t={:#010x}", self.op, self.code as u32)
    }
}
impl std::error::Error for HvError {}

fn hv(op: &'static str, code: i32) -> HvResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(HvError { op, code })
    }
}

// ---------------------------------------------------------------------------
// Guest RAM
// ---------------------------------------------------------------------------

/// A host-backed, page-aligned region of guest RAM.
pub struct GuestRam {
    host: *mut c_void,
    pub base: u64,
    pub size: usize,
}

impl GuestRam {
    pub fn new(base: u64, size: usize) -> HvResult<Self> {
        // SAFETY: standard anonymous RW mmap; result validated below.
        let host = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if host.is_null() || host == usize::MAX as *mut c_void {
            return Err(HvError { op: "mmap", code: -1 });
        }
        Ok(GuestRam { host, base, size })
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `host` is valid for `size` bytes for the lifetime of self.
        unsafe { std::slice::from_raw_parts(self.host as *const u8, self.size) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: exclusive borrow; `host` valid for `size` bytes.
        unsafe { std::slice::from_raw_parts_mut(self.host as *mut u8, self.size) }
    }

    /// Read a guest register value by GPR index (0..=30) helper lives on Vcpu;
    /// this writes bytes at a guest-physical address into RAM.
    #[allow(dead_code)] // convenience for the real port's device DMA paths
    pub fn write_phys(&mut self, gpa: u64, data: &[u8]) {
        let off = (gpa - self.base) as usize;
        self.as_mut_slice()[off..off + data.len()].copy_from_slice(data);
    }
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        // SAFETY: unmapping our own mapping exactly once.
        unsafe {
            munmap(self.host, self.size);
        }
    }
}

// ---------------------------------------------------------------------------
// VM
// ---------------------------------------------------------------------------

/// One VM per process (an HVF constraint). Guards create/destroy lifetime.
pub struct Vm {
    _priv: (),
}

impl Vm {
    pub fn create() -> HvResult<Self> {
        // SAFETY: FFI; NULL config => default.
        hv("hv_vm_create", unsafe { hv_vm_create(ptr::null_mut()) })?;
        Ok(Vm { _priv: () })
    }

    /// Map a region of host-backed guest RAM into the guest physical space.
    pub fn map_ram(&self, ram: &GuestRam, flags: u64) -> HvResult<()> {
        // SAFETY: ram.host valid for ram.size; ipa/size page aligned by construction.
        hv("hv_vm_map", unsafe {
            hv_vm_map(ram.host, ram.base, ram.size, flags)
        })
    }

    #[allow(dead_code)] // part of the Vm API surface for the real port
    pub fn unmap(&self, ipa: u64, size: usize) -> HvResult<()> {
        // SAFETY: FFI.
        hv("hv_vm_unmap", unsafe { hv_vm_unmap(ipa, size) })
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // SAFETY: all vCPUs must already be destroyed (we enforce by ordering).
        unsafe {
            hv_vm_destroy();
        }
    }
}

// ---------------------------------------------------------------------------
// vCPU
// ---------------------------------------------------------------------------

/// System registers we snapshot/restore. This curated EL1 set is the analogue
/// of KVM's ONE_REG list and is where real KVM->HVF state translation plugs in.
pub const SNAPSHOT_SYS_REGS: &[(u16, &str)] = &[
    (0x8012, "MDSCR_EL1"),
    (0xc080, "SCTLR_EL1"),
    (0xc082, "CPACR_EL1"),
    (0xc100, "TTBR0_EL1"),
    (0xc101, "TTBR1_EL1"),
    (0xc102, "TCR_EL1"),
    (0xc200, "SPSR_EL1"),
    (0xc201, "ELR_EL1"),
    (0xc208, "SP_EL0"),
    (0xc290, "ESR_EL1"),
    (0xc300, "FAR_EL1"),
    (0xc510, "MAIR_EL1"),
    (0xc600, "VBAR_EL1"),
    (0xc684, "TPIDR_EL1"),
    (0xde82, "TPIDR_EL0"),
    (0xde83, "TPIDRRO_EL0"),
    (0xe208, "SP_EL1"),
];

/// Architectural vCPU state — backend-neutral, the unit of snapshot/restore.
#[derive(Clone)]
pub struct VcpuState {
    pub gpr: [u64; 31], // x0..x30
    pub pc: u64,
    pub cpsr: u64,
    pub sysregs: Vec<(u16, u64)>,
}

pub struct Vcpu {
    id: u64,
    exit: *mut HvVcpuExit,
}

impl Vcpu {
    pub fn create() -> HvResult<Self> {
        let mut id: u64 = 0;
        let mut exit: *mut HvVcpuExit = ptr::null_mut();
        // SAFETY: out-params valid; must be called on the running thread.
        hv("hv_vcpu_create", unsafe {
            hv_vcpu_create(&mut id, &mut exit, ptr::null_mut())
        })?;
        Ok(Vcpu { id, exit })
    }

    pub fn set_reg(&self, reg: u32, val: u64) -> HvResult<()> {
        hv("hv_vcpu_set_reg", unsafe { hv_vcpu_set_reg(self.id, reg, val) })
    }
    pub fn get_reg(&self, reg: u32) -> HvResult<u64> {
        let mut v = 0u64;
        hv("hv_vcpu_get_reg", unsafe {
            hv_vcpu_get_reg(self.id, reg, &mut v)
        })?;
        Ok(v)
    }
    pub fn set_sys_reg(&self, reg: u16, val: u64) -> HvResult<()> {
        hv("hv_vcpu_set_sys_reg", unsafe {
            hv_vcpu_set_sys_reg(self.id, reg, val)
        })
    }
    pub fn get_sys_reg(&self, reg: u16) -> HvResult<u64> {
        let mut v = 0u64;
        hv("hv_vcpu_get_sys_reg", unsafe {
            hv_vcpu_get_sys_reg(self.id, reg, &mut v)
        })?;
        Ok(v)
    }

    pub fn get_gpr(&self, idx: u32) -> HvResult<u64> {
        self.get_reg(idx)
    }

    /// Run until the next exit and return the raw exit record.
    pub fn run(&mut self) -> HvResult<&HvVcpuExit> {
        hv("hv_vcpu_run", unsafe { hv_vcpu_run(self.id) })?;
        // SAFETY: `exit` is owned by HVF and valid until the next run() call.
        Ok(unsafe { &*self.exit })
    }

    /// Capture full architectural state (analogue of `Vcpu::state()`).
    pub fn capture_state(&self) -> HvResult<VcpuState> {
        let mut gpr = [0u64; 31];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = self.get_reg(i as u32)?;
        }
        let pc = self.get_reg(HV_REG_PC)?;
        let cpsr = self.get_reg(HV_REG_CPSR)?;
        let mut sysregs = Vec::with_capacity(SNAPSHOT_SYS_REGS.len());
        for &(id, _name) in SNAPSHOT_SYS_REGS {
            sysregs.push((id, self.get_sys_reg(id)?));
        }
        Ok(VcpuState {
            gpr,
            pc,
            cpsr,
            sysregs,
        })
    }

    /// Restore full architectural state (analogue of `Vcpu::set_state()`).
    pub fn restore_state(&self, s: &VcpuState) -> HvResult<()> {
        for (i, v) in s.gpr.iter().enumerate() {
            self.set_reg(i as u32, *v)?;
        }
        self.set_reg(HV_REG_PC, s.pc)?;
        self.set_reg(HV_REG_CPSR, s.cpsr)?;
        for &(id, v) in &s.sysregs {
            // Some sysregs may be read-only on a given core; ignore those.
            let _ = self.set_sys_reg(id, v);
        }
        Ok(())
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        // SAFETY: destroy on the owning thread before the Vm is dropped.
        unsafe {
            hv_vcpu_destroy(self.id);
        }
    }
}
