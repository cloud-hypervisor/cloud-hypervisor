// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Rehydrate a real cloud-hypervisor arm64 KVM snapshot into a live Apple
//! Hypervisor.framework VM.
//!
//! This is the orchestration that turns the individually-proven translation
//! pieces (vCPU core/sys registers, the GIC CPU-interface (ICC), and the GIC
//! distributor/redistributor — see [`super::translate`]) plus the captured
//! guest RAM into a single running VM. It is the concrete payoff of the port:
//! a snapshot taken by cloud-hypervisor under KVM (in the cloud, or in a nested
//! KVM guest on this Mac) is reconstructed field-by-field on Apple Silicon.
//!
//! The input is a cloud-hypervisor snapshot directory:
//!
//! ```text
//!   state.json                 # the nested snapshot tree (below)
//!   snapshot/memory-ranges     # raw guest RAM, concatenated per region
//! ```
//!
//! `state.json` carries three relevant sub-trees:
//!
//! - `snapshots/cpu-manager/snapshots/<id>/snapshot_data/state` — a JSON STRING
//!   `{"Kvm": VcpuKvmState}` per vCPU (core + system registers).
//! - `snapshots/device-manager/snapshots/gic-v3-its/snapshot_data/state` — a
//!   JSON STRING `{"Kvm": Gicv3ItsState}` (the `dist`/`rdist`/`icc` register
//!   dumps; the per-vCPU ICC lives here, NOT in the vCPU node).
//! - `snapshots/memory-manager/snapshot_data/state` — a JSON STRING describing
//!   `guest_ram_mappings` (where each RAM region maps in guest-physical space
//!   and its offset within `memory-ranges`).
//!
//! What is and is NOT covered (honest boundary): the CPU, the GIC
//! distributor/redistributor SGI-frame state, the per-vCPU ICC, and guest RAM
//! are all restored. The GIC RD_base LPI registers (GICR_PROPBASER/PENDBASER)
//! and the ITS tables — which matter only for guests actively delivering
//! MSI/LPIs — are not, and neither is a userspace device model (virtio/PCI),
//! so a rehydrated guest executes its real captured code until it touches an
//! unmodeled device. Restoring + executing the CPU/memory/interrupt state from
//! a real snapshot is exactly the link this module proves.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use libc::{
    c_void, mmap, munmap, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};

use crate::arch::aarch64::gic::{Vgic, VgicConfig};
use crate::cpu::Vcpu;
use crate::hvf::gic::HvfGicV3;
use crate::hvf::translate::gic_ingest::{dist_to_hvf, num_irq_from_dist_len, redist_to_hvf};
use crate::hvf::translate::kvm_ingest::snapshot_json_to_hvf;
use crate::hvf::HvfVcpu;
use crate::hvf::VcpuHvfState;
use crate::hypervisor::Hypervisor;
use crate::vm::{Vm, VmOps};
use crate::{CpuState, HypervisorVmConfig};

/// cloud-hypervisor arm64 GIC layout (mirrors `arch::aarch64::layout`). The
/// snapshot does not store the GIC MMIO addresses — they are fixed by the VMM's
/// memory map, so they are reproduced here.
const MAPPED_IO_START: u64 = 0x0900_0000;
const GIC_V3_DIST_SIZE: u64 = 0x01_0000;
const GIC_V3_REDIST_SIZE: u64 = 0x02_0000;
/// Base of cloud-hypervisor's reserved low-MMIO GIC window. The managed GIC is
/// relocated here (distributor first, redistributors above) to satisfy Apple's
/// `hv_gic_create` ordering constraint; see [`Snapshot::vgic_config`].
const GIC_RELOCATED_BASE: u64 = 0x0800_0000;

/// Errors raised while parsing or rehydrating a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum RehydrateError {
    /// `state.json` (or an embedded state string) did not parse.
    #[error("failed to parse snapshot JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A required node was missing or malformed in the snapshot tree.
    #[error("malformed snapshot: {0}")]
    Malformed(String),
    /// A vCPU or GIC register translation failed.
    #[error("translation failed: {0}")]
    Translate(String),
    /// Mapping the guest-RAM file failed.
    #[error("guest-RAM mmap of {path} failed: {source}")]
    Mmap {
        /// The file that could not be mapped.
        path: String,
        /// The underlying OS error.
        source: std::io::Error,
    },
    /// A hypervisor/VM operation failed.
    #[error("hypervisor operation failed: {0}")]
    Hv(#[from] anyhow::Error),
}

/// One guest-RAM region: where it maps in guest-physical space and where its
/// bytes live inside the `memory-ranges` file.
#[derive(Debug, Clone)]
pub struct MemMapping {
    /// Hypervisor memory-slot index.
    pub slot: u32,
    /// Guest-physical base address.
    pub gpa: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Byte offset of this region within `memory-ranges`.
    pub file_offset: u64,
}

/// A parsed cloud-hypervisor snapshot: everything needed to rebuild the VM,
/// with every register already translated into HVF form.
pub struct Snapshot {
    /// Guest-RAM regions, in slot order.
    pub mem_mappings: Vec<MemMapping>,
    /// Per-vCPU translated state (index == vCPU id), including its ICC vector.
    pub vcpus: Vec<VcpuHvfState>,
    /// GIC distributor dump (`Gicv3ItsState.dist`).
    pub gic_dist: Vec<u32>,
    /// GIC redistributor dump for all vCPUs (`Gicv3ItsState.rdist`).
    pub gic_rdist: Vec<u32>,
    /// Number of interrupt lines the captured GICv3 was built with.
    pub num_irq: u32,
}

impl Snapshot {
    /// Parse a cloud-hypervisor `state.json` into a translated [`Snapshot`].
    pub fn from_state_json(state_json: &str) -> Result<Self, RehydrateError> {
        let root: serde_json::Value = serde_json::from_str(state_json)?;
        let snaps = root
            .get("snapshots")
            .ok_or_else(|| RehydrateError::Malformed("missing `snapshots`".into()))?;

        // --- memory-manager: guest_ram_mappings ---------------------------------
        let mem_state = embedded_state(snaps, &["memory-manager"])?;
        let mappings_json = mem_state
            .get("guest_ram_mappings")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RehydrateError::Malformed("missing `guest_ram_mappings`".into()))?;
        let mut mem_mappings = Vec::with_capacity(mappings_json.len());
        for m in mappings_json {
            let gpa = u64_field(m, "gpa")?;
            let size = u64_field(m, "size")?;
            let file_offset = u64_field(m, "file_offset")?;
            let slot = u64_field(m, "slot")? as u32;
            mem_mappings.push(MemMapping {
                slot,
                gpa,
                size,
                file_offset,
            });
        }
        if mem_mappings.is_empty() {
            return Err(RehydrateError::Malformed(
                "snapshot has no guest_ram_mappings".into(),
            ));
        }

        // --- device-manager: the GIC (dist/rdist/icc) ---------------------------
        let gic_kvm = embedded_state(snaps, &["device-manager", "gic-v3-its"])?;
        let gic_kvm = gic_kvm
            .get("Kvm")
            .ok_or_else(|| RehydrateError::Malformed("GIC node is not a KVM GIC".into()))?;
        let gic_dist = u32_vec(gic_kvm, "dist")?;
        let gic_rdist = u32_vec(gic_kvm, "rdist")?;
        let gic_icc = u32_vec(gic_kvm, "icc")?;
        let num_irq = num_irq_from_dist_len(gic_dist.len()).ok_or_else(|| {
            RehydrateError::Translate(format!(
                "distributor dump length {} matches no GICv3 width",
                gic_dist.len()
            ))
        })?;

        // --- cpu-manager: per-vCPU state, combined with its ICC slice -----------
        let vcpu_nodes = snaps
            .get("cpu-manager")
            .and_then(|c| c.get("snapshots"))
            .and_then(|v| v.as_object())
            .ok_or_else(|| RehydrateError::Malformed("missing cpu-manager vCPUs".into()))?;
        let num_vcpus = vcpu_nodes.len();
        if num_vcpus == 0 {
            return Err(RehydrateError::Malformed("snapshot has no vCPUs".into()));
        }
        if gic_icc.len() % num_vcpus != 0 {
            return Err(RehydrateError::Translate(format!(
                "ICC dump ({}) does not divide evenly across {num_vcpus} vCPUs",
                gic_icc.len()
            )));
        }
        if gic_rdist.len() % num_vcpus != 0 {
            return Err(RehydrateError::Translate(format!(
                "redistributor dump ({}) does not divide evenly across {num_vcpus} vCPUs",
                gic_rdist.len()
            )));
        }
        let icc_per_vcpu = gic_icc.len() / num_vcpus;

        // vCPU nodes are keyed by stringified id ("0", "1", ...); restore in id
        // order so vCPU i gets the i-th ICC slice.
        let mut vcpus: Vec<VcpuHvfState> = Vec::with_capacity(num_vcpus);
        for id in 0..num_vcpus {
            let node = vcpu_nodes.get(&id.to_string()).ok_or_else(|| {
                RehydrateError::Malformed(format!("missing cpu-manager vCPU `{id}`"))
            })?;
            let state_str = node
                .get("snapshot_data")
                .and_then(|d| d.get("state"))
                .and_then(|s| s.as_str())
                .ok_or_else(|| {
                    RehydrateError::Malformed(format!("vCPU `{id}` has no snapshot state string"))
                })?;
            let mut hvf = snapshot_json_to_hvf(state_str)?;
            let icc_slice = &gic_icc[id * icc_per_vcpu..(id + 1) * icc_per_vcpu];
            if let Some(icc) =
                crate::hvf::translate::gic_ingest::icc_to_hvf(icc_slice)
            {
                hvf.gic_icc = icc;
            }
            vcpus.push(hvf);
        }

        Ok(Snapshot {
            mem_mappings,
            vcpus,
            gic_dist,
            gic_rdist,
            num_irq,
        })
    }

    /// Number of vCPUs in the snapshot.
    pub fn num_vcpus(&self) -> u32 {
        self.vcpus.len() as u32
    }

    /// The [`VgicConfig`] used to recreate the managed GIC for this snapshot.
    ///
    /// Cloud-hypervisor's arm64 map places the redistributors *below* the
    /// distributor (`GIC_V3_DIST_START` is the top of the reserved GIC window
    /// and redistributors grow downward from it). Apple's managed GIC, however,
    /// rejects that ordering: `hv_gic_create` returns `HV_BAD_ARGUMENT`
    /// (0xfae94003) unless the redistributor base is **above** the distributor
    /// base (verified empirically on hardware). The two layouts are therefore
    /// not simultaneously satisfiable.
    ///
    /// This is acceptable because the restored interrupt configuration is
    /// carried by the per-register distributor/redistributor writes and the
    /// per-vCPU ICC system registers — none of which depend on the MMIO base
    /// address. A resumed guest acknowledges/EOIs interrupts purely through
    /// `ICC_*` system registers, so relocating the managed GIC's MMIO base does
    /// not affect interrupt delivery. The only behaviour that would notice the
    /// move is *fresh* GIC MMIO reconfiguration after resume (already performed
    /// before the snapshot); that is the honest boundary of this relocation.
    ///
    /// We keep the GIC inside cloud-hypervisor's reserved low-MMIO window
    /// (`[GIC_RELOCATED_BASE, MAPPED_IO_START)`), so it never collides with
    /// guest RAM or the virtio devices that live at/above `MAPPED_IO_START`.
    pub fn vgic_config(&self) -> VgicConfig {
        let vcpu_count = self.num_vcpus() as u64;
        let redists_size = GIC_V3_REDIST_SIZE * vcpu_count;
        // Distributor first, redistributors immediately above it (HVF order).
        let dist_addr = GIC_RELOCATED_BASE;
        let redists_addr = dist_addr + GIC_V3_DIST_SIZE;
        debug_assert!(
            redists_addr + redists_size <= MAPPED_IO_START,
            "relocated GIC overflows the reserved MMIO window"
        );
        VgicConfig {
            vcpu_count,
            dist_addr,
            dist_size: GIC_V3_DIST_SIZE,
            redists_addr,
            redists_size,
            // Apple's managed GIC ignores the MSI frame (no ITS); leave unset.
            msi_addr: 0,
            msi_size: 0,
            nr_irqs: self.num_irq,
        }
    }

    /// The redistributor dump slice belonging to vCPU `id`.
    fn rdist_slice(&self, id: usize) -> &[u32] {
        let per = self.gic_rdist.len() / self.vcpus.len();
        &self.gic_rdist[id * per..(id + 1) * per]
    }
}

/// File-backed guest RAM: a private (copy-on-write) mapping of a region of the
/// `memory-ranges` file. Private mapping means the resumed guest's writes never
/// reach the on-disk snapshot, so a rehydration attempt cannot corrupt it.
struct GuestRam {
    ptr: *mut u8,
    size: usize,
}

// SAFETY: the mapping is owned exclusively by this struct and only handed to
// the hypervisor as a raw guest-physical backing; no Rust aliasing occurs.
unsafe impl Send for GuestRam {}
// SAFETY: see the `Send` impl above — the raw pointer is never aliased and the
// mapping is only read/written by the hypervisor as guest memory.
unsafe impl Sync for GuestRam {}

impl GuestRam {
    /// Map `size` bytes at `file_offset` of `path` copy-on-write.
    fn map_file(path: &Path, file_offset: u64, size: usize) -> Result<Self, RehydrateError> {
        use std::os::unix::fs::FileExt;
        // Open and validate the region is within the file.
        let file = std::fs::File::open(path).map_err(|e| RehydrateError::Mmap {
            path: path.display().to_string(),
            source: e,
        })?;
        let len = file
            .metadata()
            .map_err(|e| RehydrateError::Mmap {
                path: path.display().to_string(),
                source: e,
            })?
            .len();
        if file_offset + size as u64 > len {
            return Err(RehydrateError::Malformed(format!(
                "memory region [{file_offset:#x}, +{size:#x}) exceeds {} ({len} bytes)",
                path.display()
            )));
        }

        // Anonymous, wired-capable backing for the hypervisor, filled from the
        // file. (An anonymous mapping is the most portable choice for
        // `hv_vm_map`; the file is read into it once.)
        // SAFETY: standard anonymous read/write mapping; checked below.
        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(RehydrateError::Mmap {
                path: path.display().to_string(),
                source: std::io::Error::last_os_error(),
            });
        }
        let ram = GuestRam {
            ptr: ptr as *mut u8,
            size,
        };

        // SAFETY: ptr is valid for `size` bytes; we fill it exactly once.
        let buf = unsafe { std::slice::from_raw_parts_mut(ram.ptr, size) };
        file.read_exact_at(buf, file_offset)
            .map_err(|e| RehydrateError::Mmap {
                path: path.display().to_string(),
                source: e,
            })?;
        Ok(ram)
    }
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        // SAFETY: unmapping our own mapping exactly once.
        unsafe {
            munmap(self.ptr as *mut c_void, self.size);
        }
    }
}

/// A live VM rebuilt from a snapshot: memory mapped, GIC + vCPUs restored, ready
/// to `run()`. The guest-RAM backing is owned here so it outlives the mapping.
pub struct RehydratedVm {
    // NOTE: field declaration order is drop order. HVF requires every vCPU to be
    // destroyed before the VM, and the managed GIC + guest-RAM mappings belong
    // to the VM, so the `vm` handle (whose `Drop` calls `hv_vm_destroy`) MUST be
    // dropped last. Declaring it last guarantees that ordering.
    /// Restored vCPUs, in id order. Dropped first (`hv_vcpu_destroy`).
    pub vcpus: Vec<Box<dyn Vcpu>>,
    /// The restored managed GICv3.
    pub gic: Arc<Mutex<dyn Vgic>>,
    /// Host-side guest-RAM backings (kept alive for the VM's lifetime).
    _ram: Vec<GuestRam>,
    /// The reconstructed VM. Dropped last (`hv_vm_destroy`).
    pub vm: Arc<dyn Vm>,
}

/// Rebuild a live HVF VM from a parsed [`Snapshot`] and its `memory-ranges`
/// file. The returned vCPUs carry the full restored architectural state and can
/// be `run()` immediately.
///
/// Restore order mirrors cloud-hypervisor's own: map RAM, create the GIC,
/// create the vCPUs, restore the distributor, then per vCPU restore its
/// register file (which sets MPIDR + the ICC interface) and its redistributor
/// frame.
pub fn rehydrate(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
    vm_ops: &Arc<dyn VmOps>,
) -> Result<RehydratedVm, RehydrateError> {
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vm: {e}")))?;

    // --- guest RAM ----------------------------------------------------------
    let mut ram = Vec::with_capacity(snap.mem_mappings.len());
    for m in &snap.mem_mappings {
        let backing = GuestRam::map_file(memory_ranges, m.file_offset, m.size as usize)?;
        // SAFETY: `backing` outlives the VM (stored in RehydratedVm._ram).
        unsafe {
            vm.create_user_memory_region(m.slot, m.gpa, m.size as usize, backing.ptr, false, false)
                .map_err(|e| RehydrateError::Hv(anyhow!("map RAM @ {:#x}: {e}", m.gpa)))?;
        }
        ram.push(backing);
    }

    // --- GIC ---------------------------------------------------------------
    let gic = vm.create_vgic(&snap.vgic_config()).map_err(|e| {
        use std::error::Error;
        let mut msg = format!("create_vgic: {e}");
        let mut src = e.source();
        while let Some(s) = src {
            msg.push_str(&format!(" -> {s}"));
            src = s.source();
        }
        RehydrateError::Hv(anyhow!(msg))
    })?;

    // --- vCPUs (created before distributor restore so the redistributors
    //     exist) -----------------------------------------------------------
    let mut vcpus = Vec::with_capacity(snap.vcpus.len());
    for id in 0..snap.vcpus.len() {
        let vcpu = vm
            .create_vcpu(id as u32, Some(vm_ops.clone()))
            .map_err(|e| RehydrateError::Hv(anyhow!("create_vcpu {id}: {e}")))?;
        vcpus.push(vcpu);
    }

    // --- distributor (global) ----------------------------------------------
    {
        let mut guard = gic.lock().unwrap();
        let concrete = guard
            .as_any_concrete_mut()
            .downcast_mut::<HvfGicV3>()
            .ok_or_else(|| RehydrateError::Translate("GIC is not an HVF GIC".into()))?;
        let dist_pairs = dist_to_hvf(&snap.gic_dist)
            .ok_or_else(|| RehydrateError::Translate("distributor dump did not translate".into()))?;
        for (reg, val) in dist_pairs {
            concrete
                .set_distributor_reg(reg, val)
                .map_err(|e| RehydrateError::Hv(anyhow!("set GICD[{reg:#x}]: {e}")))?;
        }
    }

    // --- per-vCPU: register file (MPIDR + ICC) then redistributor frame -----
    for (id, vcpu) in vcpus.iter_mut().enumerate() {
        vcpu.set_state(&CpuState::Hvf(snap.vcpus[id].clone()))
            .map_err(|e| RehydrateError::Hv(anyhow!("restore vCPU {id} state: {e}")))?;

        let redist_pairs = redist_to_hvf(snap.rdist_slice(id)).ok_or_else(|| {
            RehydrateError::Translate(format!("vCPU {id} redistributor did not translate"))
        })?;
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<HvfVcpu>()
            .ok_or_else(|| RehydrateError::Translate("vCPU is not an HVF vCPU".into()))?;
        for (reg, val) in redist_pairs {
            concrete
                .set_redistributor_reg(reg, val)
                .map_err(|e| RehydrateError::Hv(anyhow!("vCPU {id} set GICR[{reg:#x}]: {e}")))?;
        }
    }

    Ok(RehydratedVm {
        vcpus,
        gic,
        _ram: ram,
        vm,
    })
}

// --- small JSON helpers -----------------------------------------------------

/// Pull the embedded `snapshot_data.state` string out of a nested snapshot node
/// and parse it as JSON. `path` walks `snapshots` keys down to the target node.
fn embedded_state(
    snaps: &serde_json::Value,
    path: &[&str],
) -> Result<serde_json::Value, RehydrateError> {
    let mut node = snaps;
    for (i, key) in path.iter().enumerate() {
        node = node
            .get(key)
            .ok_or_else(|| RehydrateError::Malformed(format!("missing snapshot node `{key}`")))?;
        // Every level except the last is reached through its `snapshots` map.
        if i + 1 < path.len() {
            node = node
                .get("snapshots")
                .ok_or_else(|| RehydrateError::Malformed(format!("`{key}` has no children")))?;
        }
    }
    let state_str = node
        .get("snapshot_data")
        .and_then(|d| d.get("state"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            RehydrateError::Malformed(format!("node `{}` has no state string", path.join("/")))
        })?;
    Ok(serde_json::from_str(state_str)?)
}

fn u64_field(v: &serde_json::Value, key: &str) -> Result<u64, RehydrateError> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| RehydrateError::Malformed(format!("missing/invalid u64 field `{key}`")))
}

fn u32_vec(v: &serde_json::Value, key: &str) -> Result<Vec<u32>, RehydrateError> {
    v.get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| RehydrateError::Malformed(format!("missing array field `{key}`")))?
        .iter()
        .map(|n| {
            n.as_u64()
                .map(|x| x as u32)
                .ok_or_else(|| RehydrateError::Malformed(format!("non-integer in `{key}`")))
        })
        .collect()
}
