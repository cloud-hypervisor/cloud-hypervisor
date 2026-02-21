// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vhost::vdpa::{VhostVdpa, VhostVdpaIovaRange};
use vhost::vhost_kern::VhostKernFeatures;
use vhost::vhost_kern::vdpa::VhostKernVdpa;
use vhost::vhost_kern::vhost_binding::VHOST_BACKEND_F_SUSPEND;
use vhost::{VhostBackend, VringConfigData};

/// VHOST_BACKEND_F_RESUME: device supports resume after suspend.
/// Not yet exposed by the vhost crate (v0.14.0), defined in linux/vhost_types.h.
const VHOST_BACKEND_F_RESUME: u64 = 0x5;

// VHOST_VDPA_RESUME ioctl number, not yet in the vhost crate.
// Defined in linux/vhost.h as _IO(VHOST_VIRTIO, 0x7E), VHOST_VIRTIO = 0xAF.
// _IO(type, nr) = (type << 8) | nr
const VHOST_VDPA_RESUME: libc::c_ulong = (0xAF << 8) | 0x7E;
use virtio_queue::desc::split::Descriptor as SplitDescriptor;
use virtio_queue::desc::RawDescriptor;
use virtio_queue::{Queue, QueueT};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_memory::{Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::protocol::{MemoryRange, MemoryRangeTable};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::{AccessPlatform, Translatable};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    ActivateError, ActivateResult, DEVICE_ACKNOWLEDGE, DEVICE_DRIVER, DEVICE_DRIVER_OK,
    DEVICE_FEATURES_OK, GuestMemoryMmap, VIRTIO_F_IOMMU_PLATFORM, VirtioCommon, VirtioDevice,
    VirtioInterrupt, VirtioInterruptType, get_host_address_range,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create vhost-vdpa")]
    CreateVhostVdpa(#[source] vhost::Error),
    #[error("Failed to map DMA range")]
    DmaMap(#[source] vhost::Error),
    #[error("Failed to unmap DMA range")]
    DmaUnmap(#[source] vhost::Error),
    #[error("Failed to get address range")]
    GetAddressRange,
    #[error("Failed to get the available index from the virtio queue")]
    GetAvailableIndex(#[source] virtio_queue::Error),
    #[error("Failed to get the used index from the virtio queue")]
    GetUsedIndex(#[source] virtio_queue::Error),
    #[error("Get virtio configuration size")]
    GetConfigSize(#[source] vhost::Error),
    #[error("Get virtio device identifier")]
    GetDeviceId(#[source] vhost::Error),
    #[error("Failed to get backend specific features")]
    GetBackendFeatures(#[source] vhost::Error),
    #[error("Failed to get virtio features")]
    GetFeatures(#[source] vhost::Error),
    #[error("Failed to get the IOVA range")]
    GetIovaRange(#[source] vhost::Error),
    #[error("Failed to get queue size")]
    GetVringNum(#[source] vhost::Error),
    #[error("Invalid IOVA range: {0}-{1}")]
    InvalidIovaRange(u64, u64),
    #[error("Missing VIRTIO_F_ACCESS_PLATFORM feature")]
    MissingAccessPlatformVirtioFeature,
    #[error("Failed to reset owner")]
    ResetOwner(#[source] vhost::Error),
    #[error("Failed to set backend specific features")]
    SetBackendFeatures(#[source] vhost::Error),
    #[error("Failed to set backend configuration")]
    SetConfig(#[source] vhost::Error),
    #[error("Failed to set eventfd notifying about a configuration change")]
    SetConfigCall(#[source] vhost::Error),
    #[error("Failed to set virtio features")]
    SetFeatures(#[source] vhost::Error),
    #[error("Failed to set memory table")]
    SetMemTable(#[source] vhost::Error),
    #[error("Failed to set owner")]
    SetOwner(#[source] vhost::Error),
    #[error("Failed to set virtio status")]
    SetStatus(#[source] vhost::Error),
    #[error("Failed to set vring address")]
    SetVringAddr(#[source] vhost::Error),
    #[error("Failed to set vring base")]
    SetVringBase(#[source] vhost::Error),
    #[error("Failed to set vring eventfd when buffer are used")]
    SetVringCall(#[source] vhost::Error),
    #[error("Failed to enable/disable vring")]
    SetVringEnable(#[source] vhost::Error),
    #[error("Failed to set vring eventfd when new descriptors are available")]
    SetVringKick(#[source] vhost::Error),
    #[error("Failed to set vring size")]
    SetVringNum(#[source] vhost::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize)]
pub struct VdpaState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub device_type: u32,
    pub iova_range_first: u64,
    pub iova_range_last: u64,
    pub config: Vec<u8>,
    pub queue_sizes: Vec<u16>,
    pub backend_features: u64,
}

/// Queue metadata captured during activation, used for conservative dirty
/// page tracking during cross-host live migration.
struct VdpaQueueInfo {
    /// GPA of the descriptor table
    desc_table_gpa: u64,
    /// GPA of the used ring
    used_ring_gpa: u64,
    /// Number of descriptors in the queue
    queue_size: u16,
}

pub struct Vdpa {
    common: VirtioCommon,
    id: String,
    vhost: Option<VhostKernVdpa<GuestMemoryAtomic<GuestMemoryMmap>>>,
    iova_range: VhostVdpaIovaRange,
    enabled_queues: BTreeMap<usize, bool>,
    backend_features: u64,
    migrating: bool,
    /// Set when the device has been suspended via VHOST_VDPA_SUSPEND during
    /// the pause phase of migration. Cleared by resume() if migration fails.
    suspended: bool,
    /// Set after dirty_log() has collected conservative dirty pages, to
    /// prevent double-reporting. Separate from `suspended` so that resume()
    /// can still detect that the device needs to be unsuspended.
    dirty_reported: bool,
    /// Guest memory reference stored during activation, needed to read
    /// virtqueue descriptor rings for conservative dirty page marking.
    guest_memory: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// Queue metadata captured during activation for descriptor ring walking.
    queue_infos: Vec<VdpaQueueInfo>,
}

impl Vdpa {
    pub fn new(
        id: String,
        device_path: &str,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        num_queues: u16,
        state: Option<VdpaState>,
    ) -> Result<Self> {
        let mut vhost = VhostKernVdpa::new(device_path, mem).map_err(Error::CreateVhostVdpa)?;
        vhost.set_owner().map_err(Error::SetOwner)?;

        let (
            device_type,
            avail_features,
            acked_features,
            queue_sizes,
            iova_range,
            backend_features,
            paused,
        ) = if let Some(state) = state {
            info!("Restoring vDPA {id}");

            vhost.set_backend_features_acked(state.backend_features);
            vhost
                .set_config(0, state.config.as_slice())
                .map_err(Error::SetConfig)?;

            (
                state.device_type,
                state.avail_features,
                state.acked_features,
                state.queue_sizes,
                VhostVdpaIovaRange {
                    first: state.iova_range_first,
                    last: state.iova_range_last,
                },
                state.backend_features,
                false,
            )
        } else {
            let device_type = vhost.get_device_id().map_err(Error::GetDeviceId)?;
            let queue_size = vhost.get_vring_num().map_err(Error::GetVringNum)?;
            let avail_features = vhost.get_features().map_err(Error::GetFeatures)?;
            let backend_features = vhost
                .get_backend_features()
                .map_err(Error::GetBackendFeatures)?;
            vhost.set_backend_features_acked(backend_features);

            let iova_range = vhost.get_iova_range().map_err(Error::GetIovaRange)?;

            if avail_features & (1u64 << VIRTIO_F_IOMMU_PLATFORM) == 0 {
                return Err(Error::MissingAccessPlatformVirtioFeature);
            }

            (
                device_type,
                avail_features,
                0,
                vec![queue_size; num_queues as usize],
                iova_range,
                backend_features,
                false,
            )
        };

        Ok(Vdpa {
            common: VirtioCommon {
                device_type,
                queue_sizes,
                avail_features,
                acked_features,
                min_queues: num_queues,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            vhost: Some(vhost),
            iova_range,
            enabled_queues: BTreeMap::new(),
            backend_features,
            migrating: false,
            suspended: false,
            dirty_reported: false,
            guest_memory: None,
            queue_infos: Vec::new(),
        })
    }

    fn enable_vrings(&mut self, enable: bool) -> Result<()> {
        assert!(self.vhost.is_some());

        for (queue_index, enabled) in self.enabled_queues.iter_mut() {
            if *enabled != enable {
                self.vhost
                    .as_ref()
                    .unwrap()
                    .set_vring_enable(*queue_index, enable)
                    .map_err(Error::SetVringEnable)?;
                *enabled = enable;
            }
        }

        Ok(())
    }

    fn activate_vdpa(
        &mut self,
        mem: &GuestMemoryMmap,
        virtio_interrupt: &dyn VirtioInterrupt,
        queues: &[(usize, Queue, EventFd)],
    ) -> Result<()> {
        assert!(self.vhost.is_some());
        self.vhost
            .as_ref()
            .unwrap()
            .set_features(self.common.acked_features)
            .map_err(Error::SetFeatures)?;
        self.vhost
            .as_mut()
            .unwrap()
            .set_backend_features(self.backend_features)
            .map_err(Error::SetBackendFeatures)?;

        self.queue_infos.clear();

        for (queue_index, queue, queue_evt) in queues.iter() {
            let queue_max_size = queue.max_size();
            let queue_size = queue.size();

            // Store queue metadata for conservative dirty page tracking
            // during cross-host live migration.
            self.queue_infos.push(VdpaQueueInfo {
                desc_table_gpa: queue.desc_table(),
                used_ring_gpa: queue.used_ring(),
                queue_size,
            });
            self.vhost
                .as_ref()
                .unwrap()
                .set_vring_num(*queue_index, queue_size)
                .map_err(Error::SetVringNum)?;

            let config_data = VringConfigData {
                queue_max_size,
                queue_size,
                flags: 0u32,
                desc_table_addr: queue.desc_table().translate_gpa(
                    self.common.access_platform.as_deref(),
                    queue_size as usize * std::mem::size_of::<RawDescriptor>(),
                ),
                used_ring_addr: queue.used_ring().translate_gpa(
                    self.common.access_platform.as_deref(),
                    4 + queue_size as usize * 8,
                ),
                avail_ring_addr: queue.avail_ring().translate_gpa(
                    self.common.access_platform.as_deref(),
                    4 + queue_size as usize * 2,
                ),
                log_addr: None,
            };

            self.vhost
                .as_ref()
                .unwrap()
                .set_vring_addr(*queue_index, &config_data)
                .map_err(Error::SetVringAddr)?;
            let avail_idx = queue
                .avail_idx(mem, Ordering::Acquire)
                .map_err(Error::GetAvailableIndex)?
                .0;
            let used_idx = queue
                .used_idx(mem, Ordering::Acquire)
                .map_err(Error::GetUsedIndex)?
                .0;
            // Use used_idx for set_vring_base because the mlx5_vdpa kernel
            // driver sets BOTH hw_available_index and hw_used_index to the
            // same value. Using avail_idx causes an RX deadlock after live
            // migration.
            info!(
                "vDPA queue {}: avail_idx={}, used_idx={}, setting vring_base={}",
                queue_index, avail_idx, used_idx, used_idx
            );
            self.vhost
                .as_ref()
                .unwrap()
                .set_vring_base(*queue_index, used_idx)
                .map_err(Error::SetVringBase)?;

            if let Some(eventfd) =
                virtio_interrupt.notifier(VirtioInterruptType::Queue(*queue_index as u16))
            {
                self.vhost
                    .as_ref()
                    .unwrap()
                    .set_vring_call(*queue_index, &eventfd)
                    .map_err(Error::SetVringCall)?;
            }

            self.vhost
                .as_ref()
                .unwrap()
                .set_vring_kick(*queue_index, queue_evt)
                .map_err(Error::SetVringKick)?;

            // After migration, the guest virtio driver may have disabled device
            // notifications (VRING_AVAIL_F_NO_INTERRUPT) because it was in NAPI
            // polling mode. The new device respects this flag and won't send
            // interrupts, causing a deadlock (guest waits for interrupt, device
            // won't send one). Clear the flag to ensure the device notifies the
            // guest about completed buffers, allowing the driver to resume.
            let avail_flags_addr = GuestAddress(queue.avail_ring());
            if let Ok(flags) = mem.read_obj::<u16>(avail_flags_addr) {
                let flags_le = u16::from_le(flags);
                if flags_le & 1 != 0 {
                    // VRING_AVAIL_F_NO_INTERRUPT is set — clear it
                    info!(
                        "vDPA queue {}: clearing VRING_AVAIL_F_NO_INTERRUPT (flags=0x{:x})",
                        queue_index, flags_le
                    );
                    let new_flags: u16 = (flags_le & !1u16).to_le();
                    let _ = mem.write_obj(new_flags, avail_flags_addr);
                } else {
                    info!(
                        "vDPA queue {}: avail flags=0x{:x} (notifications enabled)",
                        queue_index, flags_le
                    );
                }
            }

            self.enabled_queues.insert(*queue_index, false);
        }

        // Setup the config eventfd if there is one
        if let Some(eventfd) = virtio_interrupt.notifier(VirtioInterruptType::Config) {
            self.vhost
                .as_ref()
                .unwrap()
                .set_config_call(&eventfd)
                .map_err(Error::SetConfigCall)?;
        }

        self.enable_vrings(true)?;

        self.vhost
            .as_ref()
            .unwrap()
            .set_status(
                (DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK) as u8,
            )
            .map_err(Error::SetStatus)
    }

    fn reset_vdpa(&mut self) -> Result<()> {
        self.enable_vrings(false)?;

        assert!(self.vhost.is_some());
        self.vhost
            .as_ref()
            .unwrap()
            .set_status(0)
            .map_err(Error::SetStatus)
    }

    /// # SAFETY
    ///
    /// `host_vaddr` must point to `size` bytes of valid memory.
    unsafe fn dma_map(
        &mut self,
        iova: u64,
        size: u64,
        host_vaddr: *const u8,
        readonly: bool,
    ) -> Result<()> {
        let Some(iova_last) = iova.checked_add(size) else {
            return Err(Error::InvalidIovaRange(iova, u64::MAX));
        };
        let Some(iova_last) = iova_last.checked_sub(1) else {
            return Err(Error::InvalidIovaRange(0, 0));
        };
        if iova < self.iova_range.first || iova_last > self.iova_range.last {
            return Err(Error::InvalidIovaRange(iova, iova_last));
        }
        if isize::try_from(size).is_err() {
            return Err(Error::InvalidIovaRange(iova, iova_last));
        }

        assert!(self.vhost.is_some());
        self.vhost
            .as_ref()
            .unwrap()
            .dma_map(iova, size, host_vaddr, readonly)
            .map_err(Error::DmaMap)
    }

    fn dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        let iova_last = iova + size - 1;
        if iova < self.iova_range.first || iova_last > self.iova_range.last {
            return Err(Error::InvalidIovaRange(iova, iova_last));
        }

        assert!(self.vhost.is_some());
        self.vhost
            .as_ref()
            .unwrap()
            .dma_unmap(iova, size)
            .map_err(Error::DmaUnmap)
    }

    fn state(&self) -> Result<VdpaState> {
        assert!(self.vhost.is_some());
        let config_size = self
            .vhost
            .as_ref()
            .unwrap()
            .get_config_size()
            .map_err(Error::GetConfigSize)?;
        let mut config = vec![0; config_size as usize];
        self.read_config(0, config.as_mut_slice());

        Ok(VdpaState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            device_type: self.common.device_type,
            queue_sizes: self.common.queue_sizes.clone(),
            iova_range_first: self.iova_range.first,
            iova_range_last: self.iova_range.last,
            config,
            backend_features: self.backend_features,
        })
    }
}

impl VirtioDevice for Vdpa {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(vhost) = self.vhost.as_ref() {
            if let Err(e) = vhost.get_config(offset as u32, data) {
                error!("Failed reading virtio config: {e}");
            }
        } else {
            warn!("vDPA {}: read_config called but vhost handle is None", self.id);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if let Some(vhost) = self.vhost.as_ref() {
            if let Err(e) = vhost.set_config(offset as u32, data) {
                error!("Failed writing virtio config: {e}");
            }
        } else {
            warn!("vDPA {}: write_config called but vhost handle is None", self.id);
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        virtio_interrupt: Arc<dyn VirtioInterrupt>,
        queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.activate_vdpa(&mem.memory(), virtio_interrupt.as_ref(), &queues)
            .map_err(ActivateError::ActivateVdpa)?;

        // Store guest memory reference for conservative dirty page tracking
        // during cross-host live migration.
        self.guest_memory = Some(mem);

        // Store the virtio interrupt handler as we need to return it on reset
        self.common.interrupt_cb = Some(virtio_interrupt);

        event!("vdpa", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        if let Err(e) = self.reset_vdpa() {
            error!("Failed to reset vhost-vdpa: {e:?}");
            return None;
        }

        self.queue_infos.clear();

        event!("vdpa", "reset", "id", &self.id);

        // Return the virtio interrupt handler
        self.common.interrupt_cb.take()
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }
}

impl Pausable for Vdpa {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        if self.migrating {
            // Suspend the vDPA device to stop all DMA. After this point,
            // no more pages will be dirtied by the device, making it safe
            // to collect conservative dirty pages in the next dirty_log() call.
            if let Some(vhost) = self.vhost.as_ref() {
                vhost.suspend().map_err(|e| {
                    MigratableError::Pause(anyhow!("Error suspending vDPA device: {e:?}"))
                })?;
                self.suspended = true;
                info!("vDPA device {} suspended for migration", self.id);
            }
            Ok(())
        } else {
            Err(MigratableError::Pause(anyhow!(
                "Can't pause a vDPA device outside live migration"
            )))
        }
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        debug!(
            "vDPA {}: resume() called (suspended={}, migrating={}, dirty_reported={}, F_RESUME={})",
            self.id,
            self.suspended,
            self.migrating,
            self.dirty_reported,
            self.backend_features & (1 << VHOST_BACKEND_F_RESUME) != 0
        );
        // If the device was suspended (source, during migration pause phase) and we
        // need to resume it (e.g., migration failed), issue VHOST_VDPA_RESUME.
        // On the destination (fresh restore), suspended=false, so this is a no-op.
        if self.suspended {
            if self.backend_features & (1 << VHOST_BACKEND_F_RESUME) != 0 {
                if let Some(vhost) = self.vhost.as_ref() {
                    // SAFETY: VHOST_VDPA_RESUME is a simple ioctl with no pointer args.
                    let ret = unsafe {
                        libc::ioctl(vhost.as_raw_fd(), VHOST_VDPA_RESUME)
                    };
                    if ret < 0 {
                        return Err(MigratableError::Resume(anyhow!(
                            "VHOST_VDPA_RESUME ioctl failed: {}",
                            io::Error::last_os_error()
                        )));
                    }
                    info!("vDPA device {} resumed after failed migration", self.id);
                } else {
                    // vhost handle was dropped by snapshot() — device fd is closed.
                    // The kernel resets the device on close, so it's no longer suspended.
                    // The VM cannot recover from this state (same as upstream behavior).
                    warn!(
                        "vDPA device {} was suspended but vhost handle was dropped (snapshot \
                         already sent). Device cannot be resumed — VM must be restarted.",
                        self.id
                    );
                }
            } else {
                warn!(
                    "vDPA device {} was suspended but backend doesn't support resume (F_RESUME not set). \
                     Device may be in broken state.",
                    self.id
                );
            }
            self.suspended = false;
        }

        self.migrating = false;
        self.dirty_reported = false;
        Ok(())
    }
}

impl Snapshottable for Vdpa {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        if !self.migrating {
            return Err(MigratableError::Snapshot(anyhow!(
                "Can't snapshot a vDPA device outside live migration"
            )));
        }

        let snapshot = Snapshot::new_from_state(&self.state().map_err(|e| {
            MigratableError::Snapshot(anyhow!("Error snapshotting vDPA device: {e:?}"))
        })?)?;

        // Force the vhost handler to be dropped in order to close the vDPA
        // file. This will ensure the device can be accessed if the VM is
        // migrated on the same host machine.
        self.vhost.take();

        Ok(snapshot)
    }
}

impl Transportable for Vdpa {}

impl Migratable for Vdpa {
    fn start_migration(&mut self) -> std::result::Result<(), MigratableError> {
        // Verify the device supports suspend (required for stop-and-copy phase).
        if self.backend_features & (1 << VHOST_BACKEND_F_SUSPEND) == 0 {
            return Err(MigratableError::StartMigration(anyhow!(
                "vDPA device can't be suspended"
            )));
        }
        self.migrating = true;
        // NOTE: We intentionally do NOT suspend the device here. The device
        // continues running during pre-copy, allowing network traffic to flow.
        // Suspension is deferred to pause() just before the final dirty page
        // collection, minimizing network downtime.
        info!(
            "vDPA {}: migration started (device NOT suspended, traffic continues)",
            self.id
        );
        Ok(())
    }

    fn dirty_log(&mut self) -> std::result::Result<MemoryRangeTable, MigratableError> {
        // During pre-copy (before pause/suspend), we cannot track device DMA
        // writes. Return empty — KVM PML handles CPU-dirtied pages.
        // Also return empty if we already reported dirty pages for this suspension.
        if !self.suspended || self.dirty_reported {
            info!(
                "vDPA {}: dirty_log called (suspended={}, dirty_reported={}, migrating={}), returning empty",
                self.id, self.suspended, self.dirty_reported, self.migrating
            );
            return Ok(MemoryRangeTable::default());
        }

        // After suspend, conservatively mark all pages the device could have
        // DMA-written to: used rings, descriptor tables, and all device-writable
        // buffers referenced by descriptors.
        self.dirty_reported = true;

        info!(
            "vDPA {}: dirty_log collecting conservative dirty pages ({} queues)",
            self.id,
            self.queue_infos.len()
        );

        let mem = self
            .guest_memory
            .as_ref()
            .ok_or_else(|| {
                MigratableError::DirtyLog(anyhow!(
                    "Guest memory not available for vDPA dirty page tracking"
                ))
            })?
            .memory();

        let page_mask: u64 = !0xFFF;
        let mut table = MemoryRangeTable::default();
        let mut total_bytes: u64 = 0;
        let mut write_desc_count: u64 = 0;

        for (qi_idx, qi) in self.queue_infos.iter().enumerate() {
            let queue_size = qi.queue_size as u64;

            // 1. Mark used ring pages as dirty.
            // Layout: flags(u16) + idx(u16) + queue_size * used_elem(u64) + avail_event(u16)
            let used_ring_size = 4 + queue_size * 8 + 2;
            let used_start = qi.used_ring_gpa & page_mask;
            let used_end = (qi.used_ring_gpa + used_ring_size + 0xFFF) & page_mask;
            let used_range_len = used_end - used_start;
            table.push(MemoryRange {
                gpa: used_start,
                length: used_range_len,
            });
            total_bytes += used_range_len;

            // 2. Mark descriptor table pages as dirty (device may write back flags).
            // Each descriptor is 16 bytes (addr:u64 + len:u32 + flags:u16 + next:u16).
            let desc_table_size = queue_size * 16;
            let desc_start = qi.desc_table_gpa & page_mask;
            let desc_end = (qi.desc_table_gpa + desc_table_size + 0xFFF) & page_mask;
            let desc_range_len = desc_end - desc_start;
            table.push(MemoryRange {
                gpa: desc_start,
                length: desc_range_len,
            });
            total_bytes += desc_range_len;

            info!(
                "vDPA {}: queue {}: desc_table GPA={:#x} ({} bytes), used_ring GPA={:#x} ({} bytes), size={}",
                self.id, qi_idx, qi.desc_table_gpa, desc_range_len, qi.used_ring_gpa, used_range_len, queue_size
            );

            // 3. Walk all descriptors and mark device-writable buffers as dirty.
            // After suspend, the descriptor ring state is frozen — safe to read.
            // Also handles indirect descriptors by walking their tables.
            let mut queue_write_descs = 0u64;
            let mut queue_indirect_descs = 0u64;
            for i in 0..queue_size {
                let desc_gpa = GuestAddress(qi.desc_table_gpa + i * 16);
                let desc: SplitDescriptor = match mem.read_obj(desc_gpa) {
                    Ok(d) => d,
                    Err(e) => {
                        error!(
                            "Failed to read vDPA descriptor {} from GPA {:#x}: {e}",
                            i,
                            desc_gpa.raw_value()
                        );
                        continue;
                    }
                };

                if desc.refers_to_indirect_table() && desc.len() > 0 {
                    // Indirect descriptor: addr points to an indirect table,
                    // len is the size of that table in bytes.
                    let indirect_table_gpa = desc.addr().raw_value();
                    let indirect_table_size = desc.len() as u64;
                    let num_indirect = indirect_table_size / 16;
                    queue_indirect_descs += 1;

                    // Mark the indirect table pages as dirty
                    let ind_start = indirect_table_gpa & page_mask;
                    let ind_end = (indirect_table_gpa + indirect_table_size + 0xFFF) & page_mask;
                    let ind_range_len = ind_end - ind_start;
                    table.push(MemoryRange {
                        gpa: ind_start,
                        length: ind_range_len,
                    });
                    total_bytes += ind_range_len;

                    // Walk entries in the indirect table
                    for j in 0..num_indirect {
                        let ind_desc_gpa = GuestAddress(indirect_table_gpa + j * 16);
                        let ind_desc: SplitDescriptor = match mem.read_obj(ind_desc_gpa) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        if ind_desc.is_write_only() && ind_desc.len() > 0 {
                            let buf_addr = ind_desc.addr().raw_value();
                            let buf_start = buf_addr & page_mask;
                            let buf_end =
                                (buf_addr + ind_desc.len() as u64 + 0xFFF) & page_mask;
                            let buf_range_len = buf_end - buf_start;
                            table.push(MemoryRange {
                                gpa: buf_start,
                                length: buf_range_len,
                            });
                            total_bytes += buf_range_len;
                            queue_write_descs += 1;
                        }
                    }
                } else if desc.is_write_only() && desc.len() > 0 {
                    // Direct device-writable descriptor (e.g. RX packet buffers)
                    let buf_addr = desc.addr().raw_value();
                    let buf_start = buf_addr & page_mask;
                    let buf_end = (buf_addr + desc.len() as u64 + 0xFFF) & page_mask;
                    let buf_range_len = buf_end - buf_start;
                    table.push(MemoryRange {
                        gpa: buf_start,
                        length: buf_range_len,
                    });
                    total_bytes += buf_range_len;
                    queue_write_descs += 1;
                }
            }
            write_desc_count += queue_write_descs;

            info!(
                "vDPA {}: queue {}: {} device-writable descriptors, {} indirect descriptors",
                self.id, qi_idx, queue_write_descs, queue_indirect_descs
            );
        }

        info!(
            "vDPA {}: conservative dirty log: {} ranges, {} total bytes ({} KiB), {} write descriptors",
            self.id,
            table.regions().len(),
            total_bytes,
            total_bytes / 1024,
            write_desc_count
        );

        Ok(table)
    }

    fn complete_migration(&mut self) -> std::result::Result<(), MigratableError> {
        self.migrating = false;
        self.suspended = false;
        self.dirty_reported = false;
        Ok(())
    }
}

pub struct VdpaDmaMapping<M: GuestAddressSpace> {
    device: Arc<Mutex<Vdpa>>,
    memory: Arc<M>,
}

impl<M: GuestAddressSpace> VdpaDmaMapping<M> {
    pub fn new(device: Arc<Mutex<Vdpa>>, memory: Arc<M>) -> Self {
        Self { device, memory }
    }
}

impl<M: GuestAddressSpace + Sync + Send> ExternalDmaMapping for VdpaDmaMapping<M> {
    fn map(&self, iova: u64, gpa: u64, size: u64) -> result::Result<(), io::Error> {
        let usize_size = size.try_into().unwrap();
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(gpa);
        let Some(user_addr) = get_host_address_range(&*mem, guest_addr, usize_size) else {
            return Err(io::Error::other(format!(
                "failed to convert guest address 0x{gpa:x} into \
                     host user virtual address"
            )));
        };

        debug!(
            "DMA map iova 0x{:x}, gpa 0x{:x}, size 0x{:x}, host_addr 0x{:x}",
            iova, gpa, size, user_addr as u64
        );
        // SAFETY: get_host_address_range() guarantees that
        // user_addr points to `size` bytes of memory.
        unsafe {
            self.device
                .lock()
                .unwrap()
                .dma_map(iova, size, user_addr, false)
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to map memory for vDPA device, \
                         iova 0x{iova:x}, gpa 0x{gpa:x}, size 0x{size:x}: {e:?}"
                    ))
                })
        }
    }

    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), std::io::Error> {
        debug!("DMA unmap iova 0x{iova:x} size 0x{size:x}");
        self.device
            .lock()
            .unwrap()
            .dma_unmap(iova, size)
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to unmap memory for vDPA device, \
                     iova 0x{iova:x}, size 0x{size:x}: {e:?}"
                ))
            })
    }
}
