// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use iommufd_bindings::iommufd::{
    iommu_hw_info, iommu_hw_info_arm_smmuv3, iommu_hwpt_arm_smmuv3,
    iommu_veventq_flag_IOMMU_VEVENTQ_FLAG_LOST_EVENTS, iommu_viommu_arm_smmuv3_invalidate,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV,
};
use iommufd_ioctls::{
    AttachHwpt, IommufdError, IommufdHwInfoData, IommufdHwptData, IommufdInvalidateData,
    IommufdVDevice, IommufdVEvent, IommufdVEventData, IommufdVEventQ, IommufdVIommu,
    IommufdViommuData,
};
use log::{error, warn};
use pci::{PasidCap, PciBdf};
use thiserror::Error;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::iommu::{
    Error as IommuError, HwInfo, Invalidation, PhysicalIommu, Smmuv3AcpiInfo, TableEntry,
};
use crate::smmuv3::{Error as Smmuv3Error, EventRecord, IDR0_COHACC, Smmuv3, Smmuv3Interrupts};

const VEVENTQ_DEPTH: u32 = 64;

// The STE fields the kernel lets userspace set for a nested stage 1
// (STRTAB_STE_{0,1}_NESTING_ALLOWED, arm-smmu-v3.h).
//   word 0: V [0], Config [3:1], S1Fmt [5:4], S1ContextPtr [51:6],
//           S1CDMax [63:59]
//   word 1: S1DSS [1:0], S1CIR [3:2], S1COR [5:4], S1CSH [7:6],
//           S1STALLD [27], EATS [29:28]
#[cfg(target_arch = "aarch64")]
const STE0_NESTING_ALLOWED: u64 = 0xf80f_ffff_ffff_ffff;
#[cfg(target_arch = "aarch64")]
const STE1_NESTING_ALLOWED: u64 = 0x0000_0000_3800_00ff;

#[cfg(target_arch = "aarch64")]
fn nested_ste(words: &[u64; 8]) -> [u64; 2] {
    [
        words[0] & STE0_NESTING_ALLOWED,
        words[1] & STE1_NESTING_ALLOWED,
    ]
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to query host IOMMU information")]
    QueryHwInfo(#[source] IommufdError),
    #[error("Failed to create vDevice")]
    CreateVdevice(#[source] IommufdError),
    #[error("Failed to attach device to the bypass HWPT")]
    AttachBypass(#[source] IommufdError),
    #[error("Failed to install stage 1 HWPT")]
    InstallStage1(#[source] IommufdError),
    #[error("Failed to uninstall stage 1 HWPT")]
    UninstallStage1(#[source] IommufdError),
    #[error("Failed to invalidate vIOMMU caches")]
    Invalidate(#[source] IommufdError),
    #[error("Failed to allocate vEVENTQ")]
    AllocateVeventq(#[source] IommufdError),
    #[error("Failed to create fault forwarder eventfd")]
    CreateEventFd(#[source] io::Error),
    #[error("Failed to spawn fault forwarder thread")]
    SpawnFaultForwarder(#[source] io::Error),
    #[error("Failed to initialize the emulated SMMUv3 from host information")]
    DeviceInit(#[source] Smmuv3Error),
}

impl From<Error> for IommuError {
    fn from(e: Error) -> Self {
        IommuError::Backend(io::Error::other(e))
    }
}

/// Device attached to the vIOMMU.
struct Endpoint {
    bdf: PciBdf,
    vdevice: IommufdVDevice,
}

/// Iommufd backend of an emulated IOMMU.
pub struct IommufdIommu {
    viommu: Arc<IommufdVIommu>,
    hw_info_data: IommufdHwInfoData,
    ats_supported: bool,
    endpoints: Mutex<BTreeMap<u32, Endpoint>>,
}

impl IommufdIommu {
    pub fn new(viommu: Arc<IommufdVIommu>, dev_id: u32) -> Result<Self, Error> {
        let (hw_info, hw_info_data) = Self::query_hw_info(&viommu, dev_id)?;

        Ok(Self {
            viommu,
            hw_info_data,
            ats_supported: hw_info.out_capabilities
                & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED)
                == 0,
            endpoints: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn allocate_veventq(&self) -> Result<IommufdVEventQ, Error> {
        self.viommu
            .allocate_veventq(VEVENTQ_DEPTH)
            .map_err(Error::AllocateVeventq)
    }

    pub fn register_endpoint(
        &self,
        virt_id: u32,
        bdf: PciBdf,
        device: &Arc<dyn AttachHwpt>,
        dev_id: u32,
    ) -> Result<(), Error> {
        let vdevice = IommufdVDevice::new(
            Arc::clone(&self.viommu),
            Arc::clone(device),
            dev_id,
            u64::from(virt_id),
        )
        .map_err(Error::CreateVdevice)?;
        self.viommu
            .attach_bypass(device.as_ref())
            .map_err(Error::AttachBypass)?;

        self.endpoints
            .lock()
            .unwrap()
            .insert(virt_id, Endpoint { bdf, vdevice });

        Ok(())
    }

    pub fn pasid_cap(&self, dev_id: u32) -> Result<Option<PasidCap>, Error> {
        let (hw_info, _) = Self::query_hw_info(&self.viommu, dev_id)?;
        Ok((hw_info.out_max_pasid_log2 != 0).then(|| {
            PasidCap::new(
                hw_info.out_max_pasid_log2,
                hw_info.out_capabilities
                    & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC)
                    != 0,
                hw_info.out_capabilities
                    & u64::from(iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV)
                    != 0,
            )
        }))
    }

    pub fn attached_bdfs(&self) -> Vec<PciBdf> {
        self.endpoints
            .lock()
            .unwrap()
            .values()
            .map(|endpoint| endpoint.bdf)
            .collect()
    }

    fn query_hw_info(
        viommu: &IommufdVIommu,
        dev_id: u32,
    ) -> Result<(iommu_hw_info, IommufdHwInfoData), Error> {
        // The buffer to fill depends on the IOMMU the host reports.
        let mut hw_info_data = match viommu.data() {
            IommufdViommuData::Smmuv3 | IommufdViommuData::Tegra241Cmdqv { .. } => {
                IommufdHwInfoData::Smmuv3(iommu_hw_info_arm_smmuv3::default())
            }
        };
        let hw_info = viommu
            .iommufd()
            .device_hw_info(dev_id, &mut hw_info_data)
            .map_err(Error::QueryHwInfo)?;

        Ok((hw_info, hw_info_data))
    }

    fn uninstall_s1(&self, device_id: u32, abort: bool) -> Result<(), IommuError> {
        let mut endpoints = self.endpoints.lock().unwrap();
        let Some(endpoint) = endpoints.get_mut(&device_id) else {
            return Ok(());
        };
        endpoint
            .vdevice
            .uninstall_s1_hwpt(abort)
            .map_err(Error::UninstallStage1)?;

        Ok(())
    }
}

impl PhysicalIommu for IommufdIommu {
    fn hw_info(&self) -> Result<HwInfo, IommuError> {
        match self.hw_info_data {
            #[cfg(target_arch = "aarch64")]
            IommufdHwInfoData::Smmuv3(info) => Ok(HwInfo::Smmuv3 {
                idr: info.idr,
                ats_supported: self.ats_supported,
            }),
        }
    }

    fn install_table_entry(&self, device_id: u32, entry: TableEntry) -> Result<(), IommuError> {
        let hwpt_data = match entry {
            #[cfg(target_arch = "aarch64")]
            TableEntry::Smmuv3Ste(words) => IommufdHwptData::Smmuv3(iommu_hwpt_arm_smmuv3 {
                ste: nested_ste(&words),
            }),
        };

        let mut endpoints = self.endpoints.lock().unwrap();
        let Some(endpoint) = endpoints.get_mut(&device_id) else {
            return Ok(());
        };
        endpoint
            .vdevice
            .install_s1_hwpt(&hwpt_data)
            .map_err(Error::InstallStage1)?;

        Ok(())
    }

    fn set_passthrough(&self, device_id: u32) -> Result<(), IommuError> {
        self.uninstall_s1(device_id, false)
    }

    fn set_blocking(&self, device_id: u32) -> Result<(), IommuError> {
        self.uninstall_s1(device_id, true)
    }

    fn invalidate(&self, invalidation: Invalidation) -> Result<(), IommuError> {
        let mut data = match invalidation {
            #[cfg(target_arch = "aarch64")]
            Invalidation::Smmuv3Cmd(cmd) => {
                IommufdInvalidateData::Smmuv3(iommu_viommu_arm_smmuv3_invalidate { cmd })
            }
        };
        let applied = self
            .viommu
            .invalidate(&mut data)
            .map_err(Error::Invalidate)?;
        if !applied {
            warn!("Invalidation was not applied by the host");
        }

        Ok(())
    }
}

/// Emulated SMMUv3 backed by iommufd.
#[cfg(target_arch = "aarch64")]
pub struct Smmuv3Iommufd {
    device: Arc<Mutex<Smmuv3>>,
    backend: Arc<IommufdIommu>,
    acpi_info: Smmuv3AcpiInfo,
    _fault_forwarder: FaultForwarder,
}

#[cfg(target_arch = "aarch64")]
impl Smmuv3Iommufd {
    pub fn new(
        id: String,
        mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
        interrupts: Smmuv3Interrupts,
        acpi_info: Smmuv3AcpiInfo,
        viommu: Arc<IommufdVIommu>,
        dev_id: u32,
    ) -> Result<Self, Error> {
        let backend = Arc::new(IommufdIommu::new(viommu, dev_id)?);
        let IommufdHwInfoData::Smmuv3(host_info) = backend.hw_info_data;
        let acpi_info = Smmuv3AcpiInfo {
            coherent: host_info.idr[0] & IDR0_COHACC != 0,
            ats_supported: backend.ats_supported,
            ..acpi_info
        };
        let mut device = Smmuv3::new(
            id,
            mem,
            interrupts,
            Arc::clone(&backend) as Arc<dyn PhysicalIommu>,
            None,
        );
        device.initialize().map_err(Error::DeviceInit)?;
        let device = Arc::new(Mutex::new(device));
        let fault_forwarder =
            FaultForwarder::new(backend.allocate_veventq()?, Arc::clone(&device))?;

        Ok(Self {
            device,
            backend,
            acpi_info,
            _fault_forwarder: fault_forwarder,
        })
    }

    /// Stream ID of a device encoded similarly to the ITS Device ID in the
    /// IORT table. There are 256 identifiers per PCI segment with a single
    /// bus per segment.
    pub fn stream_id(bdf: PciBdf) -> u32 {
        256 * u32::from(bdf.segment()) + (u32::from(bdf) & 0xff)
    }

    pub fn device(&self) -> &Arc<Mutex<Smmuv3>> {
        &self.device
    }

    pub fn backend(&self) -> &Arc<IommufdIommu> {
        &self.backend
    }

    pub fn acpi_info(&self) -> Smmuv3AcpiInfo {
        Smmuv3AcpiInfo {
            attached_bdfs: self.backend.attached_bdfs(),
            ..self.acpi_info.clone()
        }
    }
}

/// Thread forwarding vEVENTQ records to the emulated SMMUv3.
struct FaultForwarder {
    kill: EventFd,
    handle: Option<JoinHandle<()>>,
}

impl FaultForwarder {
    fn new(mut veventq: IommufdVEventQ, device: Arc<Mutex<Smmuv3>>) -> Result<Self, Error> {
        let kill = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateEventFd)?;
        let kill_reader = kill.try_clone().map_err(Error::CreateEventFd)?;

        let handle = thread::Builder::new()
            .name("smmuv3_veventq".to_string())
            .spawn(move || Self::epoll_event_queue(&mut veventq, &device, &kill_reader))
            .map_err(Error::SpawnFaultForwarder)?;

        Ok(FaultForwarder {
            kill,
            handle: Some(handle),
        })
    }

    fn epoll_event_queue(veventq: &mut IommufdVEventQ, device: &Mutex<Smmuv3>, kill: &EventFd) {
        const VEVENTQ_TOKEN: u64 = 0;
        const KILL_TOKEN: u64 = 1;

        let epoll = match Epoll::new() {
            Ok(epoll) => epoll,
            Err(e) => {
                error!("SMMUv3 vEVENTQ reader failed to create epoll: {e}");
                return;
            }
        };
        for (fd, token) in [
            (veventq.as_raw_fd(), VEVENTQ_TOKEN),
            (kill.as_raw_fd(), KILL_TOKEN),
        ] {
            if let Err(e) = epoll.ctl(
                ControlOperation::Add,
                fd,
                EpollEvent::new(EventSet::IN, token),
            ) {
                error!("SMMUv3 vEVENTQ reader failed to register fd {fd}: {e}");
                return;
            }
        }

        let mut events = [EpollEvent::default(); 2];
        loop {
            let count = match epoll.wait(-1, &mut events) {
                Ok(count) => count,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!("SMMUv3 vEVENTQ reader epoll wait failed: {e}");
                    return;
                }
            };

            for event in events.iter().take(count) {
                match event.data() {
                    KILL_TOKEN => return,
                    VEVENTQ_TOKEN => match veventq.read_events() {
                        Ok(records) => {
                            let mut device = device.lock().unwrap();
                            for record in records {
                                Self::forward_record(&mut device, record);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => warn!("SMMUv3 vEVENTQ read failed: {e}"),
                    },
                    _ => unreachable!(),
                }
            }
        }
    }

    fn forward_record(device: &mut Smmuv3, record: IommufdVEvent) {
        if record.lost > 0 {
            warn!(
                "SMMUv3 vEVENTQ lost {} events before sequence {}",
                record.lost, record.header.sequence
            );
            device.set_event_overflow();
        }

        match record.data {
            Some(IommufdVEventData::Smmuv3(evt)) => {
                if let Err(e) = device.push_event(&EventRecord(evt.evt)) {
                    warn!("SMMUv3 failed to push a guest event: {e}");
                }
            }
            Some(IommufdVEventData::Tegra241Cmdqv(_)) => {
                warn!("SMMUv3 vEVENTQ yielded an unexpected CMDQV record");
            }
            // Header without a record.
            None => {
                if record.header.flags & iommu_veventq_flag_IOMMU_VEVENTQ_FLAG_LOST_EVENTS == 0 {
                    warn!("SMMUv3 vEVENTQ yielded a header with no record");
                } else {
                    warn!("SMMUv3 vEVENTQ lost events at the tail");
                }
                device.set_event_overflow();
            }
        }
    }
}

impl Drop for FaultForwarder {
    fn drop(&mut self) {
        if let Err(e) = self.kill.write(1) {
            error!("SMMUv3 failed to signal vEVENTQ reader shutdown: {e}");
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;

    // GENMASK_ULL(high, low)
    fn genmask(high: u32, low: u32) -> u64 {
        (u64::MAX >> (63 - high)) & (u64::MAX << low)
    }

    #[test]
    fn test_nested_ste_keeps_only_the_fields_the_kernel_allows() {
        // V, Config, S1Fmt, S1ContextPtr, S1CDMax
        let ste0 = genmask(0, 0) | genmask(3, 1) | genmask(5, 4) | genmask(51, 6) | genmask(63, 59);
        // S1DSS, S1CIR, S1COR, S1CSH, S1STALLD, EATS
        let ste1 = genmask(1, 0)
            | genmask(3, 2)
            | genmask(5, 4)
            | genmask(7, 6)
            | genmask(27, 27)
            | genmask(29, 28);

        assert_eq!(nested_ste(&[u64::MAX; 8]), [ste0, ste1]);
    }

    #[test]
    fn test_nested_ste_clears_host_owned_fields() {
        // V, Config = stage 1 only, S1ContextPtr, S1CDMax = 4
        let ste0: u64 = 1 | (0b101 << 1) | 0x8000_1000 | (4 << 59);
        // S1CIR = S1COR = WBRA, S1CSH = inner shareable
        let ste1: u64 = (1 << 2) | (1 << 4) | (3 << 6);
        let mev = 1 << 19;
        let s2fwb = 1 << 25;
        let strw_el2 = 2 << 30;
        let shcfg_incoming = 1 << 44;

        let mut words = [u64::MAX; 8];
        words[0] = ste0;
        words[1] = ste1 | mev | s2fwb | strw_el2 | shcfg_incoming;

        assert_eq!(nested_ste(&words), [ste0, ste1]);
    }
}
