// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use iommufd_bindings::iommufd::{
    iommu_hw_info, iommu_hw_info_arm_smmuv3, iommu_hw_info_tegra241_cmdqv, iommu_hwpt_arm_smmuv3,
    iommu_veventq_flag_IOMMU_VEVENTQ_FLAG_LOST_EVENTS, iommu_viommu_arm_smmuv3_invalidate,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_ATS_NOT_SUPPORTED,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_EXEC,
    iommufd_hw_capabilities_IOMMU_HW_CAP_PCI_PASID_PRIV,
};
use iommufd_ioctls::{
    AttachHwpt, IommuFd, IommufdError, IommufdHwInfoData, IommufdHwQueue, IommufdHwptData,
    IommufdInvalidateData, IommufdVDevice, IommufdVEvent, IommufdVEventData, IommufdVEventQ,
    IommufdVIommu, IommufdViommuData,
};
use log::{error, warn};
use pci::{PasidCap, PciBdf};
use thiserror::Error;
use vm_allocator::{GuestMemory, GuestRegion};
use vm_memory::{FileOffset, GuestMemoryAtomic};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::iommu::{
    Error as IommuError, HwInfo, HwQueueHandle, Invalidation, PhysicalIommu, Smmuv3AcpiInfo,
    TableEntry,
};
use crate::smmuv3::{Error as Smmuv3Error, EventRecord, IDR0_COHACC, Smmuv3, Smmuv3Interrupts};
use crate::tegra241_cmdqv::{Tegra241Cmdqv, Tegra241CmdqvConfig, VCMDQ_PAGE0_SIZE};

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
    #[error("The host reported unexpected hardware information")]
    UnexpectedHwInfo,
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
    #[error("Unexpected VINTF page size {0:#x}")]
    VintfPageSize(u64),
    #[error("Failed to duplicate the iommufd")]
    DupIommufd(#[source] io::Error),
    #[error("Failed to allocate a hardware queue")]
    AllocateHwQueue(#[source] IommufdError),
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
    hw_info_data: iommu_hw_info_arm_smmuv3,
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
    ) -> Result<(iommu_hw_info, iommu_hw_info_arm_smmuv3), Error> {
        let mut hw_info_data = IommufdHwInfoData::Smmuv3(iommu_hw_info_arm_smmuv3::default());
        let hw_info = viommu
            .iommufd()
            .device_hw_info(dev_id, &mut hw_info_data)
            .map_err(Error::QueryHwInfo)?;
        let IommufdHwInfoData::Smmuv3(hw_info_data) = hw_info_data else {
            return Err(Error::UnexpectedHwInfo);
        };

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
        Ok(HwInfo::Smmuv3 {
            idr: self.hw_info_data.idr,
            ats_supported: self.ats_supported,
        })
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

    fn allocate_hw_queue(
        &self,
        index: u32,
        addr: u64,
        size: u64,
    ) -> Result<Box<dyn HwQueueHandle>, IommuError> {
        let hw_queue = self
            .viommu
            .allocate_hw_queue(index, addr, size)
            .map_err(Error::AllocateHwQueue)?;

        Ok(Box::new(hw_queue))
    }
}

impl HwQueueHandle for IommufdHwQueue {}

#[cfg(target_arch = "aarch64")]
pub struct HostCmdqv {
    pub num_vcmdqs_log2: u8,
    pub num_sids_log2: u8,
}

/// Emulated SMMUv3 backed by iommufd.
#[cfg(target_arch = "aarch64")]
pub struct Smmuv3Iommufd {
    device: Arc<Mutex<Smmuv3>>,
    backend: Arc<IommufdIommu>,
    acpi_info: Smmuv3AcpiInfo,
    _fault_forwarder: FaultForwarder,

    // cmdqv
    vintf_page: Option<FileOffset>,
    // VINTF page mappings, dropped before `cmdqv`, whose backend holds the
    // vIOMMU they pin
    vintf_regions: Vec<GuestRegion>,
    cmdqv: Option<Arc<Mutex<Tegra241Cmdqv>>>,
}

#[cfg(target_arch = "aarch64")]
impl Smmuv3Iommufd {
    pub fn host_cmdqv(iommufd: &IommuFd, dev_id: u32) -> Option<HostCmdqv> {
        let mut hw_info_data =
            IommufdHwInfoData::Tegra241Cmdqv(iommu_hw_info_tegra241_cmdqv::default());
        match iommufd.device_hw_info(dev_id, &mut hw_info_data) {
            Ok(_) => {}
            Err(IommufdError::IommuGetHwInfo(e)) if e.errno() == libc::EOPNOTSUPP => return None,
            Err(e) => {
                warn!("Failed to query the host Tegra241 CMDQV: {e}");
                return None;
            }
        }

        match hw_info_data {
            IommufdHwInfoData::Tegra241Cmdqv(hw_info) if hw_info.version == 1 => Some(HostCmdqv {
                num_vcmdqs_log2: hw_info.log2vcmdqs,
                num_sids_log2: hw_info.log2vsids,
            }),
            IommufdHwInfoData::Tegra241Cmdqv(hw_info) => {
                warn!("Unsupported Tegra241 CMDQV version {}", hw_info.version);
                None
            }
            _ => {
                warn!("The host reported unexpected Tegra241 CMDQV information");
                None
            }
        }
    }

    pub fn new(
        id: String,
        mem: GuestMemoryAtomic<GuestMemory>,
        interrupts: Smmuv3Interrupts,
        acpi_info: Smmuv3AcpiInfo,
        viommu: Arc<IommufdVIommu>,
        dev_id: u32,
        cmdqv: Option<Tegra241CmdqvConfig>,
    ) -> Result<Self, Error> {
        let vintf_page = match viommu.data() {
            IommufdViommuData::Smmuv3 => None,
            IommufdViommuData::Tegra241Cmdqv {
                mmap_offset,
                mmap_length,
            } => Some(Self::vintf_page_file(&viommu, mmap_offset, mmap_length)?),
        };
        let backend = Arc::new(IommufdIommu::new(viommu, dev_id)?);
        let cmdqv_id = format!("{id}_cmdqv");
        let host_info = backend.hw_info_data;
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
        let cmdqv = cmdqv.map(|config| {
            Arc::new(Mutex::new(Tegra241Cmdqv::new(
                cmdqv_id,
                config,
                Arc::clone(&backend) as Arc<dyn PhysicalIommu>,
            )))
        });
        // The guest sizes its VCMDQs from CMDQS, and the host takes none
        // larger than its own CMDQS allows.
        if cmdqv.is_some() {
            device.set_max_cmdq_size(Smmuv3::max_cmdq_size(host_info.idr[1]));
        }
        let device = Arc::new(Mutex::new(device));
        let fault_forwarder = FaultForwarder::new(vec![Veventq::Smmuv3(
            backend.allocate_veventq()?,
            Arc::clone(&device),
        )])?;

        Ok(Self {
            vintf_page,
            vintf_regions: Vec::new(),
            device,
            cmdqv,
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

    pub fn cmdqv(&self) -> Option<&Arc<Mutex<Tegra241Cmdqv>>> {
        self.cmdqv.as_ref()
    }

    pub fn backend(&self) -> &Arc<IommufdIommu> {
        &self.backend
    }

    /// The host VINTF page backing the guest's VCMDQ page0s, to be mmapped
    /// with a length of `VCMDQ_PAGE0_SIZE`.
    pub fn vintf_page(&self) -> Option<&FileOffset> {
        self.vintf_page.as_ref()
    }

    fn vintf_page_file(viommu: &IommufdVIommu, offset: u64, len: u64) -> Result<FileOffset, Error> {
        if len != VCMDQ_PAGE0_SIZE {
            return Err(Error::VintfPageSize(len));
        }
        // SAFETY: the vIOMMU keeps the iommufd open.
        let fd = unsafe { BorrowedFd::borrow_raw(viommu.iommufd().as_raw_fd()) };
        let file = File::from(fd.try_clone_to_owned().map_err(Error::DupIommufd)?);

        Ok(FileOffset::new(file, offset))
    }

    pub fn set_vintf_regions(&mut self, regions: Vec<GuestRegion>) {
        self.vintf_regions = regions;
    }

    pub fn acpi_info(&self) -> Smmuv3AcpiInfo {
        Smmuv3AcpiInfo {
            attached_bdfs: self.backend.attached_bdfs(),
            ..self.acpi_info.clone()
        }
    }
}

enum Veventq {
    Smmuv3(IommufdVEventQ, Arc<Mutex<Smmuv3>>),
}

impl Veventq {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Veventq::Smmuv3(veventq, _) => veventq.as_raw_fd(),
        }
    }
}

/// Thread forwarding vEVENTQ records to the emulated SMMUv3.
struct FaultForwarder {
    kill: EventFd,
    handle: Option<JoinHandle<()>>,
}

impl FaultForwarder {
    fn new(mut veventqs: Vec<Veventq>) -> Result<Self, Error> {
        let kill = EventFd::new(EFD_NONBLOCK).map_err(Error::CreateEventFd)?;
        let kill_reader = kill.try_clone().map_err(Error::CreateEventFd)?;

        let handle = thread::Builder::new()
            .name("smmuv3_veventq".to_string())
            .spawn(move || Self::epoll_event_queue(&mut veventqs, &kill_reader))
            .map_err(Error::SpawnFaultForwarder)?;

        Ok(FaultForwarder {
            kill,
            handle: Some(handle),
        })
    }

    fn epoll_event_queue(veventqs: &mut [Veventq], kill: &EventFd) {
        // vEVENTQ i has token i.
        const KILL_TOKEN: u64 = u64::MAX;

        let epoll = match Epoll::new() {
            Ok(epoll) => epoll,
            Err(e) => {
                error!("SMMUv3 vEVENTQ reader failed to create epoll: {e}");
                return;
            }
        };
        let fds = veventqs
            .iter()
            .enumerate()
            .map(|(token, veventq)| (veventq.as_raw_fd(), token as u64))
            .chain([(kill.as_raw_fd(), KILL_TOKEN)]);
        for (fd, token) in fds {
            if let Err(e) = epoll.ctl(
                ControlOperation::Add,
                fd,
                EpollEvent::new(EventSet::IN, token),
            ) {
                error!("SMMUv3 vEVENTQ reader failed to register fd {fd}: {e}");
                return;
            }
        }

        let mut events = vec![EpollEvent::default(); veventqs.len() + 1];
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
                if event.data() == KILL_TOKEN {
                    return;
                }
                match &mut veventqs[event.data() as usize] {
                    Veventq::Smmuv3(veventq, device) => match veventq.read_events() {
                        Ok(records) => {
                            let mut device = device.lock().unwrap();
                            for record in records {
                                Self::forward_record(&mut device, record);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => warn!("SMMUv3 vEVENTQ read failed: {e}"),
                    },
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
