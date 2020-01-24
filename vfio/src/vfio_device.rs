// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::vec_with_array_field;
use arc_swap::ArcSwap;
use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem;
use std::num;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::result;
use std::sync::Arc;
use std::u32;
use vfio_bindings::bindings::vfio::*;
use vfio_bindings::bindings::IrqSet;
use vfio_ioctls::*;
use vm_device::{get_host_address_range, ExternalDmaMapping};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::fam::FamStruct;
use vmm_sys_util::ioctl::*;

#[derive(Debug)]
pub enum VfioError {
    OpenContainer(io::Error),
    OpenGroup(io::Error),
    GetGroupStatus,
    GroupViable,
    VfioApiVersion,
    VfioExtension,
    VfioInvalidType,
    VfioType1V2,
    GroupSetContainer,
    UnsetContainer,
    ContainerSetIOMMU,
    GroupGetDeviceFD,
    KvmSetDeviceAttr(kvm_ioctls::Error),
    VfioDeviceGetInfo,
    VfioDeviceGetRegionInfo,
    InvalidPath,
    IommuDmaMap,
    IommuDmaUnmap,
    VfioDeviceGetIrqInfo,
    VfioDeviceSetIrq,
    ReadLink(io::Error),
    ParseInt(num::ParseIntError),
}
pub type Result<T> = std::result::Result<T, VfioError>;

impl fmt::Display for VfioError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VfioError::OpenContainer(e) => {
                write!(f, "failed to open /dev/vfio/vfio container: {}", e)
            }
            VfioError::OpenGroup(e) => {
                write!(f, "failed to open /dev/vfio/$group_num group: {}", e)
            }
            VfioError::GetGroupStatus => write!(f, "failed to get Group Status"),
            VfioError::GroupViable => write!(f, "group is inviable"),
            VfioError::VfioApiVersion => write!(
                f,
                "vfio API version doesn't match with VFIO_API_VERSION defined in vfio-bindings"
            ),
            VfioError::VfioExtension => write!(f, "failed to check VFIO extension"),
            VfioError::VfioInvalidType => write!(f, "invalid VFIO type"),
            VfioError::VfioType1V2 => {
                write!(f, "container dones't support VfioType1V2 IOMMU driver type")
            }
            VfioError::GroupSetContainer => {
                write!(f, "failed to add vfio group into vfio container")
            }
            VfioError::UnsetContainer => write!(f, "failed to unset vfio container"),
            VfioError::ContainerSetIOMMU => write!(
                f,
                "failed to set container's IOMMU driver type as VfioType1V2"
            ),
            VfioError::GroupGetDeviceFD => write!(f, "failed to get vfio device fd"),
            VfioError::KvmSetDeviceAttr(e) => {
                write!(f, "failed to set KVM vfio device's attribute: {}", e)
            }
            VfioError::VfioDeviceGetInfo => {
                write!(f, "failed to get vfio device's info or info doesn't match")
            }
            VfioError::VfioDeviceGetRegionInfo => {
                write!(f, "failed to get vfio device's region info")
            }
            VfioError::InvalidPath => write!(f, "invalid file path"),
            VfioError::IommuDmaMap => write!(f, "failed to add guest memory map into iommu table"),
            VfioError::IommuDmaUnmap => {
                write!(f, "failed to remove guest memory map from iommu table")
            }
            VfioError::VfioDeviceGetIrqInfo => write!(f, "failed to get vfio device irq info"),
            VfioError::VfioDeviceSetIrq => write!(f, "failed to set vfio deviece irq"),
            VfioError::ReadLink(e) => write!(f, "failed to read link from path: {}", e),
            VfioError::ParseInt(e) => write!(f, "failed to parse integer: {}", e),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
struct vfio_region_info_with_cap {
    region_info: vfio_region_info,
    cap_info: __IncompleteArrayField<u8>,
}

pub struct VfioContainer {
    container: File,
}

impl VfioContainer {
    fn new() -> Result<Self> {
        let container = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .map_err(VfioError::OpenContainer)?;

        Ok(VfioContainer { container })
    }

    fn get_api_version(&self) -> i32 {
        // Safe as file is vfio container fd and ioctl is defined by kernel.
        unsafe { ioctl(self, VFIO_GET_API_VERSION()) }
    }

    fn check_extension(&self, val: u32) -> Result<()> {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            return Err(VfioError::VfioInvalidType);
        }

        // Safe as file is vfio container and make sure val is valid.
        let ret = unsafe { ioctl_with_val(self, VFIO_CHECK_EXTENSION(), val.into()) };
        if ret != 1 {
            return Err(VfioError::VfioExtension);
        }

        Ok(())
    }

    fn set_iommu(&self, val: u32) -> Result<()> {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            return Err(VfioError::VfioInvalidType);
        }

        // Safe as file is vfio container and make sure val is valid.
        let ret = unsafe { ioctl_with_val(self, VFIO_SET_IOMMU(), val.into()) };
        if ret < 0 {
            return Err(VfioError::ContainerSetIOMMU);
        }

        Ok(())
    }

    pub fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        let dma_map = vfio_iommu_type1_dma_map {
            argsz: mem::size_of::<vfio_iommu_type1_dma_map>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: user_addr,
            iova,
            size,
        };

        // Safe as file is vfio container, dma_map is constructed by us, and
        // we check the return value
        let ret = unsafe { ioctl_with_ref(self, VFIO_IOMMU_MAP_DMA(), &dma_map) };
        if ret != 0 {
            return Err(VfioError::IommuDmaMap);
        }

        Ok(())
    }

    pub fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        let mut dma_unmap = vfio_iommu_type1_dma_unmap {
            argsz: mem::size_of::<vfio_iommu_type1_dma_unmap>() as u32,
            flags: 0,
            iova,
            size,
        };

        // Safe as file is vfio container, dma_unmap is constructed by us, and
        // we check the return value
        let ret = unsafe { ioctl_with_mut_ref(self, VFIO_IOMMU_UNMAP_DMA(), &mut dma_unmap) };
        if ret != 0 || dma_unmap.size != size {
            return Err(VfioError::IommuDmaUnmap);
        }

        Ok(())
    }
}

impl AsRawFd for VfioContainer {
    fn as_raw_fd(&self) -> RawFd {
        self.container.as_raw_fd()
    }
}

struct VfioGroup {
    group: File,
    device: Arc<DeviceFd>,
    container: Arc<VfioContainer>,
}

impl VfioGroup {
    fn new(id: u32, device: Arc<DeviceFd>) -> Result<Self> {
        let group_path = Path::new("/dev/vfio").join(id.to_string());
        let group = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&group_path)
            .map_err(VfioError::OpenGroup)?;

        let mut group_status = vfio_group_status {
            argsz: mem::size_of::<vfio_group_status>() as u32,
            flags: 0,
        };
        // Safe as we are the owner of group and group_status which are valid value.
        let mut ret =
            unsafe { ioctl_with_mut_ref(&group, VFIO_GROUP_GET_STATUS(), &mut group_status) };
        if ret < 0 {
            return Err(VfioError::GetGroupStatus);
        }

        if group_status.flags != VFIO_GROUP_FLAGS_VIABLE {
            return Err(VfioError::GroupViable);
        }

        let container = Arc::new(VfioContainer::new()?);
        if container.get_api_version() as u32 != VFIO_API_VERSION {
            return Err(VfioError::VfioApiVersion);
        }

        container.check_extension(VFIO_TYPE1v2_IOMMU)?;

        // Safe as we are the owner of group and container_raw_fd which are valid value,
        // and we verify the ret value
        let container_raw_fd = container.as_raw_fd();
        ret = unsafe { ioctl_with_ref(&group, VFIO_GROUP_SET_CONTAINER(), &container_raw_fd) };
        if ret < 0 {
            return Err(VfioError::GroupSetContainer);
        }

        container.set_iommu(VFIO_TYPE1v2_IOMMU)?;

        Self::kvm_device_add_group(&device, &group)?;

        Ok(VfioGroup {
            group,
            device,
            container,
        })
    }

    fn kvm_device_add_group(device_fd: &Arc<DeviceFd>, group: &File) -> Result<()> {
        let group_fd = group.as_raw_fd();
        let group_fd_ptr = &group_fd as *const i32;
        let dev_attr = kvm_bindings::kvm_device_attr {
            flags: 0,
            group: kvm_bindings::KVM_DEV_VFIO_GROUP,
            attr: u64::from(kvm_bindings::KVM_DEV_VFIO_GROUP_ADD),
            addr: group_fd_ptr as u64,
        };

        device_fd
            .set_device_attr(&dev_attr)
            .map_err(VfioError::KvmSetDeviceAttr)
    }

    fn kvm_device_del_group(&self) -> std::result::Result<(), kvm_ioctls::Error> {
        let group_fd = self.as_raw_fd();
        let group_fd_ptr = &group_fd as *const i32;
        let dev_attr = kvm_bindings::kvm_device_attr {
            flags: 0,
            group: kvm_bindings::KVM_DEV_VFIO_GROUP,
            attr: u64::from(kvm_bindings::KVM_DEV_VFIO_GROUP_DEL),
            addr: group_fd_ptr as u64,
        };

        self.device.set_device_attr(&dev_attr)
    }

    fn unset_container(&self) -> std::result::Result<(), io::Error> {
        let container_raw_fd = self.container.as_raw_fd();

        // Safe as we are the owner of self and container_raw_fd which are valid value.
        let ret = unsafe { ioctl_with_ref(self, VFIO_GROUP_UNSET_CONTAINER(), &container_raw_fd) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn get_device(&self, name: &Path) -> Result<VfioDeviceInfo> {
        let uuid_osstr = name.file_name().ok_or(VfioError::InvalidPath)?;
        let uuid_str = uuid_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let path: CString = CString::new(uuid_str.as_bytes()).expect("CString::new() failed");
        let path_ptr = path.as_ptr();

        // Safe as we are the owner of self and path_ptr which are valid value.
        let fd = unsafe { ioctl_with_ptr(self, VFIO_GROUP_GET_DEVICE_FD(), path_ptr) };
        if fd < 0 {
            return Err(VfioError::GroupGetDeviceFD);
        }

        // Safe as fd is valid FD
        let device = unsafe { File::from_raw_fd(fd) };

        let mut dev_info = vfio_device_info {
            argsz: mem::size_of::<vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
        };
        // Safe as we are the owner of dev and dev_info which are valid value,
        // and we verify the return value.
        let ret = unsafe { ioctl_with_mut_ref(&device, VFIO_DEVICE_GET_INFO(), &mut dev_info) };
        if ret < 0
            || (dev_info.flags & VFIO_DEVICE_FLAGS_PCI) == 0
            || dev_info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX + 1
            || dev_info.num_irqs < VFIO_PCI_MSIX_IRQ_INDEX + 1
        {
            return Err(VfioError::VfioDeviceGetInfo);
        }

        Ok(VfioDeviceInfo {
            device,
            flags: dev_info.flags,
            num_regions: dev_info.num_regions,
            num_irqs: dev_info.num_irqs,
        })
    }
}

impl AsRawFd for VfioGroup {
    fn as_raw_fd(&self) -> RawFd {
        self.group.as_raw_fd()
    }
}

impl Drop for VfioGroup {
    fn drop(&mut self) {
        match self.kvm_device_del_group() {
            Ok(_) => {}
            Err(e) => {
                error!("Could not delete VFIO group: {:?}", e);
            }
        }

        match self.unset_container() {
            Ok(_) => {}
            Err(e) => {
                error!("Could not unset container: {:?}", e);
            }
        }
    }
}

struct VfioRegion {
    flags: u32,
    size: u64,
    offset: u64,
    mmap: (u64, u64),
}

struct VfioIrq {
    flags: u32,
    index: u32,
    count: u32,
}

struct VfioDeviceInfo {
    device: File,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
}

impl VfioDeviceInfo {
    fn get_irqs(&self) -> Result<HashMap<u32, VfioIrq>> {
        let mut irqs: HashMap<u32, VfioIrq> = HashMap::new();

        for index in 0..self.num_irqs {
            let mut irq_info = vfio_irq_info {
                argsz: mem::size_of::<vfio_irq_info>() as u32,
                flags: 0,
                index,
                count: 0,
            };

            let ret = unsafe {
                ioctl_with_mut_ref(&self.device, VFIO_DEVICE_GET_IRQ_INFO(), &mut irq_info)
            };
            if ret < 0 {
                warn!("Could not get VFIO IRQ info for index {:}", index);
                continue;
            }

            let irq = VfioIrq {
                flags: irq_info.flags,
                index,
                count: irq_info.count,
            };

            debug!("IRQ #{}", index);
            debug!("\tflag 0x{:x}", irq.flags);
            debug!("\tindex {}", irq.index);
            debug!("\tcount {}", irq.count);

            irqs.insert(index, irq);
        }

        Ok(irqs)
    }

    fn get_regions(&self) -> Result<Vec<VfioRegion>> {
        let mut regions: Vec<VfioRegion> = Vec::new();

        for i in VFIO_PCI_BAR0_REGION_INDEX..self.num_regions {
            let argsz: u32 = mem::size_of::<vfio_region_info>() as u32;

            let mut reg_info = vfio_region_info {
                argsz,
                flags: 0,
                index: i,
                cap_offset: 0,
                size: 0,
                offset: 0,
            };
            // Safe as we are the owner of dev and reg_info which are valid value,
            // and we verify the return value.
            let mut ret = unsafe {
                ioctl_with_mut_ref(&self.device, VFIO_DEVICE_GET_REGION_INFO(), &mut reg_info)
            };
            if ret < 0 {
                warn!("Could not get region #{} info", i);
                continue;
            }

            let mut mmap_size: u64 = reg_info.size;
            let mut mmap_offset: u64 = 0;
            if reg_info.flags & VFIO_REGION_INFO_FLAG_CAPS != 0 && reg_info.argsz > argsz {
                let cap_len: usize = (reg_info.argsz - argsz) as usize;
                let mut region_with_cap =
                    vec_with_array_field::<vfio_region_info_with_cap, u8>(cap_len);
                region_with_cap[0].region_info.argsz = reg_info.argsz;
                region_with_cap[0].region_info.flags = 0;
                region_with_cap[0].region_info.index = i;
                region_with_cap[0].region_info.cap_offset = 0;
                region_with_cap[0].region_info.size = 0;
                region_with_cap[0].region_info.offset = 0;
                // Safe as we are the owner of dev and region_info which are valid value,
                // and we verify the return value.
                ret = unsafe {
                    ioctl_with_mut_ref(
                        &self.device,
                        VFIO_DEVICE_GET_REGION_INFO(),
                        &mut (region_with_cap[0].region_info),
                    )
                };
                if ret < 0 {
                    warn!("Could not get region #{} info", i);
                    continue;
                }
                // region_with_cap[0].cap_info may contain vfio_region_info_cap_sparse_mmap
                // struct or vfio_region_info_cap_type struct. Both of them begin with
                // vfio_info_cap_header.
                // so safe to convert cap_info into vfio_info_cap_header pointer first, and
                // safe to access its elments through this poiner.
                #[allow(clippy::cast_ptr_alignment)]
                let cap_header =
                    unsafe { region_with_cap[0].cap_info.as_ptr() as *const vfio_info_cap_header };
                if unsafe { u32::from((*cap_header).id) } == VFIO_REGION_INFO_CAP_SPARSE_MMAP {
                    // cap_info is vfio_region_sparse_mmap here
                    // so safe to convert cap_info into vfio_info_region_sparse_mmap pointer, and
                    // safe to access its elements through this pointer.
                    #[allow(clippy::cast_ptr_alignment)]
                    let sparse_mmap = unsafe {
                        region_with_cap[0].cap_info.as_ptr()
                            as *const vfio_region_info_cap_sparse_mmap
                    };
                    let mmap_area = unsafe {
                        (*sparse_mmap).areas.as_ptr() as *const vfio_region_sparse_mmap_area
                    };
                    mmap_size = unsafe { (*mmap_area).size };
                    mmap_offset = unsafe { (*mmap_area).offset };
                }
            }

            let region = VfioRegion {
                flags: reg_info.flags,
                size: reg_info.size,
                offset: reg_info.offset,
                mmap: (mmap_offset, mmap_size),
            };

            debug!("Region #{}", i);
            debug!("\tflag 0x{:x}", region.flags);
            debug!("\tsize 0x{:x}", region.size);
            debug!("\toffset 0x{:x}", region.offset);

            regions.push(region);
        }

        Ok(regions)
    }
}

/// This structure implements the ExternalDmaMapping trait. It is meant to
/// be used when the caller tries to provide a way to update the mappings
/// associated with a specific VFIO container.
pub struct VfioDmaMapping {
    container: Arc<VfioContainer>,
    memory: Arc<ArcSwap<GuestMemoryMmap>>,
}

impl VfioDmaMapping {
    pub fn new(container: Arc<VfioContainer>, memory: Arc<ArcSwap<GuestMemoryMmap>>) -> Self {
        VfioDmaMapping { container, memory }
    }
}

impl ExternalDmaMapping for VfioDmaMapping {
    fn map(&self, iova: u64, gpa: u64, size: u64) -> result::Result<(), io::Error> {
        let user_addr = if let Some(addr) = get_host_address_range(
            &self.memory.load(),
            GuestAddress(gpa),
            size.try_into().unwrap(),
        ) {
            addr as u64
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "failed to convert guest address 0x{:x} into \
                     host user virtual address",
                    gpa
                ),
            ));
        };

        self.container
            .vfio_dma_map(iova, size, user_addr)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "failed to map memory for VFIO container, \
                         iova 0x{:x}, gpa 0x{:x}, size 0x{:x}: {:?}",
                        iova, gpa, size, e
                    ),
                )
            })
    }

    fn unmap(&self, iova: u64, size: u64) -> result::Result<(), io::Error> {
        self.container.vfio_dma_unmap(iova, size).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "failed to unmap memory for VFIO container, \
                     iova 0x{:x}, size 0x{:x}: {:?}",
                    iova, size, e
                ),
            )
        })
    }
}

/// Vfio device for exposing regions which could be read/write to kernel vfio device.
pub struct VfioDevice {
    device: File,
    flags: u32,
    group: VfioGroup,
    regions: Vec<VfioRegion>,
    irqs: HashMap<u32, VfioIrq>,
    mem: Arc<ArcSwap<GuestMemoryMmap>>,
    iommu_attached: bool,
}

impl VfioDevice {
    /// Create a new vfio device, then guest read/write on this device could be
    /// transfered into kernel vfio.
    /// sysfspath specify the vfio device path in sys file system.
    pub fn new(
        sysfspath: &Path,
        device_fd: Arc<DeviceFd>,
        mem: Arc<ArcSwap<GuestMemoryMmap>>,
        iommu_attached: bool,
    ) -> Result<Self> {
        let uuid_path: PathBuf = [sysfspath, Path::new("iommu_group")].iter().collect();
        let group_path = uuid_path.read_link().map_err(VfioError::ReadLink)?;
        let group_osstr = group_path.file_name().ok_or(VfioError::InvalidPath)?;
        let group_str = group_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let group_id = group_str.parse::<u32>().map_err(VfioError::ParseInt)?;

        let group = VfioGroup::new(group_id, device_fd)?;
        let device_info = group.get_device(sysfspath)?;
        let regions = device_info.get_regions()?;
        let irqs = device_info.get_irqs()?;

        Ok(VfioDevice {
            device: device_info.device,
            flags: device_info.flags,
            group,
            regions,
            irqs,
            mem,
            iommu_attached,
        })
    }

    /// VFIO device reset.
    /// Only if the device supports being reset.
    pub fn reset(&self) {
        if self.flags & VFIO_DEVICE_FLAGS_RESET != 0 {
            unsafe { ioctl(self, VFIO_DEVICE_RESET()) };
        }
    }

    /// Enables a VFIO device IRQs.
    /// This maps a vector of EventFds to all VFIO managed interrupts. In other words, this
    /// tells VFIO which EventFd to write into whenever one of the device interrupt vector
    /// is triggered.
    ///
    /// # Arguments
    ///
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to enable.
    /// * `event_fds` - The EventFds vector that matches all the supported VFIO interrupts.
    pub fn enable_irq(&self, irq_index: u32, event_fds: Vec<&EventFd>) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceSetIrq)?;
        if irq.count == 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        let mut irq_set_wrapper = IrqSet::new(event_fds.len() * mem::size_of::<u32>());
        let mut irq_set = irq_set_wrapper.as_mut_fam_struct();
        let fds = irq_set.as_mut_slice();

        for (index, event_fd) in event_fds.iter().enumerate() {
            let fds_offset = index * mem::size_of::<u32>();
            let fd = &mut fds[fds_offset..fds_offset + mem::size_of::<u32>()];
            LittleEndian::write_u32(fd, event_fd.as_raw_fd() as u32);
        }

        irq_set.argsz = mem::size_of::<vfio_irq_set>() as u32
            + (event_fds.len() * mem::size_of::<u32>()) as u32;
        irq_set.flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set.index = irq_index;
        irq_set.start = 0;
        irq_set.count = irq.count;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), irq_set) };
        if ret < 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        Ok(())
    }

    /// Disables a VFIO device IRQs
    ///
    /// # Arguments
    ///
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to disable.
    pub fn disable_irq(&self, irq_index: u32) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceSetIrq)?;
        if irq.count == 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = 0;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        Ok(())
    }

    /// Wrapper to enable MSI IRQs.
    pub fn enable_msi(&self, fds: Vec<&EventFd>) -> Result<()> {
        self.enable_irq(VFIO_PCI_MSI_IRQ_INDEX, fds)
    }

    /// Wrapper to disable MSI IRQs.
    pub fn disable_msi(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_MSI_IRQ_INDEX)
    }

    /// Wrapper to enable MSI-X IRQs.
    pub fn enable_msix(&self, fds: Vec<&EventFd>) -> Result<()> {
        self.enable_irq(VFIO_PCI_MSIX_IRQ_INDEX, fds)
    }

    /// Wrapper to disable MSI-X IRQs.
    pub fn disable_msix(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_MSIX_IRQ_INDEX)
    }

    /// get a region's flag
    pub fn get_region_flags(&self, index: u32) -> u32 {
        match self.regions.get(index as usize) {
            Some(v) => v.flags,
            None => 0,
        }
    }

    /// get a region's offset
    pub fn get_region_offset(&self, index: u32) -> u64 {
        match self.regions.get(index as usize) {
            Some(v) => v.offset,
            None => 0,
        }
    }

    /// get a region's mmap info
    pub fn get_region_mmap(&self, index: u32) -> (u64, u64) {
        match self.regions.get(index as usize) {
            Some(v) => v.mmap,
            None => {
                warn!("get_region_mmap with invalid index: {}", index);
                (0, 0)
            }
        }
    }

    /// get a region's size
    pub fn get_region_size(&self, index: u32) -> u64 {
        match self.regions.get(index as usize) {
            Some(v) => v.size,
            None => {
                warn!("get_region_size with invalid index: {}", index);
                0
            }
        }
    }

    /// Read region's data from VFIO device into buf
    /// index: region num
    /// buf: data destination and buf length is read size
    /// addr: offset in the region
    pub fn region_read(&self, index: u32, buf: &mut [u8], addr: u64) {
        let region: &VfioRegion;
        match self.regions.get(index as usize) {
            Some(v) => region = v,
            None => {
                warn!("region read with invalid index: {}", index);
                return;
            }
        }

        let size = buf.len() as u64;
        if size > region.size || addr + size > region.size {
            warn!(
                "region read with invalid parameter, add: {}, size: {}",
                addr, size
            );
            return;
        }

        if let Err(e) = self.device.read_exact_at(buf, region.offset + addr) {
            warn!(
                "Failed to read region in index: {}, addr: {}, error: {}",
                index, addr, e
            );
        }
    }

    /// write the data from buf into a vfio device region
    /// index: region num
    /// buf: data src and buf length is write size
    /// addr: offset in the region
    pub fn region_write(&self, index: u32, buf: &[u8], addr: u64) {
        let stub: &VfioRegion;
        match self.regions.get(index as usize) {
            Some(v) => stub = v,
            None => {
                warn!("region write with invalid index: {}", index);
                return;
            }
        }

        let size = buf.len() as u64;
        if size > stub.size
            || addr + size > stub.size
            || (stub.flags & VFIO_REGION_INFO_FLAG_WRITE) == 0
        {
            warn!(
                "region write with invalid parameter, add: {}, size: {}",
                addr, size
            );
            return;
        }

        if let Err(e) = self.device.write_all_at(buf, stub.offset + addr) {
            warn!(
                "Failed to write region in index: {}, addr: {}, error: {}",
                index, addr, e
            );
        }
    }

    pub fn get_container(&self) -> Arc<VfioContainer> {
        self.group.container.clone()
    }

    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        self.group.container.vfio_dma_map(iova, size, user_addr)
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        self.group.container.vfio_dma_unmap(iova, size)
    }

    /// Add all guest memory regions into vfio container's iommu table,
    /// then vfio kernel driver could access guest memory from gfn
    pub fn setup_dma_map(&self) -> Result<()> {
        if !self.iommu_attached {
            self.mem.load().with_regions(|_index, region| {
                self.vfio_dma_map(
                    region.start_addr().raw_value(),
                    region.len() as u64,
                    region.as_ptr() as u64,
                )
            })?;
        }
        Ok(())
    }

    /// remove all guest memory regions from vfio containers iommu table
    /// then vfio kernel driver couldn't access this guest memory
    pub fn unset_dma_map(&self) -> Result<()> {
        if !self.iommu_attached {
            self.mem.load().with_regions(|_index, region| {
                self.vfio_dma_unmap(region.start_addr().raw_value(), region.len() as u64)
            })?;
        }
        Ok(())
    }

    /// Return the maximum numner of interrupts a VFIO device can request.
    /// This is used for pre-allocating the VFIO PCI routes.
    pub fn max_interrupts(&self) -> u32 {
        let mut max_interrupts = 0;
        let irq_indexes = vec![
            VFIO_PCI_INTX_IRQ_INDEX,
            VFIO_PCI_MSI_IRQ_INDEX,
            VFIO_PCI_MSIX_IRQ_INDEX,
        ];

        for index in irq_indexes {
            if let Some(irq_info) = self.irqs.get(&index) {
                if irq_info.count > max_interrupts {
                    max_interrupts = irq_info.count;
                }
            }
        }

        max_interrupts
    }
}

impl AsRawFd for VfioDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}
