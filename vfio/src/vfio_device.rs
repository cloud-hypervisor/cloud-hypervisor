// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::u32;
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::*;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::ioctl::*;
use vmm_sys_util::EventFd;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

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
    ContainerSetIOMMU,
    GroupGetDeviceFD,
    CreateVfioKvmDevice(io::Error),
    KvmSetDeviceAttr(io::Error),
    VfioDeviceGetInfo,
    VfioDeviceGetRegionInfo,
    InvalidPath,
    IommuDmaMap,
    IommuDmaUnmap,
    VfioDeviceGetIrqInfo,
    VfioDeviceSetIrq,
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
            VfioError::ContainerSetIOMMU => write!(
                f,
                "failed to set container's IOMMU driver type as VfioType1V2"
            ),
            VfioError::GroupGetDeviceFD => write!(f, "failed to get vfio device fd"),
            VfioError::CreateVfioKvmDevice(e) => {
                write!(f, "failed to create KVM vfio device: {}", e)
            }
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
        }
    }
}

struct VfioContainer {
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

    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
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

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
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
    device: DeviceFd,
    container: VfioContainer,
}

impl VfioGroup {
    fn new(id: u32, vm: &Arc<VmFd>) -> Result<Self> {
        let mut group_path = String::from("/dev/vfio/");
        let s_id = &id;
        group_path.push_str(s_id.to_string().as_str());

        let group = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(&group_path))
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

        let container = VfioContainer::new()?;
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

        let device = Self::kvm_device_add_group(vm, &group)?;

        Ok(VfioGroup {
            group,
            device,
            container,
        })
    }

    fn kvm_device_add_group(vm: &VmFd, group: &File) -> Result<DeviceFd> {
        let mut vfio_dev = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        let device_fd = vm
            .create_device(&mut vfio_dev)
            .map_err(VfioError::CreateVfioKvmDevice)?;

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
            .map_err(VfioError::KvmSetDeviceAttr)?;

        Ok(device_fd)
    }

    fn kvm_device_del_group(&self) {
        let group_fd = self.as_raw_fd();
        let group_fd_ptr = &group_fd as *const i32;
        let dev_attr = kvm_bindings::kvm_device_attr {
            flags: 0,
            group: kvm_bindings::KVM_DEV_VFIO_GROUP,
            attr: u64::from(kvm_bindings::KVM_DEV_VFIO_GROUP_DEL),
            addr: group_fd_ptr as u64,
        };

        if self.device.set_device_attr(&dev_attr).is_err() {
            error!("Could not delete VFIO group");
        }
    }

    fn unset_container(&self) {
        let container_raw_fd = self.container.as_raw_fd();

        // Safe as we are the owner of self and container_raw_fd which are valid value.
        let ret = unsafe { ioctl_with_ref(self, VFIO_GROUP_UNSET_CONTAINER(), &container_raw_fd) };
        if ret < 0 {
            error!("Failed to unset container for group");
        }
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
        self.kvm_device_del_group();
        self.unset_container();
    }
}

struct VfioRegion {
    flags: u32,
    size: u64,
    offset: u64,
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

            println!("IRQ #{}", index);
            println!("\tflag 0x{:x}", irq.flags);
            println!("\tindex {}", irq.index);
            println!("\tcount {}", irq.count);

            irqs.insert(index, irq);
        }

        Ok(irqs)
    }

    fn get_regions(&self) -> Result<Vec<VfioRegion>> {
        let mut regions: Vec<VfioRegion> = Vec::new();

        for i in VFIO_PCI_BAR0_REGION_INDEX..self.num_regions {
            let mut reg_info = vfio_region_info {
                argsz: mem::size_of::<vfio_region_info>() as u32,
                flags: 0,
                index: i,
                cap_offset: 0,
                size: 0,
                offset: 0,
            };
            // Safe as we are the owner of dev and reg_info which are valid value,
            // and we verify the return value.
            let ret = unsafe {
                ioctl_with_mut_ref(&self.device, VFIO_DEVICE_GET_REGION_INFO(), &mut reg_info)
            };
            if ret < 0 {
                error!("Could not get region #{} info", i);
                continue;
            }

            let region = VfioRegion {
                flags: reg_info.flags,
                size: reg_info.size,
                offset: reg_info.offset,
            };

            println!("Region #{}", i);
            println!("\tflag 0x{:x}", region.flags);
            println!("\tsize 0x{:x}", region.size);
            println!("\toffset 0x{:x}", region.offset);

            regions.push(region);
        }

        Ok(regions)
    }
}

/// Vfio device for exposing regions which could be read/write to kernel vfio device.
#[allow(dead_code)]
pub struct VfioDevice {
    device: File,
    flags: u32,
    group: VfioGroup,
    regions: Vec<VfioRegion>,
    irqs: HashMap<u32, VfioIrq>,
    mem: GuestMemoryMmap,
}

impl VfioDevice {
    /// Create a new vfio device, then guest read/write on this device could be
    /// transfered into kernel vfio.
    /// sysfspath specify the vfio device path in sys file system.
    pub fn new(sysfspath: &Path, vm: &Arc<VmFd>, mem: GuestMemoryMmap) -> Result<Self> {
        let mut uuid_path = PathBuf::new();
        uuid_path.push(sysfspath);
        uuid_path.push("iommu_group");
        let group_path = uuid_path.read_link().map_err(|_| VfioError::InvalidPath)?;
        let group_osstr = group_path.file_name().ok_or(VfioError::InvalidPath)?;
        let group_str = group_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let group_id = group_str
            .parse::<u32>()
            .map_err(|_| VfioError::InvalidPath)?;

        let group = VfioGroup::new(group_id, vm)?;
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
        })
    }

    pub fn enable_irq(&self, irq_index: u32, fd: &EventFd) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceSetIrq)?;
        if irq.count == 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(1);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32 + 4;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = irq.count;

        {
            // irq_set.data could be none, bool or fd according to flags, so irq_set.data
            // is u8 default, here irq_set.data is fd as u32, so 4 default u8 are combined
            // together as u32. It is safe as enough space is reserved through
            // vec_with_array_field(u32)<1>.
            let fds = unsafe { irq_set[0].data.as_mut_slice(4) };
            LittleEndian::write_u32(fds, fd.as_raw_fd() as u32);
        }

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        Ok(())
    }

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
        irq_set[0].flags = VFIO_IRQ_SET_ACTION_MASK;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = irq.count;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            return Err(VfioError::VfioDeviceSetIrq);
        }

        Ok(())
    }

    pub fn enable_intx(&self, fd: &EventFd) -> Result<()> {
        self.enable_irq(VFIO_PCI_INTX_IRQ_INDEX, fd)
    }

    pub fn disable_intx(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_INTX_IRQ_INDEX)
    }

    pub fn enable_msi(&self, fd: &EventFd) -> Result<()> {
        self.enable_irq(VFIO_PCI_MSI_IRQ_INDEX, fd)
    }

    pub fn disable_msi(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_MSI_IRQ_INDEX)
    }

    pub fn enable_msix(&self, fd: &EventFd) -> Result<()> {
        self.enable_irq(VFIO_PCI_MSIX_IRQ_INDEX, fd)
    }

    pub fn disable_msix(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_MSIX_IRQ_INDEX)
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

    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        self.group.container.vfio_dma_map(iova, size, user_addr)
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        self.group.container.vfio_dma_unmap(iova, size)
    }

    /// Add all guest memory regions into vfio container's iommu table,
    /// then vfio kernel driver could access guest memory from gfn
    pub fn setup_dma_map(&self) -> Result<()> {
        self.mem.with_regions(|_index, region| {
            self.vfio_dma_map(
                region.start_addr().raw_value(),
                region.len() as u64,
                region.as_ptr() as u64,
            )
        })?;
        Ok(())
    }

    /// remove all guest memory regions from vfio containers iommu table
    /// then vfio kernel driver couldn't access this guest memory
    pub fn unset_dma_map(&self) -> Result<()> {
        self.mem.with_regions(|_index, region| {
            self.vfio_dma_unmap(region.start_addr().raw_value(), region.len() as u64)
        })?;
        Ok(())
    }
}

impl AsRawFd for VfioDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}
