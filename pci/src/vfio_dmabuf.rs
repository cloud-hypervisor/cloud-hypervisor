// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use iommufd_bindings::iommufd::{
    IOMMUFD_CMD_IOAS_MAP_FILE, IOMMUFD_TYPE, iommu_ioas_map_file,
    iommufd_ioas_map_flags_IOMMU_IOAS_MAP_FIXED_IOVA,
    iommufd_ioas_map_flags_IOMMU_IOAS_MAP_READABLE,
    iommufd_ioas_map_flags_IOMMU_IOAS_MAP_WRITEABLE,
};
use vfio_bindings::bindings::vfio::{
    VFIO_BASE, VFIO_DEVICE_FEATURE_GET, VFIO_DEVICE_FEATURE_PROBE, VFIO_TYPE,
};
use vmm_sys_util::ioctl::ioctl_with_mut_ref;

// Not in vfio-bindings yet, include/uapi/linux/vfio.h since Linux 6.19.
const VFIO_DEVICE_FEATURE_DMA_BUF: u32 = 11;

vmm_sys_util::ioctl_io_nr!(VFIO_DEVICE_FEATURE, VFIO_TYPE as u32, VFIO_BASE + 17);
vmm_sys_util::ioctl_io_nr!(
    IOMMU_IOAS_MAP_FILE,
    IOMMUFD_TYPE as u32,
    IOMMUFD_CMD_IOAS_MAP_FILE
);

// struct vfio_device_feature followed by struct vfio_device_feature_dma_buf
// with a single struct vfio_region_dma_range, the most iommufd accepts.
#[repr(C)]
#[derive(Default)]
struct VfioDeviceFeatureDmaBuf {
    argsz: u32,
    flags: u32,
    region_index: u32,
    open_flags: u32,
    dma_buf_flags: u32,
    nr_ranges: u32,
    offset: u64,
    length: u64,
}

fn dma_buf_feature(device: &impl AsRawFd, mut feature: VfioDeviceFeatureDmaBuf) -> io::Result<i32> {
    feature.argsz = size_of::<VfioDeviceFeatureDmaBuf>() as u32;
    // SAFETY: feature is a struct vfio_device_feature of argsz bytes that
    // outlives the call.
    let ret = unsafe { ioctl_with_mut_ref(device, VFIO_DEVICE_FEATURE(), &mut feature) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}

// Fails with ENOTTY before Linux 6.19, and with EOPNOTSUPP for drivers that
// do not export BARs, such as most VFIO variant drivers.
pub(crate) fn probe_dma_buf(device: &impl AsRawFd) -> io::Result<()> {
    let feature = VfioDeviceFeatureDmaBuf {
        flags: VFIO_DEVICE_FEATURE_PROBE | VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_DMA_BUF,
        ..Default::default()
    };
    dma_buf_feature(device, feature).map(|_| ())
}

/// An iommufd IOAS, into which BARs are mapped as dma-bufs.
pub struct IommufdIoas {
    iommufd: Arc<dyn AsRawFd + Send + Sync>,
    ioas_id: u32,
}

impl IommufdIoas {
    pub fn new(iommufd: Arc<dyn AsRawFd + Send + Sync>, ioas_id: u32) -> Self {
        Self { iommufd, ioas_id }
    }

    // Returns false while the device does not decode memory, as vfio-pci then
    // revokes the dma-buf.
    pub(crate) fn map_bar(
        &self,
        device: &impl AsRawFd,
        region_index: u32,
        offset: u64,
        length: u64,
        iova: u64,
    ) -> io::Result<bool> {
        let feature = VfioDeviceFeatureDmaBuf {
            flags: VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_DMA_BUF,
            region_index,
            open_flags: (libc::O_RDWR | libc::O_CLOEXEC) as u32,
            nr_ranges: 1,
            offset,
            length,
            ..Default::default()
        };
        let fd = dma_buf_feature(device, feature)?;
        // SAFETY: fd is the new dma-buf fd returned by the ioctl. iommufd
        // takes its own reference, so it is closed once mapped.
        let dmabuf = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut map = iommu_ioas_map_file {
            size: size_of::<iommu_ioas_map_file>() as u32,
            flags: iommufd_ioas_map_flags_IOMMU_IOAS_MAP_FIXED_IOVA
                | iommufd_ioas_map_flags_IOMMU_IOAS_MAP_WRITEABLE
                | iommufd_ioas_map_flags_IOMMU_IOAS_MAP_READABLE,
            ioas_id: self.ioas_id,
            fd: dmabuf.as_raw_fd(),
            start: 0,
            length,
            iova,
        };
        // SAFETY: self.iommufd keeps the fd open while it is borrowed.
        let iommufd = unsafe { BorrowedFd::borrow_raw(self.iommufd.as_raw_fd()) };
        // SAFETY: map is a struct iommu_ioas_map_file of the size it gives,
        // and outlives the call.
        let ret = unsafe { ioctl_with_mut_ref(&iommufd, IOMMU_IOAS_MAP_FILE(), &mut map) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENODEV) => Ok(false),
                _ => Err(e),
            };
        }
        Ok(true)
    }
}
