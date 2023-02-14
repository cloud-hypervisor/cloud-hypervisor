// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use bitflags::bitflags;
use libc::{c_void, iovec};
use std::ffi::CString;
use std::fs::File;
use std::io::{IoSlice, Read, Write};
use std::mem::size_of;
use std::num::Wrapping;
use std::os::unix::{
    io::{FromRawFd, RawFd},
    net::{UnixListener, UnixStream},
};
use std::path::Path;
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vm_memory::{ByteValued, FileOffset};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Default)]
pub enum Command {
    #[default]
    Unknown = 0,
    Version = 1,
    DmaMap = 2,
    DmaUnmap = 3,
    DeviceGetInfo = 4,
    DeviceGetRegionInfo = 5,
    GetRegionIoFds = 6,
    GetIrqInfo = 7,
    SetIrqs = 8,
    RegionRead = 9,
    RegionWrite = 10,
    DmaRead = 11,
    DmaWrite = 12,
    DeviceReset = 13,
    UserDirtyPages = 14,
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum HeaderFlags {
    #[default]
    Command = 0,
    Reply = 1,
    NoReply = 1 << 4,
    Error = 1 << 5,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Header {
    message_id: u16,
    command: Command,
    message_size: u32,
    flags: u32,
    error: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Version {
    header: Header,
    major: u16,
    minor: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct MigrationCapabilities {
    pgsize: u32,
}

const fn default_max_msg_fds() -> u32 {
    1
}

const fn default_max_data_xfer_size() -> u32 {
    1048576
}

const fn default_migration_capabilities() -> MigrationCapabilities {
    MigrationCapabilities { pgsize: 4096 }
}

bitflags! {
    pub struct DmaMapFlags: u32 {
        const READ_ONLY = 1 << 0;
        const WRITE_ONLY = 1 << 1;
        const READ_WRITE = Self::READ_ONLY.bits | Self::WRITE_ONLY.bits;
    }

    pub struct DmaUnmapFlags: u32 {
        const GET_DIRTY_PAGE_INFO = 1 << 1;
        const UNMAP_ALL = 1 << 2;
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaMap {
    header: Header,
    argsz: u32,
    flags: u32,
    offset: u64,
    address: u64,
    size: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaUnmap {
    header: Header,
    argsz: u32,
    flags: u32,
    address: u64,
    size: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceGetInfo {
    header: Header,
    argsz: u32,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceGetRegionInfo {
    header: Header,
    region_info: vfio_region_info,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct RegionAccess {
    header: Header,
    offset: u64,
    region: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct GetIrqInfo {
    header: Header,
    argsz: u32,
    flags: u32,
    index: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct SetIrqs {
    header: Header,
    argsz: u32,
    flags: u32,
    index: u32,
    start: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceReset {
    header: Header,
}

// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for Header {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for Version {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for DmaMap {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for DmaUnmap {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for DeviceGetInfo {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for DeviceGetRegionInfo {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for RegionAccess {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for GetIrqInfo {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for SetIrqs {}
// SAFETY: data structure only contain a sereis of integers
unsafe impl ByteValued for DeviceReset {}

#[derive(Serialize, Deserialize, Debug)]
struct Capabilities {
    #[serde(default = "default_max_msg_fds")]
    max_msg_fds: u32,
    #[serde(default = "default_max_data_xfer_size")]
    max_data_xfer_size: u32,
    #[serde(default = "default_migration_capabilities")]
    migration: MigrationCapabilities,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            max_msg_fds: default_max_msg_fds(),
            max_data_xfer_size: default_max_data_xfer_size(),
            migration: default_migration_capabilities(),
        }
    }
}

pub struct Client {
    stream: UnixStream,
    next_message_id: Wrapping<u16>,
    num_irqs: u32,
    resettable: bool,
    regions: Vec<Region>,
}

#[derive(Debug)]
pub struct Region {
    pub flags: u32,
    pub index: u32,
    pub size: u64,
    pub file_offset: Option<FileOffset>,
    pub sparse_areas: Vec<vfio_region_sparse_mmap_area>,
}

#[derive(Debug)]
pub struct IrqInfo {
    pub index: u32,
    pub flags: u32,
    pub count: u32,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error connecting: {0}")]
    Connect(#[source] std::io::Error),
    #[error("Error serializing capabilities: {0}")]
    SerializeCapabilites(#[source] serde_json::Error),
    #[error("Error deserializing capabilities: {0}")]
    DeserializeCapabilites(#[source] serde_json::Error),
    #[error("Error writing to stream: {0}")]
    StreamWrite(#[source] std::io::Error),
    #[error("Error reading from stream: {0}")]
    StreamRead(#[source] std::io::Error),
    #[error("Error shutting down stream: {0}")]
    StreamShutdown(#[source] std::io::Error),
    #[error("Error writing with file descriptors: {0}")]
    SendWithFd(#[source] vmm_sys_util::errno::Error),
    #[error("Error reading with file descriptors: {0}")]
    ReceiveWithFd(#[source] vmm_sys_util::errno::Error),
    #[error("Not a PCI device")]
    NotPciDevice,
    #[error("Error binding to socket: {0}")]
    SocketBind(#[source] std::io::Error),
    #[error("Error accepting connection: {0}")]
    SocketAccept(#[source] std::io::Error),
    #[error("Unsupported command: {0:?}")]
    UnsupportedCommand(Command),
    #[error("Unsupported feature")]
    UnsupportedFeature,
    #[error("Error from backend: {0:?}")]
    Backend(#[source] std::io::Error),
}

impl Client {
    pub fn new(path: &Path) -> Result<Client, Error> {
        let stream = UnixStream::connect(path).map_err(Error::Connect)?;

        let mut client = Client {
            next_message_id: Wrapping(0),
            stream,
            num_irqs: 0,
            resettable: false,
            regions: Vec::new(),
        };

        client.negotiate_version()?;

        client.regions = client.get_regions()?;

        Ok(client)
    }

    fn negotiate_version(&mut self) -> Result<(), Error> {
        let caps = Capabilities::default();

        let version_data = serde_json::to_string(&caps).map_err(Error::SerializeCapabilites)?;

        let version = Version {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::Version,
                flags: HeaderFlags::Command as u32,
                message_size: (size_of::<Version>() + version_data.len() + 1) as u32,
                ..Default::default()
            },
            major: 0,
            minor: 1,
        };
        debug!("Command: {:?}", version);

        let version_data = CString::new(version_data.as_bytes()).unwrap();
        let bufs = vec![
            IoSlice::new(version.as_slice()),
            IoSlice::new(version_data.as_bytes_with_nul()),
        ];

        // TODO: Use write_all_vectored() when ready
        let _ = self
            .stream
            .write_vectored(&bufs)
            .map_err(Error::StreamWrite)?;

        debug!(
            "Sent client version information: major = {} minor = {} capabilities = {:?}",
            version.major, version.minor, &caps
        );

        self.next_message_id += Wrapping(1);

        let mut server_version: Version = Version::default();
        self.stream
            .read_exact(server_version.as_mut_slice())
            .map_err(Error::StreamRead)?;

        debug!("Reply: {:?}", server_version);

        let mut server_version_data = Vec::new();
        server_version_data.resize(
            server_version.header.message_size as usize - size_of::<Version>(),
            0,
        );
        self.stream
            .read_exact(server_version_data.as_mut_slice())
            .map_err(Error::StreamRead)?;

        let server_caps: Capabilities =
            serde_json::from_slice(&server_version_data[0..server_version_data.len() - 1])
                .map_err(Error::DeserializeCapabilites)?;

        debug!(
            "Received server version information: major = {} minor = {} capabilities = {:?}",
            server_version.major, server_version.minor, &server_caps
        );

        Ok(())
    }

    pub fn dma_map(
        &mut self,
        offset: u64,
        address: u64,
        size: u64,
        fd: RawFd,
    ) -> Result<(), Error> {
        let dma_map = DmaMap {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DmaMap,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DmaMap>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<DmaMap>() - size_of::<Header>()) as u32,
            flags: DmaMapFlags::READ_WRITE.bits,
            offset,
            address,
            size,
        };
        debug!("Command: {:?}", dma_map);
        self.next_message_id += Wrapping(1);
        self.stream
            .send_with_fd(dma_map.as_slice(), fd)
            .map_err(Error::SendWithFd)?;

        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);

        Ok(())
    }

    pub fn dma_unmap(&mut self, address: u64, size: u64) -> Result<(), Error> {
        let dma_unmap = DmaUnmap {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DmaUnmap,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DmaUnmap>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<DmaUnmap>() - size_of::<Header>()) as u32,
            flags: 0,
            address,
            size,
        };
        debug!("Command: {:?}", dma_unmap);
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(dma_unmap.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = DmaUnmap::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);

        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), Error> {
        let reset = DeviceReset {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceReset,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DeviceReset>() as u32,
                ..Default::default()
            },
        };
        debug!("Command: {:?}", reset);
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(reset.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);

        Ok(())
    }

    fn get_regions(&mut self) -> Result<Vec<Region>, Error> {
        let get_info = DeviceGetInfo {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceGetInfo,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DeviceGetInfo>() as u32,
                ..Default::default()
            },
            argsz: size_of::<DeviceGetInfo>() as u32,
            ..Default::default()
        };
        debug!("Command: {:?}", get_info);
        self.next_message_id += Wrapping(1);

        self.stream
            .write_all(get_info.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = DeviceGetInfo::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);
        self.num_irqs = reply.num_irqs;

        if reply.flags & VFIO_DEVICE_FLAGS_PCI != VFIO_DEVICE_FLAGS_PCI {
            return Err(Error::NotPciDevice);
        }

        self.resettable = reply.flags & VFIO_DEVICE_FLAGS_RESET != VFIO_DEVICE_FLAGS_RESET;

        let num_regions = reply.num_regions;
        let mut regions = Vec::new();
        for index in 0..num_regions {
            let (region_info, fd, sparse_areas) = self.get_region_info(index)?;
            regions.push(Region {
                flags: region_info.flags,
                index: region_info.index,
                size: region_info.size,
                file_offset: fd.map(|fd| FileOffset::new(fd, region_info.offset)),
                sparse_areas,
            });
        }

        Ok(regions)
    }

    fn get_region_info(
        &mut self,
        index: u32,
    ) -> Result<
        (
            vfio_region_info,
            Option<File>,
            Vec<vfio_region_sparse_mmap_area>,
        ),
        Error,
    > {
        // Retrieve the region info without capability
        let mut get_region_info = DeviceGetRegionInfo {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceGetRegionInfo,
                flags: HeaderFlags::Command as u32,
                message_size: std::mem::size_of::<DeviceGetRegionInfo>() as u32,
                ..Default::default()
            },
            region_info: vfio_region_info {
                argsz: size_of::<vfio_region_info>() as u32,
                index,
                ..Default::default()
            },
        };
        debug!("Command: {:?}", get_region_info);
        self.next_message_id += Wrapping(1);

        self.stream
            .write_all(get_region_info.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = DeviceGetRegionInfo::default();
        let (_, fd) = self
            .stream
            .recv_with_fd(reply.as_mut_slice())
            .map_err(Error::ReceiveWithFd)?;
        debug!("Reply: {:?}", reply);

        // Retrieve the region info again with capabilities if needed
        if reply.region_info.argsz > std::mem::size_of::<vfio_region_info>() as u32 {
            get_region_info.region_info.argsz = reply.region_info.argsz;
            debug!("Command: {:?}", get_region_info);
            self.next_message_id += Wrapping(1);

            self.stream
                .write_all(get_region_info.as_slice())
                .map_err(Error::StreamWrite)?;

            let mut reply = DeviceGetRegionInfo::default();
            let (_, fd) = self
                .stream
                .recv_with_fd(reply.as_mut_slice())
                .map_err(Error::ReceiveWithFd)?;
            debug!("Reply: {:?}", reply);

            let cap_size = reply.region_info.argsz - std::mem::size_of::<vfio_region_info>() as u32;
            assert_eq!(
                cap_size,
                reply.header.message_size - size_of::<DeviceGetRegionInfo>() as u32
            );
            let mut cap_data = vec![0; cap_size as usize];
            self.stream
                .read_exact(cap_data.as_mut_slice())
                .map_err(Error::StreamRead)?;

            let sparse_areas = Self::parse_region_caps(&cap_data, &reply.region_info)?;

            Ok((reply.region_info, fd, sparse_areas))
        } else {
            Ok((reply.region_info, fd, Vec::new()))
        }
    }

    fn parse_region_caps(
        cap_data: &[u8],
        region_info: &vfio_region_info,
    ) -> Result<Vec<vfio_region_sparse_mmap_area>, Error> {
        let mut sparse_areas: Vec<vfio_region_sparse_mmap_area> = Vec::new();

        let cap_size = cap_data.len() as u32;
        let cap_header_size = size_of::<vfio_info_cap_header>() as u32;
        let mmap_cap_size = size_of::<vfio_region_info_cap_sparse_mmap>() as u32;
        let mmap_area_size = size_of::<vfio_region_sparse_mmap_area>() as u32;

        let cap_data_ptr = cap_data.as_ptr() as *const u8;
        let mut region_info_offset = region_info.cap_offset;
        while region_info_offset != 0 {
            // calculate the offset from the begining of the cap_data based on the offset
            // that is relative to the begining of the VFIO region info structure
            let cap_offset = region_info_offset - size_of::<vfio_region_info>() as u32;
            if cap_offset + cap_header_size > cap_size {
                warn!(
                    "Unexpected end of cap data: 'cap_offset + cap_header_size > cap_size' \
                cap_offset = {}, cap_header_size = {}, cap_size = {}",
                    cap_offset, cap_header_size, cap_size
                );
                break;
            }

            // SAFETY: `cap_data_ptr` is valid and the `cap_offset` is checked above
            let cap_ptr = unsafe { cap_data_ptr.offset(cap_offset as isize) };
            // SAFETY: `cap_ptr` is valid
            let cap_header = unsafe { &*(cap_ptr as *const vfio_info_cap_header) };
            match cap_header.id as u32 {
                VFIO_REGION_INFO_CAP_SPARSE_MMAP => {
                    if cap_offset + mmap_cap_size > cap_size {
                        warn!(
                            "Unexpected end of cap data: 'cap_offset + mmap_cap_size > cap_size' \
                        cap_offset = {}, mmap_cap_size = {}, cap_size = {}",
                            cap_offset, mmap_cap_size, cap_size
                        );
                        break;
                    }
                    // SAFETY: `cap_ptr` is valid and its size is also checked above
                    let sparse_mmap = unsafe {
                        &*(cap_ptr as *mut u8 as *const vfio_region_info_cap_sparse_mmap)
                    };

                    let area_num = sparse_mmap.nr_areas;
                    if cap_offset + mmap_cap_size + area_num * mmap_area_size > cap_size {
                        warn!("Unexpected end of cap data: 'cap_offset + mmap_cap_size + area_num * mmap_area_size > cap_size' \
                        cap_offset = {}, mmap_cap_size = {}, area_num = {}, mmap_area_size = {}, cap_size = {}",
                        cap_offset, mmap_cap_size, area_num, mmap_area_size, cap_size);
                        break;
                    }
                    let areas =
                        // SAFETY: `sparse_mmap` is valid and its size is also checked above
                        unsafe { sparse_mmap.areas.as_slice(sparse_mmap.nr_areas as usize) };
                    for area in areas.iter() {
                        sparse_areas.push(*area);
                    }
                }
                _ => {
                    warn!(
                        "Ignoring unsupported vfio region capability (id = '{}')",
                        cap_header.id
                    );
                }
            }
            region_info_offset = cap_header.next;
        }

        Ok(sparse_areas)
    }

    pub fn region_read(&mut self, region: u32, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        let region_read = RegionAccess {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::RegionRead,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<RegionAccess>() as u32,
                ..Default::default()
            },
            offset,
            count: data.len() as u32,
            region,
        };
        debug!("Command: {:?}", region_read);
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(region_read.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = RegionAccess::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);
        self.stream.read_exact(data).map_err(Error::StreamRead)?;
        Ok(())
    }

    pub fn region_write(&mut self, region: u32, offset: u64, data: &[u8]) -> Result<(), Error> {
        let region_write = RegionAccess {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::RegionWrite,
                flags: HeaderFlags::Command as u32,
                message_size: (size_of::<RegionAccess>() + data.len()) as u32,
                ..Default::default()
            },
            offset,
            count: data.len() as u32,
            region,
        };
        debug!("Command: {:?}", region_write);
        self.next_message_id += Wrapping(1);

        let bufs = vec![IoSlice::new(region_write.as_slice()), IoSlice::new(data)];

        // TODO: Use write_all_vectored() when ready
        let _ = self
            .stream
            .write_vectored(&bufs)
            .map_err(Error::StreamWrite)?;

        let mut reply = RegionAccess::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);
        Ok(())
    }

    pub fn get_irq_info(&mut self, index: u32) -> Result<IrqInfo, Error> {
        let get_irq_info = GetIrqInfo {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::GetIrqInfo,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<GetIrqInfo>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<GetIrqInfo>() - size_of::<Header>()) as u32,
            flags: 0,
            index,
            count: 0,
        };
        debug!("Command: {:?}", get_irq_info);
        self.next_message_id += Wrapping(1);

        self.stream
            .write_all(get_irq_info.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = GetIrqInfo::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);

        Ok(IrqInfo {
            index: reply.index,
            flags: reply.flags,
            count: reply.count,
        })
    }

    pub fn set_irqs(
        &mut self,
        index: u32,
        flags: u32,
        start: u32,
        count: u32,
        fds: &[RawFd],
    ) -> Result<(), Error> {
        let set_irqs = SetIrqs {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::SetIrqs,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<SetIrqs>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<SetIrqs>() - size_of::<Header>()) as u32,
            flags,
            start,
            index,
            count,
        };
        debug!("Command: {:?}", set_irqs);
        self.next_message_id += Wrapping(1);

        self.stream
            .send_with_fds(&[set_irqs.as_slice()], fds)
            .map_err(Error::SendWithFd)?;

        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {:?}", reply);

        Ok(())
    }

    pub fn region(&self, region_index: u32) -> Option<&Region> {
        self.regions
            .iter()
            .find(|&region| region.index == region_index)
    }

    pub fn resettable(&self) -> bool {
        self.resettable
    }

    pub fn shutdown(&self) -> Result<(), Error> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(Error::StreamShutdown)
    }
}

pub trait ServerBackend {
    fn region_read(
        &mut self,
        _region: u32,
        _offset: u64,
        _data: &mut [u8],
    ) -> Result<(), std::io::Error>;
    fn region_write(
        &mut self,
        _region: u32,
        _offset: u64,
        _data: &[u8],
    ) -> Result<(), std::io::Error>;
    fn dma_map(
        &mut self,
        _flags: DmaMapFlags,
        _offset: u64,
        _address: u64,
        _size: u64,
        _fd: Option<&File>,
    ) -> Result<(), std::io::Error>;
    fn dma_unmap(
        &mut self,
        _flags: DmaUnmapFlags,
        _address: u64,
        _size: u64,
    ) -> Result<(), std::io::Error>;
    fn reset(&mut self) -> Result<(), std::io::Error>;
    fn set_irqs(
        &mut self,
        _index: u32,
        _flags: u32,
        _start: u32,
        _count: u32,
        _fds: Vec<File>,
    ) -> Result<(), std::io::Error>;
}

pub struct Server {
    listener: UnixListener,
    resettable: bool,
    irqs: Vec<IrqInfo>,
    regions: Vec<vfio_region_info>,
}

impl Server {
    pub fn new(
        path: &Path,
        resettable: bool,
        irqs: Vec<IrqInfo>,
        regions: Vec<vfio_region_info>,
    ) -> Result<Server, Error> {
        let listener = UnixListener::bind(path).map_err(Error::SocketBind)?;

        Ok(Server {
            listener,
            resettable,
            irqs,
            regions,
        })
    }

    fn handle_command(
        &self,
        backend: &mut dyn ServerBackend,
        stream: &mut UnixStream,
        header: Header,
        fds: Vec<File>,
    ) -> Result<(), Error> {
        match header.command {
            Command::Unknown
            | Command::GetRegionIoFds
            | Command::DmaRead
            | Command::DmaWrite
            | Command::UserDirtyPages => {
                return Err(Error::UnsupportedCommand(header.command));
            }
            Command::Version => {
                // TODO: Make version/capabilities configurable
                let mut client_version = Version {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut client_version.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let mut raw_version_data = Vec::new();
                raw_version_data.resize(header.message_size as usize - size_of::<Version>(), 0u8);
                stream
                    .read_exact(&mut raw_version_data)
                    .map_err(Error::StreamRead)?;
                let version_data = CString::from_vec_with_nul(raw_version_data)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let client_capabilities: Capabilities =
                    serde_json::from_str(&version_data).map_err(Error::DeserializeCapabilites)?;

                info!(
                    "Received client version: major = {} minor = {} capabilities = {:?}",
                    client_version.major, client_version.minor, client_capabilities
                );

                let version = Version {
                    header: Header {
                        message_id: client_version.header.message_id,
                        command: Command::Version,
                        flags: HeaderFlags::Reply as u32,
                        message_size: (size_of::<Version>() + version_data.len() + 1) as u32,
                        ..Default::default()
                    },
                    major: 0,
                    minor: 1,
                };

                let server_capabilities = Capabilities::default();
                let version_data = serde_json::to_string(&server_capabilities)
                    .map_err(Error::SerializeCapabilites)?;
                let version_data = CString::new(version_data.as_bytes()).unwrap();

                let bufs = vec![
                    IoSlice::new(version.as_slice()),
                    IoSlice::new(version_data.as_bytes_with_nul()),
                ];

                // TODO: Use write_all_vectored() when ready
                let _ = stream.write_vectored(&bufs).map_err(Error::StreamWrite)?;

                info!(
                    "Sent server version: major = {} minor = {} capabilities = {:?}",
                    version.major, version.minor, server_capabilities
                );
            }
            Command::DmaMap => {
                let mut cmd = DmaMap {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                backend
                    .dma_map(
                        DmaMapFlags::from_bits_truncate(cmd.flags),
                        cmd.offset,
                        cmd.address,
                        cmd.size,
                        Some(&fds[0]),
                    )
                    .map_err(Error::Backend)?;

                let reply = Header {
                    message_id: cmd.header.message_id,
                    command: Command::DmaMap,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DmaUnmap => {
                let mut cmd = DmaUnmap {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                backend
                    .dma_unmap(
                        DmaUnmapFlags::from_bits_truncate(cmd.flags),
                        cmd.address,
                        cmd.size,
                    )
                    .map_err(Error::Backend)?;

                let reply = DmaUnmap {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::DmaUnmap,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<Header>() as u32,
                        ..Default::default()
                    },
                    argsz: cmd.argsz,
                    flags: cmd.flags,
                    address: cmd.address,
                    size: cmd.size,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DeviceGetInfo => {
                let mut cmd = DeviceGetInfo {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let reply = DeviceGetInfo {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::DeviceGetInfo,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<DeviceGetInfo>() as u32,
                        ..Default::default()
                    },
                    argsz: size_of::<DeviceGetInfo>() as u32,
                    // TODO: Consider non-PCI devices
                    flags: VFIO_DEVICE_FLAGS_PCI
                        | if self.resettable {
                            VFIO_DEVICE_FLAGS_RESET
                        } else {
                            0
                        },
                    num_regions: self.regions.len() as u32,
                    num_irqs: self.irqs.len() as u32,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DeviceGetRegionInfo => {
                let mut cmd = DeviceGetRegionInfo {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;
                // TODO: Need to handle region capabilities e.g. sparse regions
                let reply = DeviceGetRegionInfo {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::DeviceGetRegionInfo,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<DeviceGetRegionInfo>() as u32,
                        ..Default::default()
                    },
                    region_info: self.regions[cmd.region_info.index as usize],
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::GetIrqInfo => {
                let mut cmd = GetIrqInfo {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let irq = &self.irqs[cmd.index as usize];

                let reply = GetIrqInfo {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::GetIrqInfo,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<GetIrqInfo>() as u32,
                        ..Default::default()
                    },
                    argsz: (size_of::<GetIrqInfo>() - size_of::<Header>()) as u32,
                    index: irq.index,
                    flags: irq.flags,
                    count: irq.count,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::SetIrqs => {
                let mut cmd = SetIrqs {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                if cmd.flags & VFIO_IRQ_SET_DATA_BOOL > 0 {
                    return Err(Error::UnsupportedFeature);
                }

                backend
                    .set_irqs(cmd.index, cmd.flags, cmd.start, cmd.count, fds)
                    .map_err(Error::Backend)?;

                let reply = Header {
                    message_id: cmd.header.message_id,
                    command: Command::SetIrqs,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::RegionRead => {
                let mut cmd = RegionAccess {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let (region, offset, count) = (cmd.region, cmd.offset, cmd.count);

                let mut data = vec![0u8; count as usize];
                backend
                    .region_read(region, offset, &mut data)
                    .map_err(Error::Backend)?;

                let reply = RegionAccess {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::RegionRead,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<RegionAccess>() as u32,
                        ..Default::default()
                    },
                    region,
                    offset,
                    count,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
                stream.write_all(&data).map_err(Error::StreamWrite)?;
            }
            Command::RegionWrite => {
                let mut cmd = RegionAccess {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let (region, offset, count) = (cmd.region, cmd.offset, cmd.count);

                let mut data = vec![0u8; count as usize];
                stream.read_exact(&mut data).map_err(Error::StreamRead)?;
                backend
                    .region_write(region, offset, &data)
                    .map_err(Error::Backend)?;

                let reply = RegionAccess {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::RegionWrite,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<RegionAccess>() as u32,
                        ..Default::default()
                    },
                    region,
                    offset,
                    count,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DeviceReset => {
                backend.reset().map_err(Error::Backend)?;
                let reply = Header {
                    message_id: header.message_id,
                    command: Command::DeviceReset,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
        }

        Ok(())
    }

    pub fn run(&self, backend: &mut dyn ServerBackend) -> Result<(), Error> {
        let (mut stream, _) = self.listener.accept().map_err(Error::SocketAccept)?;

        loop {
            let mut header = Header::default();

            // The maximum number of FDs that can be sent is 16 so that is
            // also the maximum that can be received.
            let mut fds = vec![0; 16];
            let mut iovecs = vec![iovec {
                iov_base: header.as_mut_slice().as_mut_ptr() as *mut c_void,
                iov_len: header.as_mut_slice().len(),
            }];
            // SAFETY: Safe as the iovect is correctly initialised and fds is big enough
            let (bytes, fds_received) = unsafe {
                stream
                    .recv_with_fds(&mut iovecs, &mut fds)
                    .map_err(Error::ReceiveWithFd)?
            };

            // Other end closed connection
            if bytes == 0 {
                info!("Connection closed");
                break;
            }

            fds.resize(fds_received, 0);

            let fds: Vec<File> = fds
                .iter()
                // SAFETY: Safe as we have only valid FDs in the vector now
                .map(|fd| unsafe { File::from_raw_fd(*fd) })
                .collect();

            if let Err(e) = self.handle_command(backend, &mut stream, header, fds) {
                error!("Error handling command: {:?}: {e}", header.command);
                let reply = Header {
                    message_id: header.message_id,
                    command: header.command,
                    flags: HeaderFlags::Error as u32,
                    message_size: size_of::<Header>() as u32,
                    error: 0,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
        }

        Ok(())
    }
}
