// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::ffi::CString;
use std::io::{IoSlice, Read, Write};
use std::num::Wrapping;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::RawFd;
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
#[derive(Clone, Copy, Debug)]
enum Command {
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

impl Default for Command {
    fn default() -> Self {
        Command::Unknown
    }
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum HeaderFlags {
    Command = 0,
    Reply = 1,
    NoReply = 1 << 4,
    Error = 1 << 5,
}

impl Default for HeaderFlags {
    fn default() -> Self {
        HeaderFlags::Command
    }
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

unsafe impl ByteValued for Header {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Version {
    header: Header,
    major: u16,
    minor: u16,
}
unsafe impl ByteValued for Version {}

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

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum DmaMapFlags {
    Unknown = 0,
    ReadOnly = 1,
    WriteOnly = 2,
    ReadWrite = 3,
}

impl Default for DmaMapFlags {
    fn default() -> Self {
        Self::Unknown
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaMap {
    header: Header,
    argsz: u32,
    flags: DmaMapFlags,
    offset: u64,
    address: u64,
    size: u64,
}

unsafe impl ByteValued for DmaMap {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaUnmap {
    header: Header,
    argsz: u32,
    flags: u32,
    address: u64,
    size: u64,
}

unsafe impl ByteValued for DmaUnmap {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceGetInfo {
    header: Header,
    argsz: u32,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
}

unsafe impl ByteValued for DeviceGetInfo {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceGetRegionInfo {
    header: Header,
    region_info: vfio_region_info,
}

unsafe impl ByteValued for DeviceGetRegionInfo {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct RegionAccess {
    header: Header,
    offset: u64,
    region: u32,
    count: u32,
}

unsafe impl ByteValued for RegionAccess {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct GetIrqInfo {
    header: Header,
    argsz: u32,
    flags: u32,
    index: u32,
    count: u32,
}

unsafe impl ByteValued for GetIrqInfo {}

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

unsafe impl ByteValued for SetIrqs {}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceReset {
    header: Header,
}

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
    #[error("Error writing with file descriptors: {0}")]
    SendWithFd(#[source] vmm_sys_util::errno::Error),
    #[error("Error reading with file descriptors: {0}")]
    ReceiveWithFd(#[source] vmm_sys_util::errno::Error),
    #[error("Not a PCI device")]
    NotPciDevice,
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
                message_size: (std::mem::size_of::<Version>() + version_data.len() + 1) as u32,
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
            server_version.header.message_size as usize - std::mem::size_of::<Version>(),
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
                message_size: std::mem::size_of::<DmaMap>() as u32,
                ..Default::default()
            },
            argsz: (std::mem::size_of::<DmaMap>() - std::mem::size_of::<Header>()) as u32,
            flags: DmaMapFlags::ReadWrite,
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
                message_size: std::mem::size_of::<DmaUnmap>() as u32,
                ..Default::default()
            },
            argsz: (std::mem::size_of::<DmaUnmap>() - std::mem::size_of::<Header>()) as u32,
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
                message_size: std::mem::size_of::<DeviceReset>() as u32,
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
                message_size: std::mem::size_of::<DeviceGetInfo>() as u32,
                ..Default::default()
            },
            argsz: std::mem::size_of::<DeviceGetInfo>() as u32,
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
            let get_region_info = DeviceGetRegionInfo {
                header: Header {
                    message_id: self.next_message_id.0,
                    command: Command::DeviceGetRegionInfo,
                    flags: HeaderFlags::Command as u32,
                    message_size: std::mem::size_of::<DeviceGetRegionInfo>() as u32,
                    ..Default::default()
                },
                region_info: vfio_region_info {
                    argsz: 1024, // Arbitrary max size
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

            regions.push(Region {
                flags: reply.region_info.flags,
                index: reply.region_info.index,
                size: reply.region_info.size,
                file_offset: fd.map(|fd| FileOffset::new(fd, reply.region_info.offset)),
            });

            // TODO: Handle region with capabilities
            let mut _cap_data = Vec::with_capacity(
                reply.header.message_size as usize - std::mem::size_of::<DeviceGetRegionInfo>(),
            );
            _cap_data.resize(_cap_data.capacity(), 0u8);
            self.stream
                .read_exact(_cap_data.as_mut_slice())
                .map_err(Error::StreamRead)?;
        }

        Ok(regions)
    }

    pub fn region_read(&mut self, region: u32, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        let region_read = RegionAccess {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::RegionRead,
                flags: HeaderFlags::Command as u32,
                message_size: std::mem::size_of::<RegionAccess>() as u32,
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
                message_size: (std::mem::size_of::<RegionAccess>() + data.len()) as u32,
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
                message_size: std::mem::size_of::<GetIrqInfo>() as u32,
                ..Default::default()
            },
            argsz: (std::mem::size_of::<GetIrqInfo>() - std::mem::size_of::<Header>()) as u32,
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
                message_size: std::mem::size_of::<SetIrqs>() as u32,
                ..Default::default()
            },
            argsz: (std::mem::size_of::<SetIrqs>() - std::mem::size_of::<Header>()) as u32,
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
        for region in &self.regions {
            if region.index == region_index {
                return Some(region);
            }
        }

        None
    }

    pub fn resettable(&self) -> bool {
        self.resettable
    }
}
