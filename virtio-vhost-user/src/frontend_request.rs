// Copyright (c) 2020 Ant Financial
// Copyright (c) 2026 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::slice;
use std::ffi::{c_int, c_void};
use std::io::ErrorKind;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use log::error;
use queue_pair::{FdRearm, VhostUserMsgHeader};
use vhost::vhost_user::Error;
use vhost::vhost_user::message::{
    FrontendReq, MAX_MSG_SIZE, VhostUserLog, VhostUserMemory, VhostUserMemoryRegion,
    VhostUserProtocolFeatures, VhostUserSingleMemoryRegion, VhostUserU64,
};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::mapping::Allocator;
use super::queue_pair::{self, Translate};
use crate::eventfd_checker::{self, EventfdChecker};
use crate::queue_pair::Fds;

pub const SUPPORTED_PROTOCOL_FEATURES: VhostUserProtocolFeatures = VhostUserProtocolFeatures::MQ
    .union(VhostUserProtocolFeatures::LOG_SHMFD)
    .union(VhostUserProtocolFeatures::RARP)
    .union(VhostUserProtocolFeatures::MTU)
    .union(VhostUserProtocolFeatures::CROSS_ENDIAN)
    .union(VhostUserProtocolFeatures::CRYPTO_SESSION)
    .union(VhostUserProtocolFeatures::CONFIG)
    .union(VhostUserProtocolFeatures::RESET_DEVICE)
    .union(VhostUserProtocolFeatures::MTU)
    .union(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)
    .union(VhostUserProtocolFeatures::STATUS);

// TODO: move this to a utility crate
fn check_is_stream_socket(fd: OwnedFd) -> std::io::Result<UnixStream> {
    unsafe fn check_int_getsockopt(
        fd: BorrowedFd,
        option: c_int,
        expected: c_int,
        msg: &str,
    ) -> std::io::Result<()> {
        let size = core::mem::size_of_val(&expected) as libc::socklen_t;
        // Flip this so that if the kernel didn't write to the whole thing,
        // the socket option will be treated as wrong.
        let mut actual_value = !expected;
        let mut actual_size = size;
        // SAFETY: FFI call with correct arguments.
        // Caller promised that the socket option is valid for SOL_SOCKET.
        match unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                &mut actual_value as *mut c_int as *mut c_void,
                &raw mut actual_size,
            )
        } {
            0 if actual_size == size => {
                if actual_value == expected {
                    Ok(())
                } else {
                    Err(std::io::Error::new(ErrorKind::InvalidData, msg))
                }
            }
            0 => panic!("socket option was supposed to be an int, but its size was {actual_size}"),
            -1 => Err(std::io::Error::last_os_error()),
            e => panic!("bad return value from {e} from getsockopt"),
        }
    }
    let msg = "domain is not SO_DOMAIN";
    // SAFETY: SO_DOMAIN is valid for SOL_SOCKET
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_DOMAIN, libc::AF_UNIX, msg) }?;
    let msg = "type is not SOCK_STREAM";
    // SAFETY: SO_TYPE is valid for SOL_SOCKET
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_TYPE, libc::SOCK_STREAM, msg) }?;
    let msg = "protocol is not 0";
    // SAFETY: SO_PROTOCOL is valid for SOL_SOCKET
    unsafe { check_int_getsockopt(fd.as_fd(), libc::SO_PROTOCOL, 0, msg) }?;
    // SAFETY: File descriptor is valid stream socket
    Ok(unsafe { UnixStream::from_raw_fd(fd.into_raw_fd()) })
}

fn validate_reply(hdr: VhostUserMsgHeader, buf: &mut [u8]) -> Result<(), Error> {
    let flags = hdr.flags;
    if flags & 255 != 5 {
        error!("virtio-vhost-user: Wrong flags: 0x{flags:b}");
        return Err(Error::InvalidMessage);
    }
    if hdr.request == u32::from(FrontendReq::GET_PROTOCOL_FEATURES) {
        let Some(&features) = u64::from_slice(buf) else {
            error!("Bad reply to GET_PROTOCOL_FEATURES");
            return Err(Error::InvalidMessage);
        };
        let features = features & SUPPORTED_PROTOCOL_FEATURES.bits();
        buf.copy_from_slice(features.as_slice());
    }
    Ok(())
}

pub struct FrontendRequestQueuePair<T: Allocator, U: VM> {
    queue_pair: queue_pair::VirtioVhostUserQueuePair,
    internals: FrontendRequestQueuePairInternals<T, U>,
}

pub struct IoEventFds {
    pub offset: u64,
    pub fds: Vec<Option<EventFd>>,
}

pub trait VM {
    fn register_ioevent(&mut self, fd: &EventFd, offset: u64);
    fn unregister_ioevent(&mut self, fd: EventFd, offset: u64);
    fn register_vring_kick(&mut self, fd: Option<EventFd>, queue: u8);
    fn backend_request_socket(&mut self, socket: UnixStream);
}

struct FrontendRequestQueuePairInternals<T: Allocator, U: VM> {
    mapping: super::mapping::Mapping<T>,
    ioeventfds: Arc<Mutex<IoEventFds>>,
    queues: u8,
    seen_log_mapping: bool,
    seen_backend_req_socket: bool,
    vm: U,
    checker: EventfdChecker,
}

impl<T: Allocator, U: VM> FrontendRequestQueuePairInternals<T, U> {
    fn set_mem_table(&mut self, buf: &[u8], fd: &mut [Option<OwnedFd>]) -> Result<(), Error> {
        const _: () = assert!(
            u64::MAX as usize as u64 == u64::MAX,
            "32-bit platforms not supported"
        );
        const _: () = assert!(
            u64::MAX as libc::size_t as u64 == u64::MAX,
            "32-bit platforms not supported"
        );
        if buf.len() > MAX_MSG_SIZE || buf.len() < size_of::<VhostUserMemory>() {
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Bounds checked above, alignment of VhostUserMemory is 1,
        // and VhostUserMemory is POD
        let memory: VhostUserMemory = unsafe { *buf.as_ptr().cast() };
        if memory.padding1 != 0 || memory.num_regions == 0 {
            return Err(Error::InvalidMessage);
        }
        let num_regions = memory.num_regions as usize;
        if num_regions != fd.len() {
            return Err(Error::InvalidMessage);
        }
        // only 64-bit is supported (see above assert) so no overflow possible
        if buf.len()
            != size_of::<VhostUserMemory>() + num_regions * size_of::<VhostUserMemoryRegion>()
        {
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Bounds checked above, alignment of VhostUserMemoryRegion is 1,
        // and VhostUserMemoryRegion is POD
        let ctx = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(size_of::<VhostUserMemory>()) as *const VhostUserMemoryRegion,
                num_regions,
            )
        };
        // Validate all the regions before doing any mappings.
        ctx.iter()
            .try_for_each(|region| self.mapping.check_region(region))?;
        // Reset the mapping
        self.mapping.reset()?;
        for (&region, file) in ctx.iter().zip(fd.iter_mut()) {
            self.mapping
                .map_region(region, file.take().unwrap().as_fd())?;
        }
        Ok(())
    }
    fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        files: &mut [Option<OwnedFd>],
    ) -> Result<(u8, Option<EventFd>), Error> {
        let &msg = VhostUserU64::from_slice(buf).ok_or(Error::InvalidMessage)?;
        if msg.value > 512 {
            return Err(Error::InvalidMessage);
        }
        let queue = msg.value as u8;
        if queue >= self.queues {
            return Err(Error::InvalidMessage);
        }
        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag. This bit is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        // If Bit 8 is unset, the data must contain a file descriptor.
        let has_fd = (msg.value & 0x100u64) == 0;
        let file = match (has_fd, files) {
            (false, &mut []) => None,
            (true, &mut [ref mut something]) => {
                let Some(fd) = something.take() else {
                    return Err(Error::InvalidMessage);
                };
                match self.checker.convert_to_eventfd(fd) {
                    Ok(fd) => Some(fd),
                    Err((_, eventfd_checker::Error::NotEventFd)) => {
                        return Err(Error::InvalidMessage);
                    }
                    Err((_, eventfd_checker::Error::IO(e))) => {
                        return Err(Error::ReqHandlerError(e));
                    }
                }
            }
            _ => return Err(Error::InvalidMessage),
        };

        Ok((queue, file))
    }
    fn handle_ioeventfd_req(
        &mut self,
        req: FrontendReq,
        buf: &[u8],
        files: &mut [Option<OwnedFd>],
    ) -> Result<(), Error> {
        let ((queue, fd), queue_offset) = match req {
            FrontendReq::SET_VRING_CALL => (self.handle_vring_fd_request(buf, files)?, 0),
            FrontendReq::SET_VRING_ERR => (self.handle_vring_fd_request(buf, files)?, 1),
            FrontendReq::SET_LOG_FD if buf.is_empty() && files.len() == 1 => {
                (self.handle_vring_fd_request(buf, files)?, 2)
            }
            FrontendReq::SET_LOG_FD => return Err(Error::InvalidMessage),
            _ => unreachable!(),
        };
        let fd_offset: u64 = queue as u64 + self.queues as u64 * queue_offset;
        let mut ioeventfds = self.ioeventfds.lock().unwrap();
        let offset: u64 = ioeventfds.offset + 4u64 * fd_offset;
        let fd_offset = usize::try_from(fd_offset).unwrap();
        if let Some(fd) = ioeventfds.fds[fd_offset].take() {
            self.vm.unregister_ioevent(fd, offset);
        }
        if let Some(fd) = fd {
            self.vm.register_ioevent(&fd, offset);
            ioeventfds.fds[fd_offset] = Some(fd);
        }
        Ok(())
    }

    fn process_incoming(
        &mut self,
        msg: VhostUserMsgHeader,
        buf: &mut [u8],
        fd: &mut [Option<OwnedFd>],
    ) -> Result<(), Error> {
        let req = FrontendReq::try_from(msg.request).or(Err(Error::InvalidMessage))?;
        match req {
            FrontendReq::SET_MEM_TABLE
            | FrontendReq::SET_VRING_CALL
            | FrontendReq::SET_VRING_KICK
            | FrontendReq::SET_VRING_ERR
            | FrontendReq::SET_LOG_BASE
            | FrontendReq::SET_LOG_FD
            | FrontendReq::SET_BACKEND_REQ_FD
            | FrontendReq::SET_INFLIGHT_FD
            | FrontendReq::ADD_MEM_REG
            | FrontendReq::SET_DEVICE_STATE_FD
            | FrontendReq::GPU_SET_SOCKET => Ok(()),
            _ if !fd.is_empty() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }?;
        match req {
            FrontendReq::RESET_OWNER => Ok(()),
            FrontendReq::SET_FEATURES => todo!(),
            FrontendReq::SET_OWNER
            | FrontendReq::RESET_DEVICE
            | FrontendReq::GET_FEATURES
            | FrontendReq::GET_PROTOCOL_FEATURES
            | FrontendReq::GET_QUEUE_NUM => {
                if !buf.is_empty() {
                    return Err(Error::InvalidMessage);
                }
                Ok(())
            }
            FrontendReq::SET_MEM_TABLE => self.set_mem_table(
                buf,
                fd),
                FrontendReq::SET_VRING_CALL | FrontendReq::SET_VRING_ERR | FrontendReq::SET_LOG_FD => {
                    self.handle_ioeventfd_req(req,
                                              buf,
                                              fd)
                }
                FrontendReq::SET_VRING_KICK => {
                    let (index, fd) = self.handle_vring_fd_request(
                        buf,
                        fd)?;
                    self.vm.register_vring_kick(fd, index);
                    Ok(())
                }

                FrontendReq::ADD_MEM_REG => {
                    if fd.len() != 1 {
                        return Err(Error::InvalidMessage);
                    }
                    let file = fd[0].take().unwrap();
                    let region =
                    VhostUserSingleMemoryRegion::from_slice(buf).ok_or(Error::InvalidMessage)?;
                    self.mapping.map_region(**region, file.as_fd())?;
                    Ok(())
                }

                FrontendReq::REM_MEM_REG => {
                    if fd.len() > 1 {
                        return Err(Error::InvalidMessage);
                    }
                    let region =
                    *VhostUserSingleMemoryRegion::from_slice(buf).ok_or(Error::InvalidMessage)?;
                    self.mapping.unmap_region(&region)?;
                    Ok(())
                }
                FrontendReq::SET_LOG_BASE => {
                    let file = Self::get_single_file(fd)?;
                    let region = VhostUserLog::from_slice(buf).ok_or(Error::InvalidMessage)?;
                    if self.seen_log_mapping {
                        return Err(Error::InvalidOperation("Duplicate log mapping"));
                    }
                    let region = VhostUserMemoryRegion {
                        guest_phys_addr: u64::MAX,
                        memory_size: region.mmap_size,
                        user_addr: u64::MAX,
                        mmap_offset: region.mmap_offset,
                    };
                    self.mapping.map_region(region, file.as_fd())?;
                    self.seen_log_mapping = true;
                    Ok(())
                }

                FrontendReq::SET_BACKEND_REQ_FD => {
                    let file = Self::get_single_file(fd)?;
                    if self.seen_backend_req_socket {
                        return Err(Error::InvalidOperation("Backend request FD already sent"))
                    }                    self.seen_backend_req_socket = true;

                    let socket = check_is_stream_socket(file).map_err(
                        Error::ReqHandlerError
                    )?;
                    self.vm.backend_request_socket(socket);
                    Ok(())
                }

                /* These are features that aren't implemented, and aren't planned to be.*/

                /* Migration messages */FrontendReq::SET_INFLIGHT_FD
                | FrontendReq::SET_DEVICE_STATE_FD
                | FrontendReq::GET_INFLIGHT_FD
                | FrontendReq::CHECK_DEVICE_STATE
                | FrontendReq::POSTCOPY_ADVISE
                | FrontendReq::POSTCOPY_LISTEN
                | FrontendReq::POSTCOPY_END
                | FrontendReq::SEND_RARP
                /* Old-style virtio-GPU */
                | FrontendReq::GPU_SET_SOCKET
                /* In-band notifications */
                | FrontendReq::VRING_KICK
                /* Legacy devices */
                | FrontendReq::SET_VRING_ENDIAN
                /* Network device MTU (only useful with migration) */
                | FrontendReq::NET_SET_MTU
                // This could be implemented, but the IOMMU ought to
                // be enforced by the frontend, not the backend.
                | FrontendReq::IOTLB_MSG
                // Only needed for "exotic" devices like GPUs.
                | FrontendReq::GET_SHMEM_CONFIG
                // Shared objects.  TODO: this can be made to work,
                // but only with integration into the rest of Cloud Hypervisor.
                | FrontendReq::GET_SHARED_OBJECT => return Err(Error::FeatureMismatch),

                | FrontendReq::SET_PROTOCOL_FEATURES => {
                    let Some(protocol_features) = u64::from_slice(buf) else {
                        error!("Bad parameter length for SET_PROTOCOL_FEATURES!");
                        return Err(Error::InvalidMessage)
                    };
                    let unsupported_features = protocol_features & !SUPPORTED_PROTOCOL_FEATURES.bits();
                    if unsupported_features != 0 {
                        error!("Unsupported vhost-user protocol feature 0b{unsupported_features:b} negotiated!");
                        return Err(Error::InvalidMessage)
                    }
                    Ok(())
                }
                /* Messages needing no interaction */
                FrontendReq::SET_VRING_NUM
                | FrontendReq::SET_VRING_ADDR
                | FrontendReq::SET_VRING_BASE
                | FrontendReq::GET_VRING_BASE
                | FrontendReq::SET_VRING_ENABLE
                | FrontendReq::GET_CONFIG
                | FrontendReq::SET_CONFIG
                | FrontendReq::CREATE_CRYPTO_SESSION
                | FrontendReq::CLOSE_CRYPTO_SESSION
                | FrontendReq::GET_MAX_MEM_SLOTS
                | FrontendReq::SET_STATUS
                | FrontendReq::GET_STATUS => Ok(())
        }?;

        Ok(())
    }

    fn get_single_file(files: &mut [Option<OwnedFd>]) -> Result<OwnedFd, Error> {
        if files.len() == 1 {
            Ok(files[0].take().unwrap())
        } else {
            Err(Error::InvalidMessage)
        }
    }
}

impl<T: Allocator, U: VM> FrontendRequestQueuePair<T, U> {
    pub fn new(
        queue_pair: queue_pair::VirtioVhostUserQueuePair,
        mapping: super::mapping::Mapping<T>,
        ioeventfds: Arc<Mutex<IoEventFds>>,
        queues: u8,
        vm: U,
    ) -> Self {
        Self {
            queue_pair,
            internals: FrontendRequestQueuePairInternals {
                checker: EventfdChecker::new()
                    .expect("cannot create eventfd checker, you're out of resources"),
                mapping,
                ioeventfds,
                queues,
                seen_log_mapping: false,
                vm,
                seen_backend_req_socket: false,
            },
        }
    }

    pub fn vm_mut(&mut self) -> &mut U {
        &mut self.internals.vm
    }

    pub fn vm(&mut self) -> &U {
        &self.internals.vm
    }

    pub fn process_replies(
        &mut self,
        access_platform: Option<Translate>,
        max_iterations: usize,
    ) -> Result<(FdRearm, bool), vhost::vhost_user::Error> {
        self.queue_pair
            .process_outgoing(access_platform, max_iterations, &mut |hdr, buf| {
                validate_reply(hdr, buf)
            })
    }
    pub fn process_requests(
        &mut self,
        access_platform: Option<Translate>,
        max_iterations: usize,
    ) -> std::result::Result<(FdRearm, bool), vhost::vhost_user::Error> {
        self.queue_pair
            .process_incoming(access_platform, max_iterations, &mut |hdr, buf, files| {
                self.internals.process_incoming(hdr, buf, files)
            })
    }
    pub fn fds(&self) -> Fds<'_> {
        self.queue_pair.fds()
    }
}
