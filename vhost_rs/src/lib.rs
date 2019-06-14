// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD file.

//! Virtio Vhost Backend Drivers
//!
//! Virtio devices use virtqueues to transport data efficiently. Virtqueue is a set of three
//! different single-producer, single-consumer ring structures designed to store generic
//! scatter-gather I/O.
//!
//! Vhost is a mechanism to improve performance of Virtio devices by delegate data plane operations
//! to dedicated IO service processes. Only the configuration, I/O submission notification, and I/O
//! completion interruption are piped through the hypervisor.
//! It uses the same virtqueue layout as Virtio to allow Vhost devices to be mapped directly to
//! Virtio devices. This allows a Vhost device to be accessed directly by a guest OS inside a
//! hypervisor process with an existing Virtio (PCI) driver.
//!
//! The initial vhost implementation is a part of the Linux kernel and uses ioctl interface to
//! communicate with userspace applications. Dedicated kernel worker threads are created to handle
//! IO requests from the guest.
//!
//! Later Vhost-user protocol is introduced to complement the ioctl interface used to control the
//! vhost implementation in the Linux kernel. It implements the control plane needed to establish
//! virtqueues sharing with a user space process on the same host. It uses communication over a
//! Unix domain socket to share file descriptors in the ancillary data of the message.
//! The protocol defines 2 sides of the communication, master and slave. Master is the application
//! that shares its virtqueues. Slave is the consumer of the virtqueues. Master and slave can be
//! either a client (i.e. connecting) or server (listening) in the socket communication.

#![deny(missing_docs)]

#[cfg_attr(
    any(feature = "vhost-user-master", feature = "vhost-user-slave"),
    macro_use
)]
extern crate bitflags;
extern crate libc;
#[cfg(feature = "vhost-kern")]
extern crate vm_memory;
#[cfg_attr(feature = "vhost-kern", macro_use)]
extern crate vmm_sys_util;

mod backend;
pub use backend::*;

#[cfg(feature = "vhost-kern")]
pub mod vhost_kern;
#[cfg(any(feature = "vhost-user-master", feature = "vhost-user-slave"))]
pub mod vhost_user;
#[cfg(feature = "vhost-vsock")]
pub mod vsock;

/// Error codes for vhost operations
#[derive(Debug)]
pub enum Error {
    /// Invalid operations.
    InvalidOperation,
    /// Invalid guest memory.
    InvalidGuestMemory,
    /// Invalid guest memory region.
    InvalidGuestMemoryRegion,
    /// Invalid queue.
    InvalidQueue,
    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Invalid used address.
    UsedAddress,
    /// Invalid available address.
    AvailAddress,
    /// Invalid log address.
    LogAddress,
    #[cfg(feature = "vhost-kern")]
    /// Error opening the vhost backend driver.
    VhostOpen(std::io::Error),
    #[cfg(feature = "vhost-kern")]
    /// Error while running ioctl.
    IoctlError(std::io::Error),
    /// Error from IO subsystem.
    IOError(std::io::Error),
    #[cfg(any(feature = "vhost-user-master", feature = "vhost-user-slave"))]
    /// Error from the vhost-user subsystem.
    VhostUserProtocol(vhost_user::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidOperation => write!(f, "invalid vhost operations"),
            Error::InvalidGuestMemory => write!(f, "invalid guest memory object"),
            Error::InvalidGuestMemoryRegion => write!(f, "invalid guest memory region"),
            Error::InvalidQueue => write!(f, "invalid virtque"),
            Error::DescriptorTableAddress => write!(f, "invalid virtque descriptor talbe address"),
            Error::UsedAddress => write!(f, "invalid virtque used talbe address"),
            Error::AvailAddress => write!(f, "invalid virtque available talbe address"),
            Error::LogAddress => write!(f, "invalid virtque log address"),
            Error::IOError(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "vhost-kern")]
            Error::VhostOpen(e) => write!(f, "failure in opening vhost file: {}", e),
            #[cfg(feature = "vhost-kern")]
            Error::IoctlError(e) => write!(f, "failure in vhost ioctl: {}", e),
            #[cfg(any(feature = "vhost-user-master", feature = "vhost-user-slave"))]
            Error::VhostUserProtocol(e) => write!(f, "vhost-user: {}", e),
        }
    }
}

#[cfg(any(feature = "vhost-user-master", feature = "vhost-user-slave"))]
impl std::convert::From<vhost_user::Error> for Error {
    fn from(err: vhost_user::Error) -> Self {
        Error::VhostUserProtocol(err)
    }
}

/// Result of vhost operations
pub type Result<T> = std::result::Result<T, Error>;
