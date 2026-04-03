// Copyright © 2026 Demi Marie Obenour <demiobenour@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the virtio-vhost-user protocol

mod backend_request;
mod eventfd_checker;
mod frontend_request;
mod mapping;
mod queue_pair;

pub use backend_request::BackendRequestQueuePair;
pub use frontend_request::{FrontendRequestQueuePair, IoEventFds, SUPPORTED_PROTOCOL_FEATURES, VM};
pub use mapping::{Allocator, Mapping, Region};
pub use queue_pair::{FdRearm, Fds, Translate, VirtioVhostUserQueuePair};
