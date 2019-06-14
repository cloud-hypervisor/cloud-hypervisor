// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD file.

//! Trait to control vhost-vsock backend drivers.

use crate::backend::VhostBackend;
use crate::Result;

/// Trait to control vhost-vsock backend drivers.
pub trait VhostVsock: VhostBackend {
    /// Set the CID for the guest.
    /// This number is used for routing all data destined for running in the guest.
    /// Each guest on a hypervisor must have an unique CID.
    ///
    /// # Arguments
    /// * `cid` - CID to assign to the guest
    fn set_guest_cid(&mut self, cid: u64) -> Result<()>;

    /// Tell the VHOST driver to start performing data transfer.
    fn start(&mut self) -> Result<()>;

    /// Tell the VHOST driver to stop performing data transfer.
    fn stop(&mut self) -> Result<()>;
}
