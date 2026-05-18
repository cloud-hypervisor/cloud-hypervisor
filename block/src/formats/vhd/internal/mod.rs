// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! VHD format parsing and data structures.
//!
//! Contains the footer parser and the low level fixed VHD
//! block backend.

pub(crate) mod fixed;
pub(crate) mod footer;
