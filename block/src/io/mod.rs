// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared I/O infrastructure for all disk format backends.
//!
//! Contains the async I/O trait, request handling, and file locking
//! helpers.

pub mod async_io;
pub mod fcntl;
pub mod request;
