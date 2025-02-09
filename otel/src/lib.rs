// Copyright © 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

extern crate log;
#[cfg(feature = "otel")]
pub mod logger;
pub mod tracer;

pub const OTEL_SERVICE_NAME: &str = "cloud-hypervisor";

pub fn init() {
    tracer::init();
}
