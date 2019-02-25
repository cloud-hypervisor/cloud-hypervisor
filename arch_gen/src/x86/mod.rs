// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(
    clippy::unreadable_literal,
    clippy::const_static_lifetime,
    clippy::trivially_copy_pass_by_ref,
    clippy::useless_transmute,
    clippy::should_implement_trait,
    clippy::transmute_ptr_to_ptr
)]
pub mod bootparam;
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(clippy::unreadable_literal, clippy::const_static_lifetime)]
pub mod mpspec;
#[allow(non_upper_case_globals)]
#[allow(clippy::unreadable_literal, clippy::const_static_lifetime)]
pub mod msr_index;
