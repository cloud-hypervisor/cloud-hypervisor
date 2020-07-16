// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(unused)]
#[allow(
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes,
    clippy::trivially_copy_pass_by_ref,
    clippy::useless_transmute,
    clippy::should_implement_trait,
    clippy::transmute_ptr_to_ptr,
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes
)]
#[cfg(target_arch = "x86_64")]
pub mod x86;
