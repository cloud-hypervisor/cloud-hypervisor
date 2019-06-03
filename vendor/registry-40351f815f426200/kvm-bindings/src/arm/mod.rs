// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "kvm-v4_14_0")]
mod bindings_v4_14_0;
#[cfg(feature = "kvm-v4_20_0")]
mod bindings_v4_20_0;

// Major hack to have a default version in case no feature is specified:
// If no version is specified by using the features, just use the latest one
// which currently is 4.20.
#[cfg(all(not(feature = "kvm-v4_14_0"), not(feature = "kvm-v4_20_0")))]
mod bindings_v4_20_0;

pub mod bindings {
    #[cfg(feature = "kvm-v4_14_0")]
    pub use super::bindings_v4_14_0::*;

    #[cfg(feature = "kvm-v4_20_0")]
    pub use super::bindings_v4_20_0::*;

    #[cfg(all(not(feature = "kvm-v4_14_0"), not(feature = "kvm-v4_20_0")))]
    pub use super::bindings_v4_20_0::*;
}
