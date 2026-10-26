// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The rbd-sys and rados-sys crates normally emit the link directives
// themselves. When built with `--cfg ceph_sys_bundled` (or
// `ceph_sys_nolink`) they do not, so link the Ceph client libraries here
// whenever the RBD backend is enabled. Duplicate link directives in the
// default configuration are harmless.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RBD");

    if env::var_os("CARGO_FEATURE_RBD").is_some() {
        println!("cargo:rustc-link-lib=rbd");
        println!("cargo:rustc-link-lib=rados");
    }
}
