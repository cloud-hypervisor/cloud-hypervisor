// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
}
