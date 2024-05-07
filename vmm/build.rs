// Copyright © 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
}
