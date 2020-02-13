// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::process::Command;

fn main() {
    let git_out = Command::new("git")
        .args(&["describe", "--dirty"])
        .output()
        .expect("Expect to get git describe output");

    // This println!() has a special behavior, as it will set the environment
    // variable BUILT_VERSION, so that it can be reused from the binary.
    // Particularly, this is used from src/main.rs to display the exact
    // version.
    println!(
        "cargo:rustc-env=BUILT_VERSION={}",
        String::from_utf8(git_out.stdout).unwrap()
    );
}
