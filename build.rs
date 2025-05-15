// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;
use std::process::Command;

fn main() {
    let mut version = "v".to_owned() + env!("CARGO_PKG_VERSION");

    if let Ok(git_out) = Command::new("git").args(["describe", "--dirty"]).output() {
        if git_out.status.success() {
            if let Ok(git_out_str) = String::from_utf8(git_out.stdout) {
                version = git_out_str;
                // Pop the trailing newline.
                version.pop();
            }
        }
    }

    // Append CH_EXTRA_VERSION to version if it is set.
    if let Ok(extra_version) = env::var("CH_EXTRA_VERSION") {
        println!("cargo:rerun-if-env-changed=CH_EXTRA_VERSION");
        version.push_str(&format!("-{extra_version}"));
    }

    // This println!() has a special behavior, as it will set the environment
    // variable BUILD_VERSION, so that it can be reused from the binary.
    // Particularly, this is used from src/main.rs to display the exact
    // version.
    println!("cargo:rustc-env=BUILD_VERSION={version}");
}
