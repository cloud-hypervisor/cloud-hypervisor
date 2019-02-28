// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg};

use std::path::PathBuf;

fn main() {
    let cmd_arguments = App::new("cloud-hypervisor")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a cloud-hypervisor VMM.")
        .arg(
            Arg::with_name("kernel")
                .long("kernel")
                .help("Path to kernel image (vmlinux)")
                .takes_value(true),
        )
        .get_matches();

    let kernel_path = cmd_arguments
        .value_of("kernel")
        .map(PathBuf::from)
        .expect("Missing argument: kernel");

    println!("Booting {:?}...", kernel_path.as_path());

    vmm::boot_kernel(kernel_path.as_path()).unwrap();
}
