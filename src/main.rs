// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg};

use std::path::PathBuf;

use vmm::vm::*;

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
        .arg(
            Arg::with_name("cmdline")
                .long("cmdline")
                .help("Kernel command line")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disk")
                .long("disk")
                .help("Path to VM disk image")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cpus")
                .long("cpus")
                .help("Number of virtual CPUs")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("memory")
                .long("memory")
                .help("Amount of RAM (in MB)")
                .takes_value(true),
        )
        .get_matches();

    let kernel_arg = cmd_arguments
        .value_of("kernel")
        .map(PathBuf::from)
        .expect("Missing argument: kernel");
    let kernel_path = kernel_arg.as_path();

    let cmdline = cmd_arguments
        .value_of("cmdline")
        .map(std::string::ToString::to_string)
        .expect("Missing argument: cmdline");

    let disk_arg = cmd_arguments
        .value_of("disk")
        .map(PathBuf::from)
        .expect("Missing argument: disk");
    let disk_path = disk_arg.as_path();

    let mut vcpus = DEFAULT_VCPUS;
    if let Some(cpus) = cmd_arguments.value_of("cpus") {
        vcpus = cpus.parse::<u8>().unwrap();
    }

    let mut memory = DEFAULT_MEMORY;
    if let Some(mem) = cmd_arguments.value_of("memory") {
        memory = mem.parse::<u64>().unwrap();
    }

    println!("VM [{} vCPUS {} MB of memory]", vcpus, memory);
    println!("Booting {:?}...", kernel_path);

    let vm_config = VmConfig::new(kernel_path, disk_path, cmdline, vcpus, memory).unwrap();

    vmm::boot_kernel(vm_config).unwrap();
}
