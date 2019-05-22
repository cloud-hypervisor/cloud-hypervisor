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
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("net")
                .long("net")
                .help("Network parameters \"tap=<if_name>,ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>\"")
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
        .arg(
            Arg::with_name("rng")
                .long("rng")
                .help("Path to entropy source")
                .default_value("/dev/urandom"),
        )
        .get_matches();

    let kernel_arg = cmd_arguments
        .value_of("kernel")
        .map(PathBuf::from)
        .expect("Missing argument: kernel");
    let kernel_path = kernel_arg.as_path();

    let disk_paths: Vec<PathBuf> = cmd_arguments
        .values_of("disk")
        .expect("Missing arguments on disk")
        .map(PathBuf::from)
        .collect();

    let cmdline = if cmd_arguments.is_present("cmdline") {
        cmd_arguments
            .value_of("cmdline")
            .map(std::string::ToString::to_string)
            .unwrap()
    } else {
        String::new()
    };

    let mut net_params = None;
    if cmd_arguments.is_present("net") {
        if let Some(net) = cmd_arguments.value_of("net") {
            net_params = Some(net.to_string());
        } else {
            net_params = Some(String::new())
        }
    }

    let rng_path = match cmd_arguments.occurrences_of("rng") {
        0 => None,
        _ => Some(cmd_arguments.value_of("rng").unwrap().to_string()),
    };

    let mut vcpus = DEFAULT_VCPUS;
    if let Some(cpus) = cmd_arguments.value_of("cpus") {
        vcpus = cpus.parse::<u8>().unwrap();
    }

    let mut memory = DEFAULT_MEMORY;
    if let Some(mem) = cmd_arguments.value_of("memory") {
        memory = mem.parse::<u64>().unwrap();
    }

    println!(
        "Cloud Hypervisor Guest\n\tvCPUs: {}\n\tMemory: {} MB\n\tKernel: {:?}\n\tKernel cmdline: {}\n\tDisk(s): {:?}",
        vcpus, memory, kernel_path, cmdline, disk_paths,
    );

    let vm_config = VmConfig::new(
        kernel_path,
        disk_paths,
        rng_path,
        cmdline,
        net_params,
        vcpus,
        memory,
    )
    .unwrap();

    if let Err(e) = vmm::boot_kernel(vm_config) {
        println!("Guest boot failed: {}", e);
    }
}
