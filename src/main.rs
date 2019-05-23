// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg};
use std::process;
use vmm::config;

fn main() {
    let cmd_arguments = App::new("cloud-hypervisor")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a cloud-hypervisor VMM.")
        .arg(
            Arg::with_name("cpus")
                .long("cpus")
                .help("Number of virtual CPUs")
                .default_value(config::DEFAULT_VCPUS),
        )
        .arg(
            Arg::with_name("memory")
                .long("memory")
                .help("Amount of RAM (in MiB)")
                .default_value(config::DEFAULT_MEMORY),
        )
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
                .help(
                    "Network parameters \"tap=<if_name>,\
                     ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>\"",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rng")
                .long("rng")
                .help("Path to entropy source")
                .default_value(config::DEFAULT_RNG_SOURCE),
        )
        .get_matches();

    // These .unwrap()s cannot fail as there is a default value defined
    let cpus = cmd_arguments.value_of("cpus").unwrap();
    let memory = cmd_arguments.value_of("memory").unwrap();

    let kernel = cmd_arguments
        .value_of("kernel")
        .expect("Missing argument: kernel");

    let cmdline = cmd_arguments.value_of("cmdline");

    let disks: Vec<&str> = cmd_arguments
        .values_of("disk")
        .expect("Missing argument: disk. Provide at least one")
        .collect();

    let net = cmd_arguments.value_of("net");

    // This .unwrap() cannot fail as there is a default value defined
    let rng = cmd_arguments.value_of("rng").unwrap();

    let vm_config = match config::VmConfig::parse(config::VmParams {
        cpus,
        memory,
        kernel,
        cmdline,
        disks,
        rng,
        net,
    }) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    println!(
        "Cloud Hypervisor Guest\n\tvCPUs: {}\n\tMemory: {} MB\
         \n\tKernel: {:?}\n\tKernel cmdline: {}\n\tDisk(s): {:?}",
        u8::from(&vm_config.cpus),
        u64::from(&vm_config.memory),
        vm_config.kernel.path,
        vm_config.cmdline.args.as_str(),
        vm_config.disks,
    );

    if let Err(e) = vmm::boot_kernel(vm_config) {
        println!("Guest boot failed: {}", e);
        process::exit(1);
    }
}
