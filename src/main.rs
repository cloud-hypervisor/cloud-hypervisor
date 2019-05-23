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

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod tests {
    extern crate vmm;

    use ssh2::Session;
    use std::fs;
    use std::io::Read;
    use std::net::TcpStream;
    use std::thread;
    use vmm::config;

    fn ssh_command(command: &str) -> String {
        let mut s = String::new();
        #[derive(Debug)]
        enum Error {
            Connection,
            Authentication,
            Command,
        };

        let mut counter = 0;
        loop {
            match (|| -> Result<(), Error> {
                let tcp = TcpStream::connect("192.168.2.2:22").map_err(|_| Error::Connection)?;
                let mut sess = Session::new().unwrap();
                sess.handshake(&tcp).map_err(|_| Error::Connection)?;

                sess.userauth_password("admin", "cloud123")
                    .map_err(|_| Error::Authentication)?;
                assert!(sess.authenticated());

                let mut channel = sess.channel_session().map_err(|_| Error::Command)?;
                channel.exec(command).map_err(|_| Error::Command)?;

                // Intentionally ignore these results here as their failure
                // does not precipitate a repeat
                let _ = channel.read_to_string(&mut s);
                let _ = channel.close();
                let _ = channel.wait_close();
                Ok(())
            })() {
                Ok(_) => break,
                Err(e) => {
                    counter += 1;
                    if counter >= 6 {
                        panic!("Took too many attempts to run command. Last error: {:?}", e);
                    }
                }
            };
            thread::sleep(std::time::Duration::new(10, 0));
        }
        s
    }

    fn prepare_files() -> (Vec<&'static str>, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut fw_path = workload_path.clone();
        fw_path.push("hypervisor-fw");

        let mut osdisk_base_path = workload_path.clone();
        osdisk_base_path.push("clear-29620-cloud.img");

        let osdisk_path = "/tmp/osdisk.img";
        let cloudinit_path = "/tmp/cloudinit.img";

        fs::copy(osdisk_base_path, osdisk_path).expect("copying of OS source disk image failed");

        let disks = vec![osdisk_path, cloudinit_path];

        (disks, String::from(fw_path.to_str().unwrap()))
    }

    #[test]
    fn test_simple_launch() {
        let handler = thread::spawn(|| {
            let (disks, fw_path) = prepare_files();

            let vm_config = config::VmConfig::parse(config::VmParams {
                cpus: "1",
                memory: "512",
                kernel: fw_path.as_str(),
                cmdline: None,
                disks,
                rng: "/dev/urandom",
                net: Some("tap=,mac=,ip=192.168.2.1,mask=255.255.255.0"),
            })
            .expect("Failed parsing parameters");

            vmm::boot_kernel(vm_config).expect("Booting kernel failed");
        });

        thread::sleep(std::time::Duration::new(10, 0));
        assert_eq!(ssh_command("grep -c processor /proc/cpuinfo").trim(), "1");
        assert_eq!(
            ssh_command("grep MemTotal /proc/meminfo").trim(),
            "MemTotal:         496400 kB"
        );

        assert!(
            ssh_command("cat /proc/sys/kernel/random/entropy_avail")
                .trim()
                .parse::<u32>()
                .unwrap()
                >= 1000
        );

        ssh_command("sudo reboot");

        handler.join().unwrap();
    }

    #[test]
    fn test_simple_launch_again() {
        test_simple_launch()
    }
}
