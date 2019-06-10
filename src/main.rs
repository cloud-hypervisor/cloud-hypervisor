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
#[macro_use]
extern crate credibility;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod tests {
    use ssh2::Session;
    use std::fs;
    use std::io::Read;
    use std::net::TcpStream;
    use std::process::Command;
    use std::thread;

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
        osdisk_base_path.push("clear-29810-cloud.img");

        let osdisk_path = "/tmp/osdisk.img";
        let cloudinit_path = "/tmp/cloudinit.img";

        fs::copy(osdisk_base_path, osdisk_path).expect("copying of OS source disk image failed");

        let disks = vec![osdisk_path, cloudinit_path];

        (disks, String::from(fw_path.to_str().unwrap()))
    }

    fn get_cpu_count() -> u32 {
        ssh_command("grep -c processor /proc/cpuinfo")
            .trim()
            .parse()
            .unwrap()
    }

    fn get_total_memory() -> u32 {
        ssh_command("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")
            .trim()
            .parse::<u32>()
            .unwrap()
    }

    fn get_entropy() -> u32 {
        ssh_command("cat /proc/sys/kernel/random/entropy_avail")
            .trim()
            .parse::<u32>()
            .unwrap()
    }

    #[test]
    fn test_simple_launch() {
        test_block!(tb, "", {
            let (disks, fw_path) = prepare_files();
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "512"])
                .args(&["--kernel", fw_path.as_str()])
                .args(&["--disk", disks[0], disks[1]])
                .args(&["--net", "tap=,mac=,ip=192.168.2.1,mask=255.255.255.0"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));

            aver_eq!(tb, get_cpu_count(), 1);
            aver!(tb, get_total_memory() > 496_000);
            aver!(tb, get_entropy() >= 1000);

            ssh_command("sudo reboot");
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_multi_cpu() {
        test_block!(tb, "", {
            let (disks, fw_path) = prepare_files();
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "2"])
                .args(&["--memory", "512"])
                .args(&["--kernel", fw_path.as_str()])
                .args(&["--disk", disks[0], disks[1]])
                .args(&["--net", "tap=,mac=,ip=192.168.2.1,mask=255.255.255.0"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));

            aver_eq!(tb, get_cpu_count(), 2);

            ssh_command("sudo reboot");
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_large_memory() {
        test_block!(tb, "", {
            let (disks, fw_path) = prepare_files();
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "5120"])
                .args(&["--kernel", fw_path.as_str()])
                .args(&["--disk", disks[0], disks[1]])
                .args(&["--net", "tap=,mac=,ip=192.168.2.1,mask=255.255.255.0"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));

            aver!(tb, get_total_memory() > 5_063_000);

            ssh_command("sudo reboot");
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_pci_msi() {
        test_block!(tb, "", {
            let (disks, fw_path) = prepare_files();
            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "512"])
                .args(&["--kernel", fw_path.as_str()])
                .args(&["--disk", disks[0], disks[1]])
                .args(&["--net", "tap=,mac=,ip=192.168.2.1,mask=255.255.255.0"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));

            aver_eq!(
                tb,
                ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .trim()
                    .parse::<u32>()
                    .unwrap(),
                8
            );

            ssh_command("sudo reboot");
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }

    #[test]
    fn test_vmlinux_boot() {
        test_block!(tb, "", {
            let (disks, _) = prepare_files();
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut kernel_path = workload_path.clone();
            kernel_path.push("vmlinux");

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--cpus", "1"])
                .args(&["--memory", "512"])
                .args(&["--kernel", kernel_path.to_str().unwrap()])
                .args(&["--disk", disks[0], disks[1]])
                .args(&["--net", "tap=,mac=,ip=192.168.2.1,mask=255.255.255.0"])
                .args(&["--cmdline", "root=PARTUUID=3cb0e0a5-925d-405e-bc55-edf0cec8f10a console=tty0 console=ttyS0,115200n8 console=hvc0 quiet init=/usr/lib/systemd/systemd-bootchart initcall_debug tsc=reliable no_timer_check noreplace-smp cryptomgr.notests rootfstype=ext4,btrfs,xfs kvm-intel.nested=1 rw"])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(10, 0));

            aver_eq!(tb, get_cpu_count(), 1);
            aver!(tb, get_total_memory() > 496_000);
            aver!(tb, get_entropy() >= 1000);
            aver_eq!(
                tb,
                ssh_command("grep -c PCI-MSI /proc/interrupts")
                    .trim()
                    .parse::<u32>()
                    .unwrap(),
                8
            );

            ssh_command("sudo reboot");
            thread::sleep(std::time::Duration::new(10, 0));
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
    }
}
