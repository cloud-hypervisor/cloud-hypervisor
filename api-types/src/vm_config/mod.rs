// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::ArgMatches;
#[cfg(feature = "pvmemcontrol")]
use serde::{Deserialize, Serialize};

pub(crate) mod balloon_config;
pub(crate) mod console_config;
pub(crate) mod cpus_config;
pub(crate) mod device_config;
pub(crate) mod disk_config;
pub(crate) mod fs_config;
#[cfg(feature = "fw_cfg")]
pub(crate) mod fw_cfg_config;
pub(crate) mod generic_vhost_user_config;
#[cfg(feature = "ivshmem")]
pub(crate) mod ivshmem_config;
pub(crate) mod landlock_config;
pub(crate) mod memory_config;
pub(crate) mod net_config;
pub(crate) mod numa_config;
pub(crate) mod payload_config;
pub(crate) mod pci_device_common_config;
pub(crate) mod pci_segment_config;
pub(crate) mod platform_config;
pub(crate) mod pmem_config;
pub(crate) mod rate_limiter_group_config;
pub(crate) mod rng_config;
pub(crate) mod rtc_config;
pub(crate) mod tpm_config;
pub(crate) mod user_device_config;
pub(crate) mod vdpa_config;
pub(crate) mod vsock_config;

#[cfg(feature = "pvmemcontrol")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct PvmemcontrolConfig {}

pub struct VmParams<'a> {
    pub cpus: &'a str,
    pub memory: &'a str,
    pub memory_zones: Option<Vec<&'a str>>,
    pub firmware: Option<&'a str>,
    pub kernel: Option<&'a str>,
    pub initramfs: Option<&'a str>,
    pub cmdline: Option<&'a str>,
    pub rate_limit_groups: Option<Vec<&'a str>>,
    pub disks: Option<Vec<&'a str>>,
    pub net: Option<Vec<&'a str>>,
    pub rng: &'a str,
    pub balloon: Option<&'a str>,
    pub fs: Option<Vec<&'a str>>,
    pub generic_vhost_user: Option<Vec<&'a str>>,
    pub pmem: Option<Vec<&'a str>>,
    pub serial: &'a str,
    pub console: &'a str,
    #[cfg(target_arch = "x86_64")]
    pub debug_console: &'a str,
    pub devices: Option<Vec<&'a str>>,
    pub user_devices: Option<Vec<&'a str>>,
    pub vdpa: Option<Vec<&'a str>>,
    pub vsock: Option<&'a str>,
    #[cfg(feature = "pvmemcontrol")]
    pub pvmemcontrol: bool,
    pub pvpanic: bool,
    pub numa: Option<Vec<&'a str>>,
    pub watchdog: bool,
    pub rtc: Option<&'a str>,
    #[cfg(feature = "guest_debug")]
    pub gdb: bool,
    pub pci_segments: Option<Vec<&'a str>>,
    pub platform: Option<&'a str>,
    pub tpm: Option<&'a str>,
    #[cfg(feature = "igvm")]
    pub igvm: Option<&'a str>,
    #[cfg(feature = "sev_snp")]
    pub host_data: Option<&'a str>,
    pub landlock_enable: bool,
    pub landlock_rules: Option<Vec<&'a str>>,
    #[cfg(feature = "fw_cfg")]
    pub fw_cfg_config: Option<&'a str>,
    #[cfg(feature = "ivshmem")]
    pub ivshmem: Option<&'a str>,
}

impl<'a> VmParams<'a> {
    pub fn from_arg_matches(args: &'a ArgMatches) -> Self {
        // These .unwrap()s cannot fail as there is a default value defined
        let cpus = args.get_one::<String>("cpus").unwrap();
        let memory = args.get_one::<String>("memory").unwrap();
        let memory_zones: Option<Vec<&str>> = args
            .get_many::<String>("memory-zone")
            .map(|x| x.map(|y| y as &str).collect());
        let rng = args.get_one::<String>("rng").unwrap();
        let serial = args.get_one::<String>("serial").unwrap();
        let firmware = args.get_one::<String>("firmware").map(|x| x as &str);
        let kernel = args.get_one::<String>("kernel").map(|x| x as &str);
        let initramfs = args.get_one::<String>("initramfs").map(|x| x as &str);
        let cmdline = args.get_one::<String>("cmdline").map(|x| x as &str);
        let rate_limit_groups: Option<Vec<&str>> = args
            .get_many::<String>("rate-limit-group")
            .map(|x| x.map(|y| y as &str).collect());
        let disks: Option<Vec<&str>> = args
            .get_many::<String>("disk")
            .map(|x| x.map(|y| y as &str).collect());
        let net: Option<Vec<&str>> = args
            .get_many::<String>("net")
            .map(|x| x.map(|y| y as &str).collect());
        let console = args.get_one::<String>("console").unwrap();
        #[cfg(target_arch = "x86_64")]
        let debug_console = args.get_one::<String>("debug-console").unwrap().as_str();
        let balloon = args.get_one::<String>("balloon").map(|x| x as &str);
        let fs: Option<Vec<&str>> = args
            .get_many::<String>("fs")
            .map(|x| x.map(|y| y as &str).collect());
        let generic_vhost_user: Option<Vec<&str>> = args
            .get_many::<String>("generic-vhost-user")
            .map(|x| x.map(|y| y as &str).collect());
        let pmem: Option<Vec<&str>> = args
            .get_many::<String>("pmem")
            .map(|x| x.map(|y| y as &str).collect());
        let devices: Option<Vec<&str>> = args
            .get_many::<String>("device")
            .map(|x| x.map(|y| y as &str).collect());
        let user_devices: Option<Vec<&str>> = args
            .get_many::<String>("user-device")
            .map(|x| x.map(|y| y as &str).collect());
        let vdpa: Option<Vec<&str>> = args
            .get_many::<String>("vdpa")
            .map(|x| x.map(|y| y as &str).collect());
        let vsock: Option<&str> = args.get_one::<String>("vsock").map(|x| x as &str);
        #[cfg(feature = "pvmemcontrol")]
        let pvmemcontrol = args.get_flag("pvmemcontrol");
        let pvpanic = args.get_flag("pvpanic");
        let numa: Option<Vec<&str>> = args
            .get_many::<String>("numa")
            .map(|x| x.map(|y| y as &str).collect());
        let watchdog = args.get_flag("watchdog");
        let rtc: Option<&str> = args.get_one::<String>("rtc").map(|x| x as &str);
        let pci_segments: Option<Vec<&str>> = args
            .get_many::<String>("pci-segment")
            .map(|x| x.map(|y| y as &str).collect());
        let platform = args.get_one::<String>("platform").map(|x| x as &str);
        #[cfg(feature = "guest_debug")]
        let gdb = args.contains_id("gdb");
        let tpm: Option<&str> = args.get_one::<String>("tpm").map(|x| x as &str);
        #[cfg(feature = "igvm")]
        let igvm = args.get_one::<String>("igvm").map(|x| x as &str);
        #[cfg(feature = "sev_snp")]
        let host_data = args.get_one::<String>("host-data").map(|x| x as &str);
        let landlock_enable = args.get_flag("landlock");
        let landlock_rules: Option<Vec<&str>> = args
            .get_many::<String>("landlock-rules")
            .map(|x| x.map(|y| y as &str).collect());
        #[cfg(feature = "fw_cfg")]
        let fw_cfg_config: Option<&str> =
            args.get_one::<String>("fw-cfg-config").map(|x| x as &str);
        #[cfg(feature = "ivshmem")]
        let ivshmem: Option<&str> = args.get_one::<String>("ivshmem").map(|x| x as &str);
        VmParams {
            cpus,
            memory,
            memory_zones,
            firmware,
            kernel,
            initramfs,
            cmdline,
            rate_limit_groups,
            disks,
            net,
            rng,
            balloon,
            fs,
            generic_vhost_user,
            pmem,
            serial,
            console,
            #[cfg(target_arch = "x86_64")]
            debug_console,
            devices,
            user_devices,
            vdpa,
            vsock,
            #[cfg(feature = "pvmemcontrol")]
            pvmemcontrol,
            pvpanic,
            numa,
            watchdog,
            rtc,
            #[cfg(feature = "guest_debug")]
            gdb,
            pci_segments,
            platform,
            tpm,
            #[cfg(feature = "igvm")]
            igvm,
            #[cfg(feature = "sev_snp")]
            host_data,
            landlock_enable,
            landlock_rules,
            #[cfg(feature = "fw_cfg")]
            fw_cfg_config,
            #[cfg(feature = "ivshmem")]
            ivshmem,
        }
    }
}
