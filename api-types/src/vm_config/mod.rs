// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    BalloonConfig, BalloonConfigParseError, ConsoleConfig, ConsoleConfigParseError, CpusConfig,
    CpusConfigParseError, DeviceConfig, DeviceConfigParseError, DiskConfig, DiskConfigParseError,
    FsConfig, FsConfigParseError, GenericVhostUserConfig, GenericVhostUserConfigParseError,
    LandlockConfig, LandlockConfigParseError, MemoryConfig, MemoryConfigParseError, NetConfig,
    NetConfigParseError, NumaConfig, PayloadConfig, PciSegmentConfig, PciSegmentConfigParseError,
    PlatformConfig, PlatformConfigParseError, PmemConfig, PmemConfigParseError,
    RateLimiterGroupConfig, RateLimiterGroupConfigParseError, RngConfig, RngConfigParseError,
    RtcConfig, RtcConfigParseError, SerialConfig, SerialConfigParseError, TpmConfig,
    TpmConfigParseError, UserDeviceConfig, UserDeviceConfigParseError, VdpaConfig,
    VdpaConfigParseError, VsockConfig, VsockConfigParseError,
};
#[cfg(target_arch = "x86_64")]
use super::{DebugConsoleConfig, DebugConsoleConfigParseError};
#[cfg(feature = "fw_cfg")]
use super::{FwCfgConfig, FwCfgConfigParseError};
#[cfg(feature = "ivshmem")]
use super::{IvshmemConfig, IvshmemConfigParseError};
use crate::vm_config::numa_config::NumaConfigParseError;

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

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VmConfig {
    #[serde(default)]
    pub cpus: CpusConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    pub payload: Option<PayloadConfig>,
    pub rate_limit_groups: Option<Box<[RateLimiterGroupConfig]>>,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    #[serde(default)]
    pub rng: RngConfig,
    pub balloon: Option<BalloonConfig>,
    pub generic_vhost_user: Option<Vec<GenericVhostUserConfig>>,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default)]
    pub serial: SerialConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub debug_console: DebugConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub user_devices: Option<Vec<UserDeviceConfig>>,
    pub vdpa: Option<Vec<VdpaConfig>>,
    pub vsock: Option<VsockConfig>,
    #[cfg(feature = "pvmemcontrol")]
    #[serde(default)]
    pub pvmemcontrol: Option<PvmemcontrolConfig>,
    #[serde(default)]
    pub pvpanic: bool,
    #[serde(default)]
    pub iommu: bool,
    pub numa: Option<Box<[NumaConfig]>>,
    #[serde(default)]
    pub watchdog: bool,
    #[serde(default)]
    pub rtc: Option<RtcConfig>,
    #[cfg(feature = "guest_debug")]
    #[serde(default)]
    pub gdb: bool,
    pub pci_segments: Option<Box<[PciSegmentConfig]>>,
    pub platform: Option<PlatformConfig>,
    pub tpm: Option<TpmConfig>,
    #[serde(default)]
    pub landlock_enable: bool,
    pub landlock_rules: Option<Box<[LandlockConfig]>>,
    #[cfg(feature = "ivshmem")]
    pub ivshmem: Option<IvshmemConfig>,
}

#[derive(Error, Debug)]
pub enum VmConfigParseError {
    /// Error parsing disk options
    #[error("Error parsing --disk")]
    Disk(#[from] DiskConfigParseError),
    /// Failed Parsing FwCfgItem config
    #[cfg(feature = "fw_cfg")]
    #[error("Error parsing --fw-cfg-config items")]
    FwCfgConfig(#[from] FwCfgConfigParseError),
    /// Error parsing RNG options
    #[error("Error parsing --rng")]
    Rng(#[from] RngConfigParseError),
    /// Error parsing network options
    #[error("Error parsing --net")]
    Network(#[from] NetConfigParseError),
    /// Error parsing RTC options
    #[error("Error parsing --rtc")]
    Rtc(#[from] RtcConfigParseError),
    /// Error parsing balloon options
    #[error("Error parsing --balloon")]
    Balloon(#[from] BalloonConfigParseError),
    /// Error parsing filesystem parameters
    #[error("Error parsing --fs")]
    FileSystem(#[from] FsConfigParseError),
    /// Error parsing persistent memory parameters
    #[error("Error parsing --pmem")]
    PersistentMemory(#[from] PmemConfigParseError),
    /// Failed parsing console parameters
    #[error("Error parsing --console")]
    Console(#[from] ConsoleConfigParseError),
    /// Failed parsing serial parameters
    #[error("Error parsing --serial")]
    Serial(#[from] SerialConfigParseError),
    /// Failed parsing device parameters
    #[error("Error parsing --device")]
    Device(#[from] DeviceConfigParseError),
    /// Failed parsing userspace device
    #[error("Error parsing --user-device")]
    UserDevice(#[from] UserDeviceConfigParseError),
    /// Failed parsing vDPA device
    #[error("Error parsing --vdpa")]
    Vdpa(#[from] VdpaConfigParseError),
    /// Error parsing pci segment options
    #[error("Error parsing --pci-segment")]
    PciSegment(#[from] PciSegmentConfigParseError),
    /// Error parsing rate-limiter group options
    #[error("Error parsing --rate-limit-group")]
    RateLimiterGroup(#[from] RateLimiterGroupConfigParseError),
    /// Error parsing generic vhost-user parameters
    #[error("Error parsing --generic-vhost-user")]
    GenericVhostUser(#[from] GenericVhostUserConfigParseError),
    #[cfg(target_arch = "x86_64")]
    /// Failed parsing debug-console
    #[error("Error parsing --debug-console")]
    DebugConsole(#[from] DebugConsoleConfigParseError),
    /// Failed parsing platform parameters
    #[error("Error parsing --platform")]
    Platform(#[from] PlatformConfigParseError),
    /// Failed parsing vsock parameters
    #[error("Error parsing --vsock")]
    Vsock(#[from] VsockConfigParseError),
    /// Failed parsing NUMA parameters
    #[error("Error parsing --numa")]
    Numa(#[from] NumaConfigParseError),
    /// Failed parsing TPM device
    #[error("Error parsing --tpm")]
    Tpm(#[from] TpmConfigParseError),
    /// Error parsing CPU options
    #[error("Error parsing --cpus")]
    Cpus(#[from] CpusConfigParseError),
    /// Error parsing memory options
    #[error("Error parsing --memory")]
    Memory(#[from] MemoryConfigParseError),
    #[cfg(feature = "ivshmem")]
    /// Failed parsing ivsmem device
    #[error("Error parsing --ivshmem")]
    Ivshmem(#[from] IvshmemConfigParseError),
    /// Error parsing Landlock rules
    #[error("Error parsing --landlock-rules")]
    LandlockRules(#[from] LandlockConfigParseError),
}

impl VmConfig {
    pub fn parse(vm_params: VmParams) -> Result<Self, VmConfigParseError> {
        let mut rate_limit_groups: Option<Box<[RateLimiterGroupConfig]>> = None;
        if let Some(rate_limit_group_list) = &vm_params.rate_limit_groups {
            let mut rate_limit_group_config_list = Vec::new();
            for item in rate_limit_group_list.iter() {
                let rate_limit_group_config = RateLimiterGroupConfig::parse(item)?;
                rate_limit_group_config_list.push(rate_limit_group_config);
            }
            rate_limit_groups = Some(rate_limit_group_config_list.into_boxed_slice());
        }

        let mut disks: Option<Vec<DiskConfig>> = None;
        if let Some(disk_list) = &vm_params.disks {
            let mut disk_config_list = Vec::new();
            for item in disk_list.iter() {
                let disk_config = DiskConfig::parse(item)?;
                disk_config_list.push(disk_config);
            }
            disks = Some(disk_config_list);
        }

        #[cfg(feature = "fw_cfg")]
        let fw_cfg_config = if let Some(fw_cfg_config_str) = vm_params.fw_cfg_config {
            let fw_cfg_config = FwCfgConfig::parse(fw_cfg_config_str)?;
            Some(fw_cfg_config)
        } else {
            None
        };

        let mut net: Option<Vec<NetConfig>> = None;
        if let Some(net_list) = &vm_params.net {
            let mut net_config_list = Vec::new();
            for item in net_list.iter() {
                let net_config = NetConfig::parse(item)?;
                net_config_list.push(net_config);
            }
            net = Some(net_config_list);
        }

        let rng = RngConfig::parse(vm_params.rng)?;

        let mut rtc: Option<RtcConfig> = None;
        if let Some(rtc_params) = &vm_params.rtc {
            rtc = Some(RtcConfig::parse(rtc_params)?);
        }

        let mut balloon: Option<BalloonConfig> = None;
        if let Some(balloon_params) = &vm_params.balloon {
            balloon = Some(BalloonConfig::parse(balloon_params)?);
        }

        #[cfg(feature = "pvmemcontrol")]
        let pvmemcontrol: Option<PvmemcontrolConfig> = vm_params
            .pvmemcontrol
            .then_some(PvmemcontrolConfig::default());

        let mut fs: Option<Vec<FsConfig>> = None;
        if let Some(fs_list) = &vm_params.fs {
            let mut fs_config_list = Vec::new();
            for item in fs_list.iter() {
                fs_config_list.push(FsConfig::parse(item)?);
            }
            fs = Some(fs_config_list);
        }

        let mut generic_vhost_user: Option<Vec<GenericVhostUserConfig>> = None;
        if let Some(generic_vhost_user_list) = &vm_params.generic_vhost_user {
            let mut generic_vhost_user_config_list = Vec::new();
            for item in generic_vhost_user_list.iter() {
                generic_vhost_user_config_list.push(GenericVhostUserConfig::parse(item)?);
            }
            generic_vhost_user = Some(generic_vhost_user_config_list);
        }

        let mut pmem: Option<Vec<PmemConfig>> = None;
        if let Some(pmem_list) = &vm_params.pmem {
            let mut pmem_config_list = Vec::new();
            for item in pmem_list.iter() {
                let pmem_config = PmemConfig::parse(item)?;
                pmem_config_list.push(pmem_config);
            }
            pmem = Some(pmem_config_list);
        }

        let console = ConsoleConfig::parse(vm_params.console)?;
        let serial = SerialConfig::parse(vm_params.serial)?;
        #[cfg(target_arch = "x86_64")]
        let debug_console = DebugConsoleConfig::parse(vm_params.debug_console)?;

        let mut devices: Option<Vec<DeviceConfig>> = None;
        if let Some(device_list) = &vm_params.devices {
            let mut device_config_list = Vec::new();
            for item in device_list.iter() {
                let device_config = DeviceConfig::parse(item)?;
                device_config_list.push(device_config);
            }
            devices = Some(device_config_list);
        }

        let mut user_devices: Option<Vec<UserDeviceConfig>> = None;
        if let Some(user_device_list) = &vm_params.user_devices {
            let mut user_device_config_list = Vec::new();
            for item in user_device_list.iter() {
                let user_device_config = UserDeviceConfig::parse(item)?;
                user_device_config_list.push(user_device_config);
            }
            user_devices = Some(user_device_config_list);
        }

        let mut vdpa: Option<Vec<VdpaConfig>> = None;
        if let Some(vdpa_list) = &vm_params.vdpa {
            let mut vdpa_config_list = Vec::new();
            for item in vdpa_list.iter() {
                let vdpa_config = VdpaConfig::parse(item)?;
                vdpa_config_list.push(vdpa_config);
            }
            vdpa = Some(vdpa_config_list);
        }

        let mut vsock: Option<VsockConfig> = None;
        if let Some(vs) = &vm_params.vsock {
            let vsock_config = VsockConfig::parse(vs)?;
            vsock = Some(vsock_config);
        }

        let mut pci_segments: Option<Box<[PciSegmentConfig]>> = None;
        if let Some(pci_segment_list) = &vm_params.pci_segments {
            let mut pci_segment_config_list = Vec::new();
            for item in pci_segment_list.iter() {
                let pci_segment_config = PciSegmentConfig::parse(item)?;
                pci_segment_config_list.push(pci_segment_config);
            }
            pci_segments = Some(pci_segment_config_list.into_boxed_slice());
        }

        let platform = vm_params.platform.map(PlatformConfig::parse).transpose()?;

        let mut numa: Option<Box<[NumaConfig]>> = None;
        if let Some(numa_list) = &vm_params.numa {
            let mut numa_config_list = Vec::new();
            for item in numa_list.iter() {
                let numa_config = NumaConfig::parse(item)?;
                numa_config_list.push(numa_config);
            }
            numa = Some(numa_config_list.into_boxed_slice());
        }

        #[cfg(not(feature = "igvm"))]
        let payload_present = vm_params.kernel.is_some() || vm_params.firmware.is_some();

        #[cfg(feature = "igvm")]
        let payload_present =
            vm_params.kernel.is_some() || vm_params.firmware.is_some() || vm_params.igvm.is_some();

        let payload = if payload_present {
            Some(PayloadConfig {
                kernel: vm_params.kernel.map(PathBuf::from),
                initramfs: vm_params.initramfs.map(PathBuf::from),
                cmdline: vm_params.cmdline.map(|s| s.to_string()),
                firmware: vm_params.firmware.map(PathBuf::from),
                #[cfg(feature = "igvm")]
                igvm: vm_params.igvm.map(PathBuf::from),
                #[cfg(feature = "sev_snp")]
                host_data: vm_params.host_data.map(|s| s.to_string()),
                #[cfg(feature = "fw_cfg")]
                fw_cfg_config,
            })
        } else {
            None
        };

        let mut tpm: Option<TpmConfig> = None;
        if let Some(tc) = vm_params.tpm {
            let tpm_conf = TpmConfig::parse(tc)?;
            tpm = Some(TpmConfig {
                socket: tpm_conf.socket,
            });
        }

        #[cfg(feature = "guest_debug")]
        let gdb = vm_params.gdb;

        let mut landlock_rules: Option<Box<[LandlockConfig]>> = None;
        if let Some(ll_rules) = vm_params.landlock_rules {
            landlock_rules = Some(
                ll_rules
                    .iter()
                    .map(|rule| LandlockConfig::parse(rule))
                    .collect::<Result<Vec<LandlockConfig>, LandlockConfigParseError>>()?
                    .into_boxed_slice(),
            );
        }

        #[cfg(feature = "ivshmem")]
        let mut ivshmem: Option<IvshmemConfig> = None;
        #[cfg(feature = "ivshmem")]
        if let Some(iv) = vm_params.ivshmem {
            let ivshmem_conf = IvshmemConfig::parse(iv)?;
            ivshmem = Some(ivshmem_conf);
        }

        Ok(VmConfig {
            cpus: CpusConfig::parse(vm_params.cpus)?,
            memory: MemoryConfig::parse(vm_params.memory, vm_params.memory_zones)?,
            payload,
            rate_limit_groups,
            disks,
            net,
            rng,
            balloon,
            generic_vhost_user,
            fs,
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
            pvpanic: vm_params.pvpanic,
            iommu: false, // updated in VmConfig::validate()
            numa,
            watchdog: vm_params.watchdog,
            rtc,
            #[cfg(feature = "guest_debug")]
            gdb,
            pci_segments,
            platform,
            tpm,
            landlock_enable: vm_params.landlock_enable,
            landlock_rules,
            #[cfg(feature = "ivshmem")]
            ivshmem,
        })
    }
}
