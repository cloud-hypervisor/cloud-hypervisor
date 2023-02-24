// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use net_util::MacAddr;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, path::PathBuf};
use virtio_devices::RateLimiterConfig;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuAffinity {
    pub vcpu: u8,
    pub host_cpus: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuFeatures {
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub amx: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuTopology {
    pub threads_per_core: u8,
    pub cores_per_die: u8,
    pub dies_per_package: u8,
    pub packages: u8,
}

// When booting with PVH boot the maximum physical addressable size
// is a 46 bit address space even when the host supports with 5-level
// paging.
pub const DEFAULT_MAX_PHYS_BITS: u8 = 46;

pub fn default_cpuconfig_max_phys_bits() -> u8 {
    DEFAULT_MAX_PHYS_BITS
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpusConfig {
    pub boot_vcpus: u8,
    pub max_vcpus: u8,
    #[serde(default)]
    pub topology: Option<CpuTopology>,
    #[serde(default)]
    pub kvm_hyperv: bool,
    #[serde(default = "default_cpuconfig_max_phys_bits")]
    pub max_phys_bits: u8,
    #[serde(default)]
    pub affinity: Option<Vec<CpuAffinity>>,
    #[serde(default)]
    pub features: CpuFeatures,
}

pub const DEFAULT_VCPUS: u8 = 1;

impl Default for CpusConfig {
    fn default() -> Self {
        CpusConfig {
            boot_vcpus: DEFAULT_VCPUS,
            max_vcpus: DEFAULT_VCPUS,
            topology: None,
            kvm_hyperv: false,
            max_phys_bits: DEFAULT_MAX_PHYS_BITS,
            affinity: None,
            features: CpuFeatures::default(),
        }
    }
}

pub const DEFAULT_NUM_PCI_SEGMENTS: u16 = 1;
pub fn default_platformconfig_num_pci_segments() -> u16 {
    DEFAULT_NUM_PCI_SEGMENTS
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PlatformConfig {
    #[serde(default = "default_platformconfig_num_pci_segments")]
    pub num_pci_segments: u16,
    #[serde(default)]
    pub iommu_segments: Option<Vec<u16>>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub oem_strings: Option<Vec<String>>,
    #[cfg(feature = "tdx")]
    #[serde(default)]
    pub tdx: bool,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            num_pci_segments: DEFAULT_NUM_PCI_SEGMENTS,
            iommu_segments: None,
            serial_number: None,
            uuid: None,
            oem_strings: None,
            #[cfg(feature = "tdx")]
            tdx: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MemoryZoneConfig {
    pub id: String,
    pub size: u64,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub host_numa_node: Option<u32>,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum HotplugMethod {
    #[default]
    Acpi,
    VirtioMem,
}

fn default_memoryconfig_thp() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MemoryConfig {
    pub size: u64,
    #[serde(default)]
    pub mergeable: bool,
    #[serde(default)]
    pub hotplug_method: HotplugMethod,
    #[serde(default)]
    pub hotplug_size: Option<u64>,
    #[serde(default)]
    pub hotplugged_size: Option<u64>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub hugepage_size: Option<u64>,
    #[serde(default)]
    pub prefault: bool,
    #[serde(default)]
    pub zones: Option<Vec<MemoryZoneConfig>>,
    #[serde(default = "default_memoryconfig_thp")]
    pub thp: bool,
}

pub const DEFAULT_MEMORY_MB: u64 = 512;

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            size: DEFAULT_MEMORY_MB << 20,
            mergeable: false,
            hotplug_method: HotplugMethod::Acpi,
            hotplug_size: None,
            hotplugged_size: None,
            shared: false,
            hugepages: false,
            hugepage_size: None,
            prefault: false,
            zones: None,
            thp: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub enum VhostMode {
    #[default]
    Client,
    Server,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DiskConfig {
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_diskconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_diskconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default)]
    pub id: Option<String>,
    // For testing use only. Not exposed in API.
    #[serde(default)]
    pub disable_io_uring: bool,
    #[serde(default)]
    pub pci_segment: u16,
}

pub const DEFAULT_DISK_NUM_QUEUES: usize = 1;

pub fn default_diskconfig_num_queues() -> usize {
    DEFAULT_DISK_NUM_QUEUES
}

pub const DEFAULT_DISK_QUEUE_SIZE: u16 = 128;

pub fn default_diskconfig_queue_size() -> u16 {
    DEFAULT_DISK_QUEUE_SIZE
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            path: None,
            readonly: false,
            direct: false,
            iommu: false,
            num_queues: default_diskconfig_num_queues(),
            queue_size: default_diskconfig_queue_size(),
            vhost_user: false,
            vhost_socket: None,
            id: None,
            disable_io_uring: false,
            rate_limiter_config: None,
            pci_segment: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NetConfig {
    #[serde(default = "default_netconfig_tap")]
    pub tap: Option<String>,
    #[serde(default = "default_netconfig_ip")]
    pub ip: Ipv4Addr,
    #[serde(default = "default_netconfig_mask")]
    pub mask: Ipv4Addr,
    #[serde(default = "default_netconfig_mac")]
    pub mac: MacAddr,
    #[serde(default)]
    pub host_mac: Option<MacAddr>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default = "default_netconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_netconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub vhost_user: bool,
    pub vhost_socket: Option<String>,
    #[serde(default)]
    pub vhost_mode: VhostMode,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub fds: Option<Vec<i32>>,
    #[serde(default)]
    pub rate_limiter_config: Option<RateLimiterConfig>,
    #[serde(default)]
    pub pci_segment: u16,
    #[serde(default = "default_netconfig_true")]
    pub offload_tso: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_ufo: bool,
    #[serde(default = "default_netconfig_true")]
    pub offload_csum: bool,
}

pub fn default_netconfig_true() -> bool {
    true
}

pub fn default_netconfig_tap() -> Option<String> {
    None
}

pub fn default_netconfig_ip() -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 249, 1)
}

pub fn default_netconfig_mask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}

pub fn default_netconfig_mac() -> MacAddr {
    MacAddr::local_random()
}

pub const DEFAULT_NET_NUM_QUEUES: usize = 2;

pub fn default_netconfig_num_queues() -> usize {
    DEFAULT_NET_NUM_QUEUES
}

pub const DEFAULT_NET_QUEUE_SIZE: u16 = 256;

pub fn default_netconfig_queue_size() -> u16 {
    DEFAULT_NET_QUEUE_SIZE
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            tap: default_netconfig_tap(),
            ip: default_netconfig_ip(),
            mask: default_netconfig_mask(),
            mac: default_netconfig_mac(),
            host_mac: None,
            mtu: None,
            iommu: false,
            num_queues: default_netconfig_num_queues(),
            queue_size: default_netconfig_queue_size(),
            vhost_user: false,
            vhost_socket: None,
            vhost_mode: VhostMode::Client,
            id: None,
            fds: None,
            rate_limiter_config: None,
            pci_segment: 0,
            offload_tso: true,
            offload_ufo: true,
            offload_csum: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RngConfig {
    pub src: PathBuf,
    #[serde(default)]
    pub iommu: bool,
}

pub const DEFAULT_RNG_SOURCE: &str = "/dev/urandom";

impl Default for RngConfig {
    fn default() -> Self {
        RngConfig {
            src: PathBuf::from(DEFAULT_RNG_SOURCE),
            iommu: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BalloonConfig {
    pub size: u64,
    /// Option to deflate the balloon in case the guest is out of memory.
    #[serde(default)]
    pub deflate_on_oom: bool,
    /// Option to enable free page reporting from the guest.
    #[serde(default)]
    pub free_page_reporting: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FsConfig {
    pub tag: String,
    pub socket: PathBuf,
    #[serde(default = "default_fsconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default = "default_fsconfig_queue_size")]
    pub queue_size: u16,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

pub fn default_fsconfig_num_queues() -> usize {
    1
}

pub fn default_fsconfig_queue_size() -> u16 {
    1024
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            tag: "".to_owned(),
            socket: PathBuf::new(),
            num_queues: default_fsconfig_num_queues(),
            queue_size: default_fsconfig_queue_size(),
            id: None,
            pci_segment: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct PmemConfig {
    pub file: PathBuf,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub discard_writes: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ConsoleOutputMode {
    Off,
    Pty,
    Tty,
    File,
    Null,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ConsoleConfig {
    #[serde(default = "default_consoleconfig_file")]
    pub file: Option<PathBuf>,
    pub mode: ConsoleOutputMode,
    #[serde(default)]
    pub iommu: bool,
}

pub fn default_consoleconfig_file() -> Option<PathBuf> {
    None
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct DeviceConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct UserDeviceConfig {
    pub socket: PathBuf,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct VdpaConfig {
    pub path: PathBuf,
    #[serde(default = "default_vdpaconfig_num_queues")]
    pub num_queues: usize,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

pub fn default_vdpaconfig_num_queues() -> usize {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct VsockConfig {
    pub cid: u64,
    pub socket: PathBuf,
    #[serde(default)]
    pub iommu: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub pci_segment: u16,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct SgxEpcConfig {
    pub id: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub prefault: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct NumaDistance {
    #[serde(default)]
    pub destination: u32,
    #[serde(default)]
    pub distance: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct NumaConfig {
    #[serde(default)]
    pub guest_numa_id: u32,
    #[serde(default)]
    pub cpus: Option<Vec<u8>>,
    #[serde(default)]
    pub distances: Option<Vec<NumaDistance>>,
    #[serde(default)]
    pub memory_zones: Option<Vec<String>>,
    #[cfg(target_arch = "x86_64")]
    #[serde(default)]
    pub sgx_epc_sections: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayloadConfig {
    #[serde(default)]
    pub firmware: Option<PathBuf>,
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    #[serde(default)]
    pub cmdline: Option<String>,
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
}

pub fn default_serial() -> ConsoleConfig {
    ConsoleConfig {
        file: None,
        mode: ConsoleOutputMode::Null,
        iommu: false,
    }
}

pub fn default_console() -> ConsoleConfig {
    ConsoleConfig {
        file: None,
        mode: ConsoleOutputMode::Tty,
        iommu: false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct TpmConfig {
    pub socket: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VmConfig {
    #[serde(default)]
    pub cpus: CpusConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    pub payload: Option<PayloadConfig>,
    pub disks: Option<Vec<DiskConfig>>,
    pub net: Option<Vec<NetConfig>>,
    #[serde(default)]
    pub rng: RngConfig,
    pub balloon: Option<BalloonConfig>,
    pub fs: Option<Vec<FsConfig>>,
    pub pmem: Option<Vec<PmemConfig>>,
    #[serde(default = "default_serial")]
    pub serial: ConsoleConfig,
    #[serde(default = "default_console")]
    pub console: ConsoleConfig,
    pub devices: Option<Vec<DeviceConfig>>,
    pub user_devices: Option<Vec<UserDeviceConfig>>,
    pub vdpa: Option<Vec<VdpaConfig>>,
    pub vsock: Option<VsockConfig>,
    #[serde(default)]
    pub iommu: bool,
    #[cfg(target_arch = "x86_64")]
    pub sgx_epc: Option<Vec<SgxEpcConfig>>,
    pub numa: Option<Vec<NumaConfig>>,
    #[serde(default)]
    pub watchdog: bool,
    #[cfg(feature = "guest_debug")]
    pub gdb: bool,
    pub platform: Option<PlatformConfig>,
    pub tpm: Option<TpmConfig>,
}

#[cfg(test)]
mod tests {
    use std::{fs::File, os::fd::AsRawFd};

    use super::*;
    use net_util::MacAddr;
    use serde_json::Result;

    #[test]
    fn test_cpu_deserializing() -> Result<()> {
        assert_eq!(
            serde_json::from_str::<CpusConfig>(r#"{"boot_vcpus": 1, "max_vcpus": 2}"#)?,
            CpusConfig {
                boot_vcpus: 1,
                max_vcpus: 2,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<CpusConfig>(
                r#"
                {
                    "boot_vcpus": 8,
                    "max_vcpus": 8,
                    "topology": {
                        "threads_per_core": 2,
                        "cores_per_die": 2,
                        "dies_per_package": 1,
                        "packages": 2
                    }
                }
                "#
            )?,
            CpusConfig {
                boot_vcpus: 8,
                max_vcpus: 8,
                topology: Some(CpuTopology {
                    threads_per_core: 2,
                    cores_per_die: 2,
                    dies_per_package: 1,
                    packages: 2
                }),
                ..Default::default()
            }
        );

        assert!(serde_json::from_str::<CpusConfig>(
            r#"
                {
                    "boot_vcpus": 8,
                    "max_vcpus": 8,
                    "topology": {
                        "threads_per_core": 2,
                        "cores_per_die": 2,
                        "dies_per_package": 1
                    }
                }
                "#
        )
        .is_err());

        assert!(serde_json::from_str::<CpusConfig>(
            r#"
                {
                    "boot_vcpus": 8,
                    "max_vcpus": 8,
                    "topology": {
                        "threads_per_core": 2,
                        "cores_per_die": 2,
                        "dies_per_package": 1
                        "packages": "x"
                    }
                }
                "#
        )
        .is_err());

        assert_eq!(
            serde_json::from_str::<CpusConfig>(
                r#"
                {
                    "boot_vcpus": 8,
                    "max_vcpus": 8,
                    "kvm_hyperv": true
                }
                "#
            )?,
            CpusConfig {
                boot_vcpus: 8,
                max_vcpus: 8,
                kvm_hyperv: true,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<CpusConfig>(
                r#"
                {
                    "boot_vcpus": 2,
                    "max_vcpus": 2,
                    "affinity": [
                        {"vcpu": 0, "host_cpus": [0, 2]},
                        {"vcpu": 1, "host_cpus": [1, 3]}
                    ]
                }
                "#
            )?,
            CpusConfig {
                boot_vcpus: 2,
                max_vcpus: 2,
                affinity: Some(vec![
                    CpuAffinity {
                        vcpu: 0,
                        host_cpus: vec![0, 2],
                    },
                    CpuAffinity {
                        vcpu: 1,
                        host_cpus: vec![1, 3],
                    }
                ]),
                ..Default::default()
            },
        );

        Ok(())
    }

    #[test]
    fn test_mem_deserializing() -> Result<()> {
        // Default string
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(r#"{"size": 536870912}"#)?,
            MemoryConfig::default()
        );
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(
                r#"
                {
                    "size": 536870912,
                    "mergeable": true
                }
                "#
            )?,
            MemoryConfig {
                size: 512 << 20,
                mergeable: true,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(
                r#"
                {
                    "size": 1073741824,
                    "mergeable": false
                }
                "#
            )?,
            MemoryConfig {
                size: 1 << 30,
                mergeable: false,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(
                r#"
                {
                    "size": 536870912,
                    "hotplug_method": "Acpi"
                }
                "#
            )?,
            MemoryConfig {
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(
                r#"
                {
                    "size": 536870912,
                    "hotplug_method": "Acpi",
                    "hotplug_size": 536870912
                }
                "#
            )?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(
                r#"
                {
                    "size": 536870912,
                    "hotplug_method": "VirtioMem",
                    "hotplug_size": 536870912
                }
                "#
            )?,
            MemoryConfig {
                hotplug_size: Some(512 << 20),
                hotplug_method: HotplugMethod::VirtioMem,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<MemoryConfig>(
                r#"
                {
                    "size": 1073741824,
                    "hugepages": true,
                    "hugepage_size": 2097152
                }
                "#
            )?,
            MemoryConfig {
                hugepage_size: Some(2 << 20),
                size: 1 << 30,
                hugepages: true,
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_disk_deserializing() -> Result<()> {
        assert_eq!(
            serde_json::from_str::<DiskConfig>(r#"{"path": "/path/to_file"}"#)?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<DiskConfig>(
                r#"
                {
                    "path": "/path/to_file",
                    "id": "mydisk0"
                }
                "#
            )?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                id: Some("mydisk0".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<DiskConfig>(
                r#"
                {
                    "vhost_user": true,
                    "vhost_socket": "/tmp/sock"
                }
                "#
            )?,
            DiskConfig {
                vhost_socket: Some(String::from("/tmp/sock")),
                vhost_user: true,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<DiskConfig>(
                r#"
                {
                    "path": "/path/to_file",
                    "iommu": true
                }
                "#
            )?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<DiskConfig>(
                r#"
                {
                    "path": "/path/to_file",
                    "iommu": true,
                    "queue_size": 256
                }
                "#
            )?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                queue_size: 256,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<DiskConfig>(
                r#"
                {
                    "path": "/path/to_file",
                    "iommu": true,
                    "queue_size": 256,
                    "num_queues": 4
                }
                "#
            )?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                iommu: true,
                queue_size: 256,
                num_queues: 4,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<DiskConfig>(
                r#"
                {
                    "path": "/path/to_file",
                    "direct": true
                }
                "#
            )?,
            DiskConfig {
                path: Some(PathBuf::from("/path/to_file")),
                direct: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_net_deserializing() -> Result<()> {
        // mac address is random
        assert_eq!(
            serde_json::from_str::<NetConfig>(
                r#"
                {
                    "mac": "de:ad:be:ef:12:34",
                    "host_mac": "12:34:de:ad:be:ef"
                }
                "#
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                id: None,
                fds: None,
                tap: None,
                vhost_socket: None,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<NetConfig>(
                r#"
                {
                    "mac": "de:ad:be:ef:12:34",
                    "host_mac": "12:34:de:ad:be:ef",
                    "id": "mynet0"
                }
                "#
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                id: Some("mynet0".to_owned()),
                fds: None,
                tap: None,
                vhost_socket: None,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<NetConfig>(
                r#"
                {
                    "mac": "de:ad:be:ef:12:34",
                    "host_mac": "12:34:de:ad:be:ef",
                    "tap": "tap0",
                    "ip": "192.168.100.1",
                    "mask": "255.255.255.128"
                }
                "#
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                tap: Some("tap0".to_owned()),
                ip: "192.168.100.1".parse().unwrap(),
                mask: "255.255.255.128".parse().unwrap(),
                fds: None,
                id: None,
                vhost_socket: None,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<NetConfig>(
                r#"
                {
                    "mac": "de:ad:be:ef:12:34",
                    "host_mac": "12:34:de:ad:be:ef",
                    "vhost_user": true,
                    "vhost_socket": "/tmp/sock"
                }
                "#
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                vhost_user: true,
                vhost_socket: Some("/tmp/sock".to_owned()),
                fds: None,
                id: None,
                tap: None,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<NetConfig>(
                r#"
                {
                    "mac": "de:ad:be:ef:12:34",
                    "host_mac": "12:34:de:ad:be:ef",
                    "num_queues": 4,
                    "queue_size": 1024,
                    "iommu": true
                }
                "#
            )?,
            NetConfig {
                mac: MacAddr::parse_str("de:ad:be:ef:12:34").unwrap(),
                host_mac: Some(MacAddr::parse_str("12:34:de:ad:be:ef").unwrap()),
                num_queues: 4,
                queue_size: 1024,
                iommu: true,
                fds: None,
                id: None,
                tap: None,
                vhost_socket: None,
                ..Default::default()
            }
        );

        // SAFETY: Safe as the file was just opened
        let fd1 = unsafe { libc::dup(File::open("/dev/null").unwrap().as_raw_fd()) };
        // SAFETY: Safe as the file was just opened
        let fd2 = unsafe { libc::dup(File::open("/dev/null").unwrap().as_raw_fd()) };

        assert_eq!(
            &format!(
                "{:?}",
                serde_json::from_str::<NetConfig>(
                    &format!(r#"
                    {{
                        "mac": "de:ad:be:ef:12:34",
                        "fds": [{fd1}, {fd2}],
                        "num_queues": 4
                    }}
                    "#)
                )?,
            ),
            &format!("NetConfig {{ tap: None, ip: 192.168.249.1, mask: 255.255.255.0, \
                mac: MacAddr {{ bytes: [222, 173, 190, 239, 18, 52] }}, host_mac: None, mtu: None, \
                iommu: false, num_queues: 4, queue_size: 256, vhost_user: false, vhost_socket: None, \
                vhost_mode: Client, id: None, fds: Some([{fd1}, {fd2}]), \
                rate_limiter_config: None, pci_segment: 0, offload_tso: true, offload_ufo: true, offload_csum: true }}")
        );

        Ok(())
    }

    #[test]
    fn test_rng_deserializing() -> Result<()> {
        assert_eq!(
            serde_json::from_str::<RngConfig>(
                r#"{"src": "/dev/random"}"#
            )?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<RngConfig>(
                r#"
                {
                    "src": "/dev/random",
                    "iommu": true
                }
                "#
            )?,
            RngConfig {
                src: PathBuf::from("/dev/random"),
                iommu: true,
            }
        );
        Ok(())
    }

    #[test]
    fn test_fs_deserializing() -> Result<()> {
        // "tag" and "socket" must be supplied
        assert!(serde_json::from_str::<FsConfig>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<FsConfig>(r#"{"tag": "mytag"}"#).is_err());
        assert!(serde_json::from_str::<FsConfig>(r#"{"socket": "/tmp/sock"}"#).is_err());
        assert_eq!(
            serde_json::from_str::<FsConfig>(
                r#"
                {
                    "tag": "mytag",
                    "socket": "/tmp/sock"
                }
                "#
            )?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<FsConfig>(
                r#"
                {
                    "tag": "mytag",
                    "socket": "/tmp/sock",
                    "num_queues": 4,
                    "queue_size": 1024
                }
                "#
            )?,
            FsConfig {
                socket: PathBuf::from("/tmp/sock"),
                tag: "mytag".to_owned(),
                num_queues: 4,
                queue_size: 1024,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_pmem_deserializing() -> Result<()> {
        // Must always give a file and size
        assert!(serde_json::from_str::<PmemConfig>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<PmemConfig>(r#"{"size": 134217728}"#).is_err());
        assert_eq!(
            serde_json::from_str::<PmemConfig>(
                r#"
                {
                    "file": "/tmp/pmem",
                    "size": 134217728
                }
                "#
            )?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<PmemConfig>(
                r#"
                {
                    "file": "/tmp/pmem",
                    "size": 134217728,
                    "id": "mypmem0"
                }
                "#
            )?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                id: Some("mypmem0".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<PmemConfig>(
                r#"
                {
                    "file": "/tmp/pmem",
                    "size": 134217728,
                    "iommu": true,
                    "discard_writes": true
                }
                "#
            )?,
            PmemConfig {
                file: PathBuf::from("/tmp/pmem"),
                size: Some(128 << 20),
                discard_writes: true,
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_console_deserializing() -> Result<()> {
        assert!(serde_json::from_str::<ConsoleConfig>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<ConsoleConfig>(r#"{"mode": "badmode"}"#).is_err());
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(r#"{"mode": "Off"}"#)?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Off,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(r#"{"mode": "Pty"}"#)?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Pty,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(r#"{"mode": "Tty"}"#)?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(r#"{"mode": "Null"}"#)?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: false,
                file: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(
                r#"
                {
                    "mode": "File",
                    "file": "/tmp/console"
                }
                "#
            )?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: false,
                file: Some(PathBuf::from("/tmp/console"))
            }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(
                r#"
                {
                    "mode": "Null",
                    "iommu": true
                }
                "#
            )?,
            ConsoleConfig {
                mode: ConsoleOutputMode::Null,
                iommu: true,
                file: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleConfig>(
                r#"
                {
                    "mode": "File",
                    "file": "/tmp/console",
                    "iommu": true
                }
                "#
            )?,
            ConsoleConfig {
                mode: ConsoleOutputMode::File,
                iommu: true,
                file: Some(PathBuf::from("/tmp/console"))
            }
        );
        Ok(())
    }

    #[test]
    fn test_device_deserializing() -> Result<()> {
        // Device must have a path provided
        assert!(serde_json::from_str::<DeviceConfig>(r#"{}"#).is_err());
        assert_eq!(
            serde_json::from_str::<DeviceConfig>(r#"{"path": "/path/to/device"}"#)?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: false,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<DeviceConfig>(
                r#"
                {
                    "path": "/path/to/device",
                    "iommu": true
                }
                "#
            )?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: None,
                iommu: true,
                ..Default::default()
            }
        );

        assert_eq!(
            serde_json::from_str::<DeviceConfig>(
                r#"
                {
                    "path": "/path/to/device",
                    "iommu": true,
                    "id": "mydevice0"
                }
                "#
            )?,
            DeviceConfig {
                path: PathBuf::from("/path/to/device"),
                id: Some("mydevice0".to_owned()),
                iommu: true,
                ..Default::default()
            }
        );

        Ok(())
    }

    #[test]
    fn test_vdpa_deserializing() -> Result<()> {
        // path is required
        assert!(serde_json::from_str::<VdpaConfig>(r#"{}"#).is_err());
        assert_eq!(
            serde_json::from_str::<VdpaConfig>(r#"{"path": "/dev/vhost-vdpa"}"#)?,
            VdpaConfig {
                path: PathBuf::from("/dev/vhost-vdpa"),
                num_queues: 1,
                id: None,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<VdpaConfig>(
                r#"
                {
                    "path": "/dev/vhost-vdpa",
                    "num_queues": 2,
                    "id": "my_vdpa"
                }
                "#
            )?,
            VdpaConfig {
                path: PathBuf::from("/dev/vhost-vdpa"),
                num_queues: 2,
                id: Some("my_vdpa".to_owned()),
                ..Default::default()
            }
        );
        Ok(())
    }

    #[test]
    fn test_tpm_deserializing() -> Result<()> {
        // path is required
        assert!(serde_json::from_str::<TpmConfig>(r#"{}"#).is_err());
        assert_eq!(
            serde_json::from_str::<TpmConfig>(r#"{"socket": "/var/run/tpm.sock"}"#)?,
            TpmConfig {
                socket: PathBuf::from("/var/run/tpm.sock"),
            }
        );
        Ok(())
    }

    #[test]
    fn test_vsock_deserializing() -> Result<()> {
        // socket and cid is required
        assert!(serde_json::from_str::<VsockConfig>(r#"{}"#).is_err());
        assert_eq!(
            serde_json::from_str::<VsockConfig>(
                r#"
                {
                    "socket": "/tmp/sock",
                    "cid": 1
                }
                "#
            )?,
            VsockConfig {
                cid: 1,
                socket: PathBuf::from("/tmp/sock"),
                iommu: false,
                id: None,
                ..Default::default()
            }
        );
        assert_eq!(
            serde_json::from_str::<VsockConfig>(
                r#"
                {
                    "socket": "/tmp/sock",
                    "cid": 1,
                    "iommu": true
                }
                "#
            )?,
            VsockConfig {
                cid: 1,
                socket: PathBuf::from("/tmp/sock"),
                iommu: true,
                id: None,
                ..Default::default()
            }
        );
        Ok(())
    }
}
