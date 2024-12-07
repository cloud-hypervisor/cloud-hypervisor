use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use super::{VmInstanceConfig, ConsoleType};  // Our config type
use vmm::vm_config::{
    CpusConfig, DiskConfig, MemoryConfig, PayloadConfig, VmConfig,
    ConsoleConfig, ConsoleOutputMode, CpuFeatures, RngConfig
};

pub fn create_vm_config(config: &VmInstanceConfig) -> VmConfig {

    // Add cloud-init disk if provided
    let mut disks = vec![DiskConfig {
        path: Some(config.rootfs_path.clone()),
        readonly: false,
        direct: true,
        vhost_user: false,
        vhost_socket: None,
        rate_limiter_config: None,
        queue_size: 256,
        num_queues: 1,
        queue_affinity: None,
        id: None,
        rate_limit_group: None,
        pci_segment: 0,
        iommu: false,
        serial: None,
        disable_io_uring: false,  // New field
        disable_aio: false,       // New field
    }];

    if let Some(cloud_init_path) = &config.cloud_init_path {
        disks.push(DiskConfig {
            path: Some(cloud_init_path.clone()),
            readonly: true,
            direct: true,
            vhost_user: false,
            vhost_socket: None,
            rate_limiter_config: None,
            queue_size: 256,
            num_queues: 1,
            queue_affinity: None,
            id: None,
            rate_limit_group: None,
            pci_segment: 0,
            iommu: false,
            serial: None,
            disable_io_uring: false,  // New field
            disable_aio: false,       // New field
        });
    }

    // Configure console based on type
    let (serial, console) = match config.console_type {
        ConsoleType::Serial => (
            ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                socket: None,
            },
            ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Off,
                iommu: false,
                socket: None,
            },
        ),
        ConsoleType::Virtio => (
            ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Off,
                iommu: false,
                socket: None,
            },
            ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                socket: None,
            },
        ),
    };
    
    VmConfig {
        cpus: CpusConfig {
            boot_vcpus: config.vcpu_count,
            max_vcpus: config.vcpu_count,
            topology: None,
            kvm_hyperv: false,
            max_phys_bits: 46,
            affinity: None,
            features: CpuFeatures {
                amx: false,
                ..CpuFeatures::default()
            },
        },
        memory: MemoryConfig {
            size: config.memory_mb * 1024 * 1024, // Convert MB to bytes
            mergeable: false,
            hotplug_method: vmm::vm_config::HotplugMethod::Acpi,
            hotplug_size: None,
            hotplugged_size: None,
            shared: false,
            hugepages: false,
            hugepage_size: None,
            prefault: false,
            zones: None,
            thp: true,
        },
        payload: Some(PayloadConfig {
            kernel: Some(config.kernel_path.clone()),
            initramfs: None,
            cmdline: Some(config.generate_cmdline()),
            firmware: None,
        }),
        disks: Some(vec![DiskConfig {
            path: Some(config.rootfs_path.clone()),
            readonly: false,
            direct: true,
            vhost_user: false,
            vhost_socket: None,
            rate_limiter_config: None,
            queue_size: 256,
            num_queues: 1,
            queue_affinity: None,
            id: None,
            rate_limit_group: None,
            pci_segment: 0,
            iommu: false,
            serial: None,
            disable_io_uring: false,  // New field
            disable_aio: false,       // New field
        }]),
        net: None,
        rng: RngConfig {
            src: config.rng_source.clone().unwrap_or_else(|| "/dev/urandom".to_string()).into(),
            iommu: false,
        },
        balloon: None,
        fs: None,
        pmem: None,
        serial,
        console,
        #[cfg(target_arch = "x86_64")]
        debug_console: vmm::vm_config::DebugConsoleConfig::default(),
        devices: None,
        user_devices: None,
        vdpa: None,
        vsock: None,
        pvpanic: false,
        #[cfg(feature = "pvmemcontrol")]
        pvmemcontrol: None,
        iommu: false,
        #[cfg(target_arch = "x86_64")]
        sgx_epc: None,
        numa: None,
        watchdog: false,
        #[cfg(feature = "guest_debug")]
        gdb: false,
        platform: None,
        tpm: None,
        preserved_fds: None,
        landlock_enable: false,
        landlock_rules: None,
        rate_limit_groups: None,     // New required field
        pci_segments: None,          // New required field
    }
}

/// Default paths for VMM Service
pub struct ServicePaths;

impl ServicePaths {
    /// Base path for all VMM service related files
    pub const BASE_DIR: &'static str = "/var/lib/form";
    /// Path for kernel image(s)
    pub const KERNEL_DIR: &'static str = "kernel"; 
    /// Path for base disk images
    pub const IMAGES_DIR: &'static str = "images";
    /// Path for cloud-init images
    pub const CLOUD_INIT_DIR: &'static str = "cloud-init"; 
    /// Path for working copies of disk images
    pub const WORKING_DIR: &'static str = "working";
}

/// Global configuration for the VMM service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Base directory for VM-related files
    pub base_dir: PathBuf,
    /// Directory structure for various VM components
    pub directories: DirectoryConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Resource limits
    pub limits: ResourceLimits,
    /// Default VM parameters
    pub default_vm_params: DefaultVmParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryConfig {
    /// Directory for kernel images
    pub kernel_dir: PathBuf,
    /// Directory for base OS images
    pub images_dir: PathBuf,
    /// Directory for CloudInit images
    pub cloud_init_dir: PathBuf,
    /// Directory for working copies of images
    pub working_dir: PathBuf
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Bridge interface name
    pub bridge_interface: String,
    /// DHCP range start
    pub dhcp_range_start: String,
    /// DHCP range end
    pub dhcp_range_end: String,
    /// Network Gateway
    pub gateway: String,
    /// Network mask
    pub netmask: String,
    /// DNS Servers
    pub nameservers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum number of concurrent VMs this host can handle
    pub max_vms: usize,
    /// Maximum memory per VM on this host in MB
    pub max_memory_per_vm: u64,
    /// Maximum vCPUs per VM on this host
    pub max_vcpus_per_vm: u8,
    /// Maximum Disk size per VM on this host in GB
    pub max_disk_size_per_vm: u64

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultVmParams {
    pub memory_mb: u64,
    pub vcpu_count: u8,
    pub disk_size_gb: u64,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        let base_dir = PathBuf::from(ServicePaths::BASE_DIR);
        Self {
            kernel_dir: base_dir.join(ServicePaths::KERNEL_DIR),
            images_dir: base_dir.join(ServicePaths::IMAGES_DIR),
            cloud_init_dir: base_dir.join(ServicePaths::CLOUD_INIT_DIR),
            working_dir: base_dir.join(ServicePaths::WORKING_DIR),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bridge_interface: "vmbr0".to_string(),
            dhcp_range_start: "192.168.122.2".to_string(),
            dhcp_range_end: "192.168.122.254".to_string(),
            gateway: "192.168.122.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            nameservers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_vms: 10,
            max_memory_per_vm: 32768, // 32GB
            max_vcpus_per_vm: 8,
            max_disk_size_per_vm: 1024, // 1TB
        }
    }
}

impl Default for DefaultVmParams {
    fn default() -> Self {
        Self {
            memory_mb: 2048,  // 2GB
            vcpu_count: 2,
            disk_size_gb: 20,
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from(ServicePaths::BASE_DIR),
            directories: DirectoryConfig::default(),
            network: NetworkConfig::default(),
            limits: ResourceLimits::default(),
            default_vm_params: DefaultVmParams::default(),
        }
    }
}
