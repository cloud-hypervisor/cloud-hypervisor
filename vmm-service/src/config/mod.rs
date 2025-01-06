pub mod wizard;
use net_util::MacAddr;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::io::{Read, Write};
use crate::VmmError;

use super::{VmInstanceConfig, ConsoleType}; 
use vmm::vm_config::{
    ConsoleConfig,
    ConsoleOutputMode,
    CpuFeatures, 
    CpusConfig, 
    DiskConfig, 
    MemoryConfig, 
    NetConfig, 
    PayloadConfig, 
    RngConfig, 
    VhostMode, 
    VmConfig
};

pub fn create_vm_config(config: &VmInstanceConfig) -> VmConfig {

    // Add cloud-init disk if provided
    let mut disks = vec![DiskConfig {
        // This needs to be a copied disk, raw cannot use backing file
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

    disks.push(DiskConfig {
        path: config.cloud_init_path.clone(),
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
                mode: ConsoleOutputMode::Null,
                iommu: false,
                socket: None
            }
        ),
        ConsoleType::Virtio => (
            ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Tty,
                iommu: false,
                socket: None,
            },
            ConsoleConfig {
                file: None,
                mode: ConsoleOutputMode::Null,
                iommu: false,
                socket: None,
            },
        ),
    };

    let net = Some(vec![NetConfig {
        tap: Some(config.tap_device.to_string()),
        ip: config.ip_addr.parse().unwrap(),  // Use our bridge IP as gateway
        mask: "255.255.255.0".parse().unwrap(),
        mac: MacAddr::local_random(),  // Default MAC, can be configured
        host_mac: None,
        mtu: Some(1500),
        iommu: false,
        num_queues: 2,
        queue_size: 256,
        vhost_user: false,
        vhost_socket: None,
        vhost_mode: VhostMode::Client,
        id: Some(format!("net_{}", config.name)),
        fds: None,
        rate_limiter_config: None,
        pci_segment: 0,
        offload_tso: true,
        offload_ufo: true,
        offload_csum: true,
    }]);
    
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
            cmdline: None,
            firmware: None,
        }),
        disks: Some(disks),
        net,
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

impl ServiceConfig {
    /// Loads a ServiceConfig from a file. This method reads a TOML, YAML or
    /// JSON configuration file and deserializes it into a ServiceConfig instance.
    ///
    /// # Arguments
    /// * `path` - the path to the config file
    ///
    /// # Returns
    /// * `Result<ServiceConfig, VmmError>` - the loaded configuration or an error
    ///
    /// # Example
    /// ```rust
    /// let config = ServiceConfig::from_file("/etc/vmm/config.toml")?;
    /// ```
    pub fn from_file(path: &str) -> Result<Self, VmmError> {
        // Open the configuration file
        let mut file = std::fs::File::open(path).map_err(|e| {
            VmmError::Config(format!("Failed to open config file `{path}`: {e}"))
        })?;

        // Read the file contents into a string
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            VmmError::Config(format!("Failed to read config file `{path}`: {e}"))
        })?;

        toml::from_str(&contents).map_err(|e| {
            VmmError::Config(format!("failed to parse config file `{path}`: {e}"))
        })

    }

    /// Saves the current `ServiceConfig` to a file in TOML format. This method handles 
    /// serialization serialization of the config and ensures the file is written
    /// atomically by writing to a temporary file first then renaming it.
    ///
    /// # Arguments
    /// * `path` - The path where the configuration should be saved
    ///
    /// # Returns
    /// * `Result<(), VmmError>` - Success or an error
    ///
    /// # Example
    /// ```rust
    /// config.save_to_file("/tec/vmm/config.toml")?;
    /// ```
    pub fn save_to_file(&self, path: &str) -> Result<(), VmmError> {
        // Serialize to TOML
        let toml_content = toml::to_string_pretty(self).map_err(|e| {
            VmmError::Config(format!("Failed to serialize config: {}", e))
        })?;

        // Create a temporary file in the same directory
        let path = PathBuf::from(path);
        let parent = path.parent().ok_or_else(|| {
            VmmError::Config("Invalid config file path".to_string())
        })?;

        let mut temp_file = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
            VmmError::Config(format!("Failed to create temporary file: {e}"))
        })?;

        // Write the configuration to a temporary file
        temp_file.write_all(toml_content.as_bytes()).map_err(|e| {
            VmmError::Config(format!("Failed to write config: {e}"))
        })?;

        // Persist the file by moving it to the target location
        temp_file.persist(&path).map_err(|e| {
            VmmError::Config(format!("Failed to save config file `{path:?}`: {e}"))
        })?;

        Ok(())
    }
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
    /// Domain suffix
    pub domain_suffix: String,
    /// DNS listen addr
    pub dns_listener_addr: String,
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
            dns_listener_addr: "0.0.0.0:53".to_string(),
            domain_suffix: "dev.formation.cloud".to_string() 
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
