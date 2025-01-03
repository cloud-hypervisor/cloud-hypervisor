use std::net::Ipv4Addr;
use std::str::FromStr;
use std::path::PathBuf;
use net_util::MacAddr;
use serde::{Deserialize, Serialize};
use shared::interface_config::InterfaceConfig;
use crate::error::VmmError;
use crate::Distro;
use crate::CloudInit;
use form_types::VmmEvent;
use rand::{thread_rng, Rng};
use gabble::Gab;
use crate::util::copy_distro_base;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInstanceConfig {
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub tap_device: String,
    pub ip_addr: String,
    pub cloud_init_path: Option<PathBuf>,
    pub memory_mb: u64,
    pub vcpu_count: u8,
    pub name: String,
    pub custom_cmdline: Option<String>,
    pub rng_source: Option<String>,
    pub console_type: ConsoleType,
}

impl Default for VmInstanceConfig {
    fn default() -> Self {
        let mut rng = thread_rng();
        let name: Gab = rng.gen();
        Self {
            kernel_path: PathBuf::from("/var/lib/formation/kernel/hypervisor-fw"),
            rootfs_path: PathBuf::from("/var/lib/formation/vm-images/ubuntu/22.04/default/disk.raw"),
            tap_device: "vnet0".to_string(),
            ip_addr: "10.99.0.44".to_string(),
            cloud_init_path: None,
            memory_mb: 1024,
            vcpu_count: 2,
            name: name.to_string(),
            custom_cmdline: None,
            rng_source: None,
            console_type: ConsoleType::Virtio,
        }
    }
}

impl VmInstanceConfig {
    pub const CLOUD_INIT_BASE: &str = "/var/lib/formation/vm-images/default/cloud_init";

    pub fn validate(&self) -> Result<(), VmmError> {
        // Validate paths exist
        if !self.kernel_path.exists() {
            return Err(VmmError::InvalidPath(
                format!("Kernel path does not exist: {:?}", self.kernel_path)
            ));
        }
        if !self.rootfs_path.exists() {
            return Err(VmmError::InvalidPath(
                format!("Rootfs path does not exist: {:?}", self.rootfs_path)
            ));
        }

        // Validate memory and CPU configuration
        if self.memory_mb < 128 {
            return Err(VmmError::Config("Memory must be at least 128MB".into()));
        }
        if self.vcpu_count == 0 {
            return Err(VmmError::Config("Must have at least 1 vCPU".into()));
        }

        Ok(())
    }

    pub fn generate_cmdline(&self) -> String {
        self.custom_cmdline.clone().unwrap_or_else(|| {
            match self.console_type {
                ConsoleType::Serial => {
                    "console=ttyS0,115200n8 earlyprintk=serial,tty0,115200 console=tty0 root=/dev/vdb1 rw virtio_pci.disable_legacy=0"
                },
                ConsoleType::Virtio => {
                    "console=hvc0 root=/dev/vdb1 rw virtio_pci.disable_legacy=0"
                },
            }.to_string()
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConsoleType {
    Virtio,
    Serial
}

impl FromStr for ConsoleType {
    type Err = VmmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "virtio" => Ok(Self::Virtio),
            "serial" => Ok(Self::Serial),
            _ => {
                Err(
                    VmmError::Config(
                        format!("ConsoleType {s} not a valid console type for Formation VPS instances")
                    )
                )
            }
        }
    }
}

impl TryFrom<(&VmmEvent, &InterfaceConfig)> for VmInstanceConfig {
    type Error = VmmError;
    fn try_from(event: (&VmmEvent, &InterfaceConfig)) -> Result<Self, Self::Error> {
        match &event.0 {
            VmmEvent::Create { 
                owner,
                recovery_id: _,
                requestor: _,
                distro,
                version,
                user_data,
                meta_data,
                memory_mb,
                vcpu_count,
                name,
                custom_cmdline,
                rng_source,
                console_type 
            } => { 

                let distro = Distro::from_str(distro).map_err(|e| {
                    VmmError::Config(e.to_string())
                })?;

                let rootfs_path = copy_distro_base(distro.clone(), version, name).map_err(|e| {
                    VmmError::Config(
                        format!("unable to create instance disk image for instance {}: {e}", name)
                    )
                })?;

                let console_type = if let Some(ct) = console_type {
                    ConsoleType::from_str(ct)?
                } else {
                    ConsoleType::Virtio
                };

                let cloud_init = CloudInit::from_base64(
                    distro,
                    user_data.as_deref(),
                    meta_data.as_deref(), 
                    event.1.clone(),
                ).map_err(|e| {
                    VmmError::Config(e.to_string())
                })?;

                let output_path = PathBuf::from(
                    Self::CLOUD_INIT_BASE
                ).join(owner).join(name);

                cloud_init.create_image(&output_path).map_err(|e| {
                    VmmError::Config(e.to_string())
                })?;

                Ok(VmInstanceConfig {
                    rootfs_path: rootfs_path.into(),
                    memory_mb: *memory_mb,
                    vcpu_count: *vcpu_count,
                    cloud_init_path: Some(output_path.to_path_buf()),
                    name: name.clone(),
                    custom_cmdline: custom_cmdline.clone(),
                    rng_source: rng_source.clone(),
                    console_type,
                    ..Default::default()
                })
            },
            _ => {
                return Err(
                    VmmError::Config(
                        format!("VmmEvent type: {event:?} cannot be converted into VmInstanceConfig")
                    )
                )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub ip: Option<Ipv4Addr>,
    pub mac_addr: Option<MacAddr>,
    pub mtu: Option<u16>,
    pub tap_name: Option<String>,
    pub offload_tso: bool,
    pub offload_ufo: bool,
    pub offload_csum: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ip: None,  // Will be assigned by DHCP
            mac_addr: None,  // Will be generated if not provided
            mtu: Some(1500),
            tap_name: None,
            offload_tso: true,
            offload_ufo: true,
            offload_csum: true,
        }
    }
}
