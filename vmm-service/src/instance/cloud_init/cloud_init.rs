use std::fs;
use std::path::PathBuf; 
use std::process::Command;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use shared::interface_config::InterfaceConfig;
use tempfile::TempDir;
use crate::{
    UserData,
    MetaData,
    InitNetworkConfig,
    CloudInitError,
    NetworkConfigEntry,
    ChPasswd,
    User
};
use crate::Distro;

use super::runcmd::generate_default_runcmds;
use super::write_files::generate_invite_file;

pub struct CloudInit {
    temp_dir: TempDir,
    user_data: UserData,
    meta_data: MetaData,
}

impl CloudInit {
    /// Create a new CloudInit instance from base64 encoded configuration data
    pub fn from_base64(
        distro: Distro,
        user_data: Option<&str>,
        meta_data: Option<&str>,
        invitation: InterfaceConfig,
    ) -> Result<Self, CloudInitError> {
        // Decode and deserialize user data
        let mut user_data = if let Some(ud) = user_data {
            serde_yaml::from_slice(&BASE64.decode(ud)?)?
        } else {
            UserData::default_from_distro(distro.clone())
        };

        if let Some(ref mut runcmd) = user_data.run_cmd {
            runcmd.extend(generate_default_runcmds())
        } else {
            user_data.run_cmd = Some(generate_default_runcmds());
        }

        if let Some(ref mut write_files) = user_data.write_files {
            write_files.push(
                generate_invite_file(invitation).map_err(|e| {
                    CloudInitError::FileWrite(
                        format!("Unable to generate formnet invite file: {e}")
                    )
                })?
            );
        }

        // Decode and deserialize meta data
        let meta_data = if let Some(md) = meta_data { 
            serde_yaml::from_slice(&BASE64.decode(md)?)? 
        } else {
            MetaData::default_from_distro(distro.clone())
        };

        // Create temporary directory for cloud-init files
        let temp_dir = TempDir::new()?;

        Ok(Self {
            temp_dir,
            user_data,
            meta_data,
        })
    }

    pub fn default_from_distro(distro: Distro) -> Result<Self, CloudInitError> {
        let user_data = UserData::default_from_distro(distro.clone());
        let meta_data = MetaData::default_from_distro(distro.clone()); 

        Ok(Self {
            temp_dir: TempDir::new()?,
            user_data,
            meta_data,
        })
    }

    /// Write cloud-init files to the temporary directory
    fn write_files(&self) -> Result<(), CloudInitError> {
        // Write user-data
        let user_data_path = self.temp_dir.path().join("user-data");
        let user_data_yaml = serde_yaml::to_string(&self.user_data)?;
        fs::write(user_data_path, user_data_yaml)?;

        // Write meta-data
        let meta_data_path = self.temp_dir.path().join("meta-data");
        let meta_data_yaml = serde_yaml::to_string(&self.meta_data)?;
        fs::write(meta_data_path, meta_data_yaml)?;

        Ok(())
    }

    /// Create a cloud-init ISO image
    pub fn create_image(&self, output_path: &PathBuf) -> Result<PathBuf, CloudInitError> {
        // Create parent directories if they don't exist
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CloudInitError::ImageCreation(
                    format!("Failed to create directory structure: {e}")
                )
            })?;
        }
        // Write the cloud-init files
        self.write_files()?;

        // Build cloud-init image using cloud-localds
        let output_path_str = output_path.to_str().ok_or_else(|| {
            CloudInitError::ImageCreation("Invalid output path".to_string())
        })?;

        let temp_dir_str = self.temp_dir.path().to_str().ok_or_else(|| {
            CloudInitError::ImageCreation("Invalid temporary directory path".to_string())
        })?;

        let mut command = Command::new("cloud-localds");
        
        // Add network-config if present
        /*
         * Networking via cloud-init is unreliable right now. revisit in 
         * future.
        if self.network_config.is_some() {
            command.arg("--network-config")
                .arg(format!("{}/network-config", temp_dir_str));
        }
        */

        // Add output path and cloud-init files
        command.arg(output_path_str)
            .arg(format!("{}/user-data", temp_dir_str))
            .arg(format!("{}/meta-data", temp_dir_str));

        let status = command.status().map_err(|e| {
            CloudInitError::ImageCreation(format!("Failed to execute cloud-localds: {}", e))
        })?;

        if !status.success() {
            return Err(CloudInitError::ImageCreation(
                "cloud-localds command failed".to_string()
            ));
        }

        Ok(PathBuf::from(output_path_str))
    }
}

// Default implementations for common configurations
impl Default for InitNetworkConfig {
    fn default() -> Self {
        Self {
            version: 2,
            config: vec![NetworkConfigEntry {
                type_: "physical".to_string(),
                name: "eth0".to_string(),
                dhcp4: Some(true),
                addresses: None,
                gateway4: None,
                nameservers: None,
                mac_address: None,
            }],
        }
    }
}

impl Default for UserData {
    fn default() -> Self {
        Self {
            hostname: "default-vm".to_string(),
            users: Some(vec![User {
                name: "ubuntu".to_string(),
                sudo: Some("ALL=(ALL) NOPASSWD:ALL".to_string()),
                groups: Some("sudo".to_string()),
                shell: Some("/bin/bash".to_string()),
                ssh_authorized_keys: None,
            }]),
            chpasswd: Some(ChPasswd {
                expire: false,
                list: vec!["ubuntu:ubuntu".to_string()],
            }),
            ssh_pwauth: Some(true),
            disable_root: Some(true),
            package_update: Some(true),
            package_upgrade: Some(true),
            packages: None,
            write_files: None,
            run_cmd: None,
            boot_cmd: None,
        }
    }
}

impl Default for MetaData {
    fn default() -> Self {
        use uuid::Uuid;
        Self {
            instance_id: Uuid::new_v4().to_string(),
            local_hostname: "default-vm".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use ipnet::{IpNet, Ipv4Net};
    use shared::{interface_config::{InterfaceInfo, ServerInfo}, Endpoint};
    use tempfile::tempdir;

    fn generate_mock_interface_config() -> InterfaceConfig {
        InterfaceConfig {
            interface: InterfaceInfo {
                network_name: "test-network".to_string(),
                address: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 22),  8).unwrap()),
                private_key: "Some-Private-Key".to_string(),
                listen_port: None 
            },
            server: ServerInfo {
                public_key: "Some-Public-Key".to_string(),
                external_endpoint: Endpoint::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820)),
                internal_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820)
            }
        }
    }

    #[test]
    fn test_cloud_init_defaults() {
        // Create default configurations
        let user_data = UserData::default();
        let meta_data = MetaData::default();
        let network_config = InitNetworkConfig::default();

        // Serialize to YAML and encode as base64
        let user_data_yaml = serde_yaml::to_string(&user_data).unwrap();
        let meta_data_yaml = serde_yaml::to_string(&meta_data).unwrap();
        let network_config_yaml = serde_yaml::to_string(&network_config).unwrap();

        let user_data_b64 = BASE64.encode(user_data_yaml);
        let meta_data_b64 = BASE64.encode(meta_data_yaml);
        let _network_config_b64 = BASE64.encode(network_config_yaml);

        // Create CloudInit instance
        let cloud_init = CloudInit::from_base64(
            Distro::Ubuntu,
            Some(&user_data_b64),
            Some(&meta_data_b64),
            generate_mock_interface_config()
        ).unwrap();

        // Verify the files can be written
        cloud_init.write_files().unwrap();

        // Check that files exist and contain valid YAML
        let user_data_path = cloud_init.temp_dir.path().join("user-data");
        let meta_data_path = cloud_init.temp_dir.path().join("meta-data");
        let network_config_path = cloud_init.temp_dir.path().join("network-config");

        assert!(user_data_path.exists());
        assert!(meta_data_path.exists());
        assert!(network_config_path.exists());

        // Verify content can be parsed back
        let user_data_content = fs::read_to_string(user_data_path).unwrap();
        let _: UserData = serde_yaml::from_str(&user_data_content).unwrap();

        let meta_data_content = fs::read_to_string(meta_data_path).unwrap();
        let _: MetaData = serde_yaml::from_str(&meta_data_content).unwrap();

        let network_config_content = fs::read_to_string(network_config_path).unwrap();
        let _: InitNetworkConfig = serde_yaml::from_str(&network_config_content).unwrap();
    }

    #[test]
    fn test_create_image() {
        // Create default configurations
        let user_data = UserData::default();
        let meta_data = MetaData::default();
        let _network_config = InitNetworkConfig::default();

        // Serialize to YAML and encode as base64
        let user_data_yaml = serde_yaml::to_string(&user_data).unwrap();
        let meta_data_yaml = serde_yaml::to_string(&meta_data).unwrap();

        let user_data_b64 = BASE64.encode(user_data_yaml);
        let meta_data_b64 = BASE64.encode(meta_data_yaml);

        // Create temporary directory for output
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().join("cloud-init.img");

        // Create CloudInit instance and generate image
        let cloud_init = CloudInit::from_base64(
            Distro::Ubuntu,
            Some(&user_data_b64),
            Some(&meta_data_b64),
            generate_mock_interface_config()
        ).unwrap();

        // Only run this test if cloud-localds is available
        if Command::new("cloud-localds").spawn().is_ok() {
            cloud_init.create_image(&output_path).unwrap();
            assert!(output_path.exists());
        }
    }
}
