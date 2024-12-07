use std::fs;
use std::path::PathBuf; 
use std::process::Command;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use thiserror::Error;
use crate::ServiceConfig;
use super::Distro;

#[derive(Debug, Error)]
pub enum CloudInitError {
    #[error("Failed to decode base64 data: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    
    #[error("Failed to create temp directory: {0}")]
    TempDir(#[from] std::io::Error),
    
    #[error("Failed to serialize cloud-init data: {0}")]
    Serialize(#[from] serde_yaml::Error),
    
    #[error("Failed to create cloud-init image: {0}")]
    ImageCreation(String),
    
    #[error("Failed to write cloud-init file: {0}")]
    FileWrite(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub version: u8,
    pub config: Vec<NetworkConfigEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfigEntry {
    pub type_: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp4: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameservers: Option<NameServers>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NameServers {
    pub addresses: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<User>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chpasswd: Option<ChPasswd>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_pwauth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_root: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_update: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_upgrade: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<String>>,
}

impl UserData {
    pub fn default_from_distro(distro: Distro) -> Self {
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChPasswd {
    pub expire: bool,
    pub list: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetaData {
    pub instance_id: String,
    pub local_hostname: String,
}

impl MetaData {
    pub fn default_from_distro(distro: Distro) -> Self {
        todo!()
    }
}

pub struct CloudInit {
    temp_dir: TempDir,
    user_data: UserData,
    meta_data: MetaData,
    network_config: Option<NetworkConfig>,
}

impl CloudInit {
    /// Create a new CloudInit instance from base64 encoded configuration data
    pub fn from_base64(
        distro: Distro,
        user_data: Option<&str>,
        meta_data: Option<&str>,
        service_config:  &ServiceConfig,
    ) -> Result<Self, CloudInitError> {
        // Decode and deserialize user data
        let user_data = if let Some(ud) = user_data {
            serde_yaml::from_slice(&BASE64.decode(ud)?)?
        } else {
            UserData::default_from_distro(distro.clone())
        };

        // Decode and deserialize meta data
        let meta_data = if let Some(md) = meta_data { 
            serde_yaml::from_slice(&BASE64.decode(md)?)? 
        } else {
            MetaData::default_from_distro(distro.clone())
        };

        // Decode and deserialize network config if provided
        let network_config = NetworkConfig {
            version: 2,
            config: vec![NetworkConfigEntry {
                type_: "physical".to_string(),
                name: "eth0".to_string(),
                dhcp4: Some(true),
                addresses: None,
                gateway4: Some(service_config.network.gateway.clone()),
                nameservers: Some(NameServers {
                    addresses: service_config.network.nameservers.clone()
                })
            }],
        };

        // Create temporary directory for cloud-init files
        let temp_dir = TempDir::new()?;

        Ok(Self {
            temp_dir,
            user_data,
            meta_data,
            network_config: Some(network_config),
        })
    }

    pub fn default_from_distro(distro: Distro) -> Result<Self, CloudInitError> {
        let user_data = UserData::default_from_distro(distro.clone());
        let meta_data = MetaData::default_from_distro(distro.clone()); 

        Ok(Self {
            temp_dir: TempDir::new()?,
            user_data,
            meta_data,
            network_config: None,
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

        // Write network-config if present
        if let Some(ref network_config) = self.network_config {
            let network_config_path = self.temp_dir.path().join("network-config");
            let network_config_yaml = serde_yaml::to_string(network_config)?;
            fs::write(network_config_path, network_config_yaml)?;
        }

        Ok(())
    }

    /// Create a cloud-init ISO image
    pub fn create_image(&self, output_path: &PathBuf) -> Result<PathBuf, CloudInitError> {
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
        if self.network_config.is_some() {
            command.arg("--network-config")
                .arg(format!("{}/network-config", temp_dir_str));
        }

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
impl Default for NetworkConfig {
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
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cloud_init_defaults() {
        // Create default configurations
        let user_data = UserData::default();
        let meta_data = MetaData::default();
        let network_config = NetworkConfig::default();

        // Serialize to YAML and encode as base64
        let user_data_yaml = serde_yaml::to_string(&user_data).unwrap();
        let meta_data_yaml = serde_yaml::to_string(&meta_data).unwrap();
        let network_config_yaml = serde_yaml::to_string(&network_config).unwrap();

        let user_data_b64 = BASE64.encode(user_data_yaml);
        let meta_data_b64 = BASE64.encode(meta_data_yaml);
        let network_config_b64 = BASE64.encode(network_config_yaml);

        // Create CloudInit instance
        let cloud_init = CloudInit::from_base64(
            &user_data_b64,
            &meta_data_b64,
            Some(&network_config_b64)
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
        let _: NetworkConfig = serde_yaml::from_str(&network_config_content).unwrap();
    }

    #[test]
    fn test_create_image() {
        // Create default configurations
        let user_data = UserData::default();
        let meta_data = MetaData::default();
        let network_config = NetworkConfig::default();

        // Serialize to YAML and encode as base64
        let user_data_yaml = serde_yaml::to_string(&user_data).unwrap();
        let meta_data_yaml = serde_yaml::to_string(&meta_data).unwrap();
        let network_config_yaml = serde_yaml::to_string(&network_config).unwrap();

        let user_data_b64 = BASE64.encode(user_data_yaml);
        let meta_data_b64 = BASE64.encode(meta_data_yaml);
        let network_config_b64 = BASE64.encode(network_config_yaml);

        // Create temporary directory for output
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().join("cloud-init.img");

        // Create CloudInit instance and generate image
        let cloud_init = CloudInit::from_base64(
            &user_data_b64,
            &meta_data_b64,
            Some(&network_config_b64)
        ).unwrap();

        // Only run this test if cloud-localds is available
        if Command::new("cloud-localds").spawn().is_ok() {
            cloud_init.create_image(&output_path).unwrap();
            assert!(output_path.exists());
        }
    }
}
