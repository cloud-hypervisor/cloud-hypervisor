use serde::{Deserialize, Serialize};
use crate::Distro;

#[derive(Debug, Serialize, Deserialize)]
pub struct MetaData {
    pub instance_id: String,
    pub local_hostname: String,
}

impl MetaData {
    pub fn default_from_distro(distro: Distro) -> Self {
        // Generate a unique instance ID
        let instance_id = uuid::Uuid::new_v4().to_string();
        
        // Create a distribution-specific hostname prefix
        // This helps identify what kind of VM this is when looking at network traffic
        // or system logs
        let prefix = match distro {
            Distro::Ubuntu => "ubuntu",
            Distro::Fedora => "fedora",
            Distro::Debian => "debian",
            Distro::CentOS => "centos",
            Distro::Arch => "arch",
            Distro::Alpine => "alpine",
        };
        
        // Create a hostname that includes both the distro and part of the UUID
        // for uniqueness. We'll use the first 8 characters of the UUID.
        let short_id = &instance_id[..8];
        let local_hostname = format!("{prefix}-{short_id}");

        Self {
            instance_id,
            local_hostname,
        }
    }
}

