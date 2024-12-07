use serde::{Serialize, Deserialize};
use std::{path::PathBuf, str::FromStr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Distro {
    Ubuntu,
    Fedora,
    Debian,
    CentOS,
    Arch,
    Alpine,
}

impl Distro {
    pub const BASE_PATH: &str = "/var/lib/form/images/";

    pub fn rootfs_disk_path(&self, version: &str) -> PathBuf {
        PathBuf::from(Self::BASE_PATH)
            .join(self.to_string())
            .join(version)
            .join("disk.raw")
    }
}

impl std::fmt::Display for Distro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Distro::Ubuntu => write!(f, "ubuntu"),
            Distro::Fedora => write!(f, "fedora"),
            Distro::Debian => write!(f, "debian"),
            Distro::CentOS => write!(f, "centos"),
            Distro::Arch => write!(f, "arch"),
            Distro::Alpine => write!(f, "alpine"),
        }
    }
}

impl FromStr for Distro {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ubuntu" => Ok(Self::Ubuntu),
            "fedora" => Ok(Self::Fedora),
            "debian" => Ok(Self::Debian),
            "centos" => Ok(Self::CentOS),
            "arch" => Ok(Self::Arch),
            "alpine" => Ok(Self::Alpine),
            _ => Err(
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{s} is not a valid distro in the Formation Network")
                    )
                )
            )
        } 
    }
}
