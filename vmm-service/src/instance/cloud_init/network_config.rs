use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct InitNetworkConfig {
    pub version: u8,
    pub config: Vec<NetworkConfigEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfigEntry {
    pub type_: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
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
