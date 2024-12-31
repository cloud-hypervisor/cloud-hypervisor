use serde::{Serialize, Deserialize};
use shared::interface_config::InterfaceConfig;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::CloudInitError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteFile {
    path: String,
    owner: Option<String>,
    permissions: Option<String>,
    encoding: Option<String>,
    content: Option<String>,
}

pub fn generate_invite_file(invite: InterfaceConfig) -> Result<WriteFile, CloudInitError> {
    let toml_invite = toml::to_string(&invite).map_err(|e| {
        CloudInitError::FileWrite(format!("Unable to convert invite to toml string: {e}"))
    })?;

    let base64_invite = BASE64.encode(toml_invite.as_bytes());

    Ok(WriteFile {
        path: "/etc/formnet/invite.toml".to_string(),
        owner: Some("root:root".to_string()),
        permissions: Some("0644".to_string()),
        encoding: Some("b64".to_string()),
        content: Some(base64_invite)
    })
}
