use thiserror::Error;

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
