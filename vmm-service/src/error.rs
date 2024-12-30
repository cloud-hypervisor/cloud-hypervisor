use thiserror::Error;

#[derive(Error, Debug)]
pub enum VmmError {
    #[error("Failed to initialize hypervisor: {0}")]
    HypervisorInit(#[from] hypervisor::HypervisorError),
    
    #[error("VM operation failed: {0:?}")]
    VmOperation(vmm::api::ApiError),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    
    #[error("VM not found: {0}")]
    VmNotFound(String),
    
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    
    #[error("System error: {0}")]
    SystemError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

// Instead of using #[from], we'll implement the From trait manually
impl From<vmm::api::ApiError> for VmmError {
    fn from(error: vmm::api::ApiError) -> Self {
        VmmError::VmOperation(error)
    }
}
