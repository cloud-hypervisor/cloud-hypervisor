use thiserror::Error;
use vmm::landlock::LandlockError;

#[derive(Error, Debug)]
pub enum ChError {
    #[error("Failed to create API EventFd: {0}")]
    CreateApiEventFd(#[source] std::io::Error),
    #[error("Failed to create exit EventFd: {0}")]
    CreateExitEventFd(#[source] std::io::Error),
    #[error("Failed to open hypervisor interface (is hypervisor interface available?): {0}")]
    CreateHypervisor(#[source] hypervisor::HypervisorError),
    #[error("Failed to start the VMM thread: {0}")]
    StartVmmThread(#[source] vmm::Error),
    #[error("Error parsing config: {0}")]
    ParsingConfig(vmm::config::Error),
    #[error("Error creating VM: {0:?}")]
    VmCreate(vmm::api::ApiError),
    #[error("Error booting VM: {0:?}")]
    VmBoot(vmm::api::ApiError),
    #[error("Error restoring VM: {0:?}")]
    VmRestore(vmm::api::ApiError),
    #[error("Error parsing restore: {0}")]
    ParsingRestore(vmm::config::Error),
    #[error("Failed to join on VMM thread: {0:?}")]
    ThreadJoin(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    #[error("VMM thread exited with error: {0}")]
    VmmThread(#[source] vmm::Error),
    #[error("Error parsing --api-socket: {0}")]
    ParsingApiSocket(std::num::ParseIntError),
    #[error("Error parsing --event-monitor: {0}")]
    ParsingEventMonitor(option_parser::OptionParserError),
    #[error("Error parsing --event-monitor: path or fd required")]
    BareEventMonitor,
    #[error("Error doing event monitor I/O: {0}")]
    EventMonitorIo(std::io::Error),
    #[error("Event monitor thread failed: {0}")]
    EventMonitorThread(#[source] vmm::Error),
    #[error("Error creating log file: {0}")]
    LogFileCreation(std::io::Error),
    #[error("Error setting up logger: {0}")]
    LoggerSetup(log::SetLoggerError),
    #[error("Failed to gracefully shutdown http api: {0}")]
    HttpApiShutdown(#[source] vmm::Error),
    #[error("Failed to create Landlock object: {0}")]
    CreateLandlock(#[source] LandlockError),
    #[error("Failed to apply Landlock: {0}")]
    ApplyLandlock(#[source] LandlockError),
}

#[derive(Error, Debug)]
enum FdTableError {
    #[error("Failed to create event fd: {0}")]
    CreateEventFd(std::io::Error),
    #[error("Failed to obtain file limit: {0}")]
    GetRLimit(std::io::Error),
    #[error("Error calling fcntl with F_GETFD: {0}")]
    GetFd(std::io::Error),
    #[error("Failed to duplicate file handle: {0}")]
    Dup2(std::io::Error),
}

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
