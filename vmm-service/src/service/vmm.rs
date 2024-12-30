// src/service/vmm.rs
#[cfg(feature = "dev")]
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
#[cfg(feature = "dev")]
use tokio::sync::mpsc::{self, Receiver};
use std::sync::mpsc::{Sender, channel};
use vmm::api::{ApiAction, ApiRequest};
use vmm_sys_util::eventfd::EventFd;
use seccompiler::SeccompAction;
use tokio::task::JoinHandle;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
#[cfg(feature = "dev")]
use form_types::VmmEvent;
#[cfg(feature = "dev")]
use crate::api::TestApi;
use crate::VmRuntime;
use crate::VmState;
use crate::{
    error::VmmError,
    config::create_vm_config,
    instance::{config::VmInstanceConfig, manager::{InstanceManager, VmInstance}},
    ServiceConfig,
};

pub struct VmmService {
    pub hypervisor: Arc<dyn hypervisor::Hypervisor>,
    pub config: ServiceConfig,
    instance_manager: Arc<Mutex<InstanceManager>>,
    event_thread: Option<JoinHandle<Result<(), VmmError>>>, 
    api_sender: Option<Sender<ApiRequest>>,
    api_evt: EventFd,
    exit_evt: EventFd,
    shutdown_sender: broadcast::Sender<()>,
    #[cfg(feature = "dev")]
    test_api: Option<TestApi>,
    #[cfg(feature = "dev")]
    api_task: Option<JoinHandle<Result<(), VmmError>>>, 
}

impl VmmService {
    #[cfg(not(feature = "dev"))]
    pub async fn new(config: ServiceConfig) -> Result<Self, VmmError> {
        let hypervisor = hypervisor::new()
            .map_err(VmmError::HypervisorInit)?;

        let api_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(|e| VmmError::SystemError(format!("Failed to create API eventfd: {}", e)))?;
            
        let exit_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(|e| VmmError::SystemError(format!("Failed to create exit eventfd: {}", e)))?;

        let (api_sender, api_receiver) = channel();
        let (shutdown_sender, _) = broadcast::channel(1);


        vmm::start_vmm_thread(
            vmm::VmmVersionInfo::new(env!("BUILD_VERSION"), env!("CARGO_PKG_VERSION")),
            &None,
            None,
            api_evt.try_clone().unwrap(),
            api_sender.clone(),
            api_receiver,
            exit_evt.try_clone().unwrap(),
            &SeccompAction::Allow,
            hypervisor.clone(),
            false,
        ).map_err(|e| VmmError::SystemError(format!("Failed to start VMM thread: {}", e)))?;

        Ok(Self {
            hypervisor,
            config,
            instance_manager: Arc::new(Mutex::new(InstanceManager::new())),
            event_thread: None,
            api_sender: Some(api_sender),
            api_evt,
            exit_evt,
            shutdown_sender,
            
        })
    }

    #[cfg(feature = "dev")]
    pub async fn new(config: ServiceConfig, event_sender: mpsc::Sender<VmmEvent>) -> Result<Self, VmmError> {
        let hypervisor = hypervisor::new()
            .map_err(VmmError::HypervisorInit)?;

        let api_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(|e| VmmError::SystemError(format!("Failed to create API eventfd: {}", e)))?;
            
        let exit_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(|e| VmmError::SystemError(format!("Failed to create exit eventfd: {}", e)))?;

        let (api_sender, api_receiver) = channel();

        let (shutdown_sender, _) = broadcast::channel(1);

        // Create the test API instance
        let test_api = TestApi::new(
            event_sender,
            SocketAddr::from(([127, 0, 0, 1], 8000))
        );

        vmm::start_vmm_thread(
            vmm::VmmVersionInfo::new(env!("BUILD_VERSION"), env!("CARGO_PKG_VERSION")),
            &None,
            None,
            api_evt.try_clone().unwrap(),
            api_sender.clone(),
            api_receiver,
            exit_evt.try_clone().unwrap(),
            &SeccompAction::Allow,
            hypervisor.clone(),
            false,
        ).map_err(|e| VmmError::SystemError(format!("Failed to start VMM thread: {}", e)))?;

        Ok(Self {
            hypervisor,
            config,
            instance_manager: Arc::new(Mutex::new(InstanceManager::new())),
            event_thread: None,
            api_sender: Some(api_sender),
            api_evt,
            exit_evt,
            shutdown_sender,
            test_api: Some(test_api),
            api_task: None,
        })
    }
    
    #[cfg(not(feature = "dev"))]
    /// Start the VMM service
    pub async fn start(&mut self) -> Result<(), VmmError> {
        // Start DNS server
        let instance_manager = self.instance_manager.clone();
        let exit_evt = self.exit_evt.try_clone()
            .map_err(|e| VmmError::SystemError(format!("Failed to clone exit event: {e}")))?;
        let mut shutdown_receiver = self.shutdown_sender.subscribe();

        // Start the event processing loop
        let event_thread = tokio::spawn(async move {
            // Create async wrapper for exit evt
            let exit_evt = tokio::io::unix::AsyncFd::new(exit_evt)
                .map_err(|e| {
                    VmmError::SystemError(format!("Unable to convert exit_evt file descriptor to Async File Descriptor {e}"))
                })?;

            loop {
                tokio::select! {
                    // Handle shutdown signal
                    Ok(()) = shutdown_receiver.recv() => {
                        log::info!("Received shutdown signal, stopping event loop");
                        break;
                    }

                    // Handle VM exit events
                    Ok(mut guard) = exit_evt.readable() => {
                        match guard.try_io(|inner: &AsyncFd<EventFd>| inner.get_ref().read()) {
                            Ok(Ok(_)) => {
                                log::info!("VM exit event received");
                                break;
                            }
                            Ok(Err(e)) => {
                                log::error!("Error reading exit event: {e}");
                                break;
                            }
                            Err(_would_block) => continue,
                        }
                    }
                    
                    // Process VM lifecycle events
                    _ = Self::process_vm_lifecycle(instance_manager.clone()) => {}
                }
            }
            Ok::<(), VmmError>(())
        });

        self.event_thread = Some(event_thread);

        Ok(())
    }

    #[cfg(feature = "dev")]
    pub async fn start(&mut self) -> Result<(), VmmError> {
        // Start DNS server
        let instance_manager = self.instance_manager.clone();
        let exit_evt = self.exit_evt.try_clone()
            .map_err(|e| VmmError::SystemError(format!("Failed to clone exit event: {e}")))?;
        let mut shutdown_receiver = self.shutdown_sender.subscribe();

        if let Some(api) = self.test_api.take() {
            log::info!("Starting API server on {}", api.addr());
            let api_task = tokio::spawn(async move {
                api.start().await
            });
            self.api_task = Some(api_task);
        }

        // Start the event processing loop
        let event_thread = tokio::spawn(async move {
            // Create async wrapper for exit evt
            let exit_evt = tokio::io::unix::AsyncFd::new(exit_evt)
                .map_err(|e| {
                    VmmError::SystemError(format!("Unable to convert exit_evt file descriptor to Async File Descriptor {e}"))
                })?;

            loop {
                tokio::select! {
                    // Handle shutdown signal
                    Ok(()) = shutdown_receiver.recv() => {
                        log::info!("Received shutdown signal, stopping event loop");
                        break;
                    }

                    // Handle VM exit events
                    Ok(mut guard) = exit_evt.readable() => {
                        match guard.try_io(|inner: &AsyncFd<EventFd>| inner.get_ref().read()) {
                            Ok(Ok(_)) => {
                                log::info!("VM exit event received");
                                break;
                            }
                            Ok(Err(e)) => {
                                log::error!("Error reading exit event: {e}");
                                break;
                            }
                            Err(_would_block) => continue,
                        }
                    }
                    
                    // Process VM lifecycle events
                    _ = Self::process_vm_lifecycle(instance_manager.clone()) => {}
                }
            }
            Ok::<(), VmmError>(())
        });

        self.event_thread = Some(event_thread);

        Ok(())
    }
    /// Creates a new VM instance
    pub async fn create_vm(&self, config: VmInstanceConfig) -> Result<VmInstance, VmmError> {
        config.validate()?;

        // Set up networking for the VM
        let vm_config = create_vm_config(&config);


        if let Some(api_sender) = &self.api_sender {
            vmm::api::VmCreate.send(
                self.api_evt.try_clone().unwrap(),
                api_sender.clone(),
                Box::new(vm_config),
            ).map_err(|e| VmmError::VmOperation(e))?;

            vmm::api::VmBoot.send(
                self.api_evt.try_clone().unwrap(),
                api_sender.clone(),
                (),
            ).map_err(|e| VmmError::VmOperation(e))?;

            let vmrt = VmRuntime::new(config);
            let instance = vmrt.instance().clone(); 
            self.instance_manager.lock().await.add_instance(vmrt).await?;

            log::info!("Successfully created VM {}", instance.id());

            Ok(instance)
        } else {
            Err(VmmError::SystemError("API sender not initialized".to_string()))
        }
    }

    /// Stops a running  VM
    pub async fn stop_vm(&self, id: &str) -> Result<(), VmmError> {
        self.instance_manager.lock().await.stop_instance(id).await
    }

    /// Processes VM lifecycle events
    async fn process_vm_lifecycle(instance_manager: Arc<Mutex<InstanceManager>>) {
        let manager = instance_manager.lock().await;
        for instance in manager.list_instances().await {
            match instance.state() {
                VmState::Failed => {
                    log::warn!("VM {} in failed state - initiating cleanup", instance.id());
                    if let Err(e) = manager.remove_instance(instance.id()).await {
                        let id = instance.id();
                        log::error!("Failed to clean up failed VM {id}: {e}");
                    }
                }
                VmState::Stopped => {
                    let id = instance.id();
                    log::info!("VM {id} stoped - cleaning up resources");
                    if let Err(e) = manager.remove_instance(id).await {
                        log::error!("Failed to clean up stopped VM {id}: {e}");
                    }
                }
                _ => {}
            }
        }
    }

    /// Shuts down the `VmmService`
    pub async fn shutdown(&mut self) -> Result<(), VmmError> {
        log::info!("Initiating VMM service shutdown");

        // Stop all running VMs
        let mut manager = self.instance_manager.lock().await;
        manager.shutdown_all().await?;

        // Send shutdown signal to event loop
        self.shutdown_sender.send(()).map_err(|e| {
            VmmError::SystemError(format!("Failed to send shutdown signal: {e}"))
        })?;

        #[cfg(feature = "dev")]
        // Shutdown API server if running
        if let Some(handle) = self.api_task.take() {
            log::info!("Shutting down the API server");
            handle.abort();
            match handle.await {
                Ok(_) => log::info!("API server shut down Successfully"),
                Err(e) => log::error!("Error shutting down the API server: {e}"),
            }
        }


        log::info!("VMM Service shutdown complete");
        Ok(())
    }
}

impl Drop for VmmService {
    fn drop(&mut self) {
        // Ensure clean shutdown in synvhronous context
        if self.event_thread.is_some() {
            log::warn!("VmmService dropped while event thread was running - some resources may not be cleaned up properly");
            
            // We can still do basic cleanup
            if let Some(handle) = self.event_thread.take() {
                handle.abort();
            }

            #[cfg(feature = "dev")]
            if let Some(handle) = self.api_task.take() {
                handle.abort();
            }
        }
    }
}
