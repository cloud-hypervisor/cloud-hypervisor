// vmm-service/src/instance/manager.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::error::VmmError;
use super::config::VmInstanceConfig;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmState {
    Created,
    Running,
    Paused,
    Stopped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct VmInstance {
    id: String,
    config: VmInstanceConfig,
    state: VmState,
}

impl VmInstance {
    pub(crate) fn new(config: VmInstanceConfig) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            config,
            state: VmState::Created,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn state(&self) -> VmState {
        self.state
    }

    pub fn config(&self) -> &VmInstanceConfig {
        &self.config
    }
}

/// Structure to hold VM Runtime Information
#[derive(Debug)]
pub struct VmRuntime {
    instance: VmInstance,
    task_handle: Option<JoinHandle<()>>,
}

impl VmRuntime {
    pub fn new(config: VmInstanceConfig) -> Self {
        let instance = VmInstance::new(config);
        Self { instance, task_handle: None } 
    }

    pub fn id(&self) -> &str {
        &self.instance.id()
    }

    pub fn state(&self) -> VmState { 
        self.instance.state
    }

    pub fn config(&self) -> &VmInstanceConfig {
        self.instance.config()
    }

    pub fn instance(&self) -> &VmInstance {
        &self.instance
    }

    pub fn instance_mut(&mut self) -> &mut VmInstance {
        &mut self.instance 
    }
}

#[derive(Clone)]
pub(crate) struct InstanceManager {
    instances: Arc<Mutex<HashMap<String, VmRuntime>>>,
}

impl InstanceManager {
    pub fn new() -> Self {
        Self { instances: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Inserts an instance into the instance managers in-memory map of the 
    /// current instances it owns
    /// TODO: persist to backing DB or file.
    pub async fn add_instance(&mut self, runtime: VmRuntime) -> Result<(), VmmError> {
        let runtime_id = runtime.id().to_string();
        log::info!(
            "Adding new VM instance: id={}, name={}",
            runtime.id(),
            runtime.config().name
        );

        self.instances.lock().await.insert(runtime_id.to_string(), runtime);
        log::info!("Successfully added VM instance {}", runtime_id.clone());

        Ok(())
    }

    /// Get's a single `VmInstance` by it's `id`
    pub async fn get_instance(&self, id: &str) -> Result<VmInstance, VmmError> {
        Ok(self.instances.lock().await
            .get(id)
            .ok_or_else(|| {
                VmmError::VmNotFound(
                    id.to_string()
                )
            })?.instance()
            .clone()
        )
    }

    /// Update an instance with a task handle with VM starts running
    pub async fn set_instance_task(&mut self, id:&str, task_handle: JoinHandle<()>) -> Result<(), VmmError> {
        if let Some(rt) = self.instances.lock().await.get_mut(id) {
            rt.task_handle = Some(task_handle);
            Ok(())
        } else {
            Err(VmmError::VmNotFound(id.to_string()))
        }
    }

    /// Stop running a VM instance
    pub async fn stop_instance(&mut self, id: &str) -> Result<(), VmmError> {
        if let Some(rt) = self.instances.lock().await.get_mut(id) {
            if let Some(handle) = rt.task_handle.take() {
                handle.abort();

                match handle.await {
                    Ok(_) => log::info!("VM {id} stopped successfully"),
                    Err(e) => log::error!("Error stopping VM {id}: {e}"),
                }
            }
        } else {
            return Err(VmmError::VmNotFound(id.to_string()));
        }

        self.remove_instance(id).await?;

        Ok(())
    }

    /// Returns a vector of the current instances
    pub async fn list_instances(&self) -> Vec<VmInstance> {
        self.instances.lock().await.values().map(|rt| rt.instance().clone()).collect()
    }

    /// Removes an instance from the instance managers in-memory map of the current
    /// instances it owns
    /// TODO: Persist to backing DB or file
    pub async fn remove_instance(&self, id: &str) -> Result<(), VmmError> {
        self.instances.lock().await.remove(id)
            .ok_or_else(|| {
                VmmError::VmNotFound(
                    id.to_string()
                )
            })?;

        Ok(())
    }

    /// Clean shutdown of all VMs being managed
    pub async fn shutdown_all(&mut self) -> Result<(), VmmError> {
        let mut runtimes = self.instances.lock().await; 
        for (id, rt) in runtimes.drain() { 
            if let Some(handle) = rt.task_handle {
                handle.abort();
                match handle.await {
                    Ok(_) => log::info!("VM {id} shut down successfully"),
                    Err(e) => log::error!("Error shutting down VM {id}: {e}"),
                }
            }
        }
        Ok(())
    }
}
