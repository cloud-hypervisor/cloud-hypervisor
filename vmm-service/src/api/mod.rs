use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::State,
};

use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use std::sync::Arc;
use std::net::SocketAddr;

use crate::VmmError;
use form_types::VmmEvent;

/// Testing API server that allows direct interaction with the VMM service
pub struct TestApi {
    /// Channel to send events to the service
    event_sender: mpsc::Sender<VmmEvent>,
    /// Server address
    addr: SocketAddr,
}

/// Request to create a new VM instance
#[derive(Debug, Deserialize)]
pub struct CreateVmRequest {
    pub distro: String,
    pub version: String,
    pub memory_mb: u64,
    pub vcpu_count: u8,
    pub name: String,
    pub user_data: Option<String>,
    pub meta_data: Option<String>
}

/// Response containing VM information
#[derive(Debug, Serialize)]
pub struct VmResponse {
    pub id: String,
    pub name: String,
    pub state: String,
}

impl TestApi {
    pub fn new(event_sender: mpsc::Sender<VmmEvent>, addr: SocketAddr) -> Self {
        Self {
            event_sender, addr
        }
    }

    pub async fn start(&self) -> Result<(), VmmError> {
        let app_state = Arc::new(self.event_sender.clone());

        let app = Router::new()
            .route("/vm", post(create_vm))
            .route("/vm/:id/start", post(start_vm))
            .route("/vm/:id/stop", post(stop_vm))
            .route("/vm/:id/delete", post(delete_vm))
            .route("/vm/:id", get(get_vm))
            .route("/vms", get(list_vms))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(self.addr.clone()).await
            .map_err(|e| VmmError::SystemError(format!("Failed to bind listener to address {}: {e}", self.addr.clone())))?;
        // Start the API server
        axum::serve(listener, app).await
            .map_err(|e| VmmError::SystemError(format!("Failed to serve API server {e}")))?;


        Ok(())
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
}

async fn create_vm(
    State(sender): State<Arc<mpsc::Sender<VmmEvent>>>,
    Json(request): Json<CreateVmRequest>,
) -> Result<Json<VmResponse>, String> {
    log::info!(
        "Received VM create request: name={}, distro={}, version={}",
        request.name, request.distro, request.version
    );
    // Convert request into a VmmEvent::Create
    let event = VmmEvent::Create {
        owner: "test".to_string(),
        recovery_id: 0,
        requestor: "test-api".to_string(),
        distro: request.distro,
        version: request.version,
        user_data: request.user_data,
        meta_data: request.meta_data,
        memory_mb: request.memory_mb,
        vcpu_count: request.vcpu_count,
        name: request.name.clone(),
        custom_cmdline: None,
        rng_source: None,
        console_type: None,
    };

    log::info!("Sending create event to VMM service: {:?}", event);

    sender.send(event).await.map_err(|e| e.to_string())?;

    log::info!("VM Creation requestt processed for {}", request.name);

    Ok(Json(VmResponse {
        id: "pending".to_string(),
        name: request.name,
        state: "creating".to_string()
    }))

}
async fn start_vm() {}
async fn stop_vm() {}
async fn delete_vm() {}
async fn get_vm() {}
async fn list_vms() {}
