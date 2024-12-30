use std::net::IpAddr;
use std::sync::Arc;
use axum::{
    routing::{get, post, delete},
    Router,
    Json,
    extract::{Path, State},
};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMapping {
    pub domain: String,
    pub private_ip: IpAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMappingRequest {
    pub domain: String,
    pub private_ip: IpAddr,
}

// State
#[derive(Debug, Default)]
pub struct ControlPlaneState {
    mappings: HashMap<String, InstanceMapping>,
}

type SharedState = Arc<RwLock<ControlPlaneState>>;

// API Server
pub struct ControlPlaneApi {
    state: SharedState,
    bind_addr: String,
}

impl ControlPlaneApi {
    pub fn new(bind_addr: String) -> Self {
        Self {
            state: Arc::new(RwLock::new(ControlPlaneState::default())),
            bind_addr,
        }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/instances/mapping/:domain", get(get_mapping))
            .route("/instances/mapping", post(create_mapping))
            .route("/instances/mapping/:domain", delete(delete_mapping))
            .route("/instances/mappings", get(list_mappings))
            .with_state(self.state);

        println!("Control plane API starting on {}", self.bind_addr);
        let listener = tokio::net::TcpListener::bind(self.bind_addr.clone()).await
            .map_err(|e| format!("Failed to bind listener to address {}: {e}", self.bind_addr.clone()))?;
        // Start the API server
        axum::serve(listener, app).await
            .map_err(|e| format!("Failed to serve API server {e}"))?;

        Ok(())
    }
}

// Handlers
async fn get_mapping(
    Path(domain): Path<String>,
    State(state): State<SharedState>,
) -> Json<Option<InstanceMapping>> {
    log::info!("Received request to retrieve IP for instance {domain}");
    let state = state.read().await;
    Json(state.mappings.get(&domain).cloned())
}

async fn create_mapping(
    State(state): State<SharedState>,
    Json(request): Json<CreateMappingRequest>,
) -> Json<InstanceMapping> {
    let mapping = InstanceMapping {
        domain: request.domain.clone(),
        private_ip: request.private_ip,
    };

    state.write().await.mappings.insert(request.domain.clone(), mapping.clone());
    Json(mapping)
}

async fn delete_mapping(
    Path(domain): Path<String>,
    State(state): State<SharedState>,
) -> Json<Option<InstanceMapping>> {
    let mut state = state.write().await;
    Json(state.mappings.remove(&domain))
}

async fn list_mappings(
    State(state): State<SharedState>,
) -> Json<Vec<InstanceMapping>> {
    let state = state.read().await;
    Json(state.mappings.values().cloned().collect())
}

// Basic test module
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, Request};
    use axum::body::Body;
    use tower::ServiceExt;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_mapping_crud() {
        let state = Arc::new(RwLock::new(ControlPlaneState::default()));
        let app = Router::new()
            .route("/instances/mapping/:domain", get(get_mapping))
            .route("/instances/mapping", post(create_mapping))
            .route("/instances/mappings", get(list_mappings))
            .with_state(state);

        // Create mapping
        let create_req = CreateMappingRequest {
            domain: "test.example.com".to_string(),
            private_ip: IpAddr::from_str("192.168.1.10").unwrap(),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/instances/mapping")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&create_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Get mapping
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/instances/mapping/test.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let mapping: Option<InstanceMapping> = serde_json::from_slice(&body).unwrap();
        
        assert!(mapping.is_some());
        let mapping = mapping.unwrap();
        assert_eq!(mapping.domain, "test.example.com");
        assert_eq!(mapping.private_ip.to_string(), "192.168.1.10");
    }
}
