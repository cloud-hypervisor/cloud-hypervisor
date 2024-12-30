use std::net::IpAddr;
use std::str::FromStr;
use vmm_service::{proxy::ApiClient, sdn::{proxy::Proxy, ControlPlaneApi}};
use tokio::sync::broadcast::channel;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::init_with_level(log::Level::Info)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let listen_api_endpoint = "0.0.0.0:8000";
    let send_api_endpoint = "http://localhost:8000";
    let api = ControlPlaneApi::new(listen_api_endpoint.to_string());
    let reverse_proxy = Proxy::new(send_api_endpoint.to_string(), None, None)?;
    let (shutdown_tx, _) = channel::<()>(1);

    let mut api_shutdown = shutdown_tx.subscribe();
    let api_handle = tokio::spawn(async move {
        tokio::select! {
            _ = api_shutdown.recv() => {}
            res = api.start() => {
                if let Err(e) = res {
                    log::error!("Api Error: {e}");
                }
            }
        }
    });

    let mut proxy_shutdown = shutdown_tx.subscribe();
    let proxy_handle = tokio::spawn(async move {
        tokio::select! {
            _ = proxy_shutdown.recv() => {}
            res = reverse_proxy.start() => {
                if let Err(e) = res {
                    log::error!("Proxy Error: {e}");
                }
            }
        }
    });

    let client = ApiClient::new(send_api_endpoint.to_string());
    let response = client.create_mapping(
        "test.example.com",
        IpAddr::from_str("192.168.1.10").unwrap()
    ).await?;

    log::info!("Response: {response:?}");

    let response = client.get_instance(
        "test.example.com"
    ).await?;

    log::info!("Response: {response:?}");

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(())?;

    api_handle.await?;
    proxy_handle.await?;

    Ok(())
}
