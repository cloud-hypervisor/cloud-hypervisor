use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::AsyncReadExt;
use crate::{VmmService, VmInstanceConfig, VmmError};
use form_types::{FormnetMessage, GenericPublisher, NetworkTopic, PeerType, VmmEvent};
use shared::interface_config::InterfaceConfig;
use tokio::net::TcpListener;
use conductor::publisher::PubStream;

#[allow(unused)]
pub async fn handle_vmm_event(service: &mut VmmService, event: &VmmEvent) -> Result<(), VmmError> {
    match event {
        VmmEvent::Create { 
            owner,
            recovery_id,
            requestor,
            distro,
            version,
            user_data,
            meta_data,
            memory_mb,
            vcpu_count,
            name, 
            custom_cmdline, 
            rng_source, 
            console_type 
        } => {
            let service_config = service.config.clone();
            let invite = request_formnet_invite_for_vm(name.clone()).await?;

            let mut instance_config: VmInstanceConfig = (event, &invite).try_into().map_err(|e: VmmError| {
                VmmError::Config(e.to_string())
            })?;
            // TODO: return Future, and stash future in a `FuturesUnordered`
            // to be awaited asynchronously.
            service.create_vm(&mut instance_config).await?;
            Ok(())
        }, 
        VmmEvent::Start { owner, recovery_id, id, requestor } => todo!(), 
        VmmEvent::Stop { owner, recovery_id, id, requestor } => todo!(),
        VmmEvent::Delete { owner, recovery_id, id, requestor } => todo!(),
        VmmEvent::Copy => todo!(),
        VmmEvent::Migrate => todo!(),
        VmmEvent::Snapshot => todo!(),
        _ => todo!()
    }
}

async fn request_formnet_invite_for_vm(name: String) -> Result<InterfaceConfig, VmmError> {
    // Request a innernet invitation from local innernet peer
    let mut publisher = GenericPublisher::new("127.0.0.1:5555").await.map_err(|e| {
        VmmError::NetworkError(format!("Unable to publish message to setup networking: {e}"))
    })?;

    let callback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5855);

    let listener = TcpListener::bind(callback.clone()).await.map_err(|e| {
        VmmError::NetworkError(
            format!("Unable to bind listener to callback socket to receive formnet invite: {e}")
        )
    })?;

    publisher.publish(
        Box::new(NetworkTopic),
        Box::new(FormnetMessage::AddPeer { 
            peer_id: name.clone(),
            peer_type: PeerType::Instance,
            callback
        })
    ).await.map_err(|e| {
        VmmError::NetworkError(
            format!("Error sending message to broker to request formnet invite: {e}")
        )
    })?;

    tokio::select! {
        Ok((mut stream, _)) = listener.accept() => {
            let mut buf: Vec<u8> = vec![];
            if let Ok(n) = stream.read_to_end(&mut buf).await {
                let invite: shared::interface_config::InterfaceConfig = serde_json::from_slice(&buf[..n]).map_err(|e| {
                    VmmError::NetworkError(
                        format!("Error converting response into InterfaceConfig: {e}")
                    )
                })?;
                return Ok(invite);
            }

            return Err(VmmError::NetworkError(format!("Unable to read response on TcpStream: Error awaiting response to formnet invite request")));
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            log::error!("Timed out awaiting invitation response from formnet");
            return Err(VmmError::NetworkError(format!("Timed out awaiting invite from formnet for VM {}", name)));
        }
    }
}
