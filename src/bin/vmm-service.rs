use clap::{Command, ArgMatches};
use log::{info, error};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use form_types::{VmmEvent, VmmSubscriber};

use vmm_service::VmInstanceConfig;
use vmm_service::{
    VmmService,
    error::VmmError,
    config::ServiceConfig
};

use conductor::subscriber::SubStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Parse command line args
    let matches = create_cli().get_matches();

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel(1);
    let shutdown_rx = shutdown_tx.subscribe();

    let config = ServiceConfig::default();

    // Initialize the VMM service
    let mut service = VmmService::new(config)?;

    // build the subscriber
    let subscriber_addr = if let Some(addr) = matches.get_one::<String>("sub_addr") {
        addr.to_string()
    } else {
        "127.0.0.1:5556".to_string()
    };

    let subscriber = VmmSubscriber::new(&subscriber_addr).await?;

    // Start the service
    service.start().await?;

    info!("VMM service started successfully");

    // Set up the signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    // Run the main service loop
    tokio::select! {
        // Handle SIGTERM
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal");
        }
        // Handle SIGINT (Ctrl+C)
        _ = sigint.recv() => {
            info!("Received SIGIN signal");
        }
        // Handle other service events
        result = run_service(&mut service, shutdown_rx, subscriber) => {
            if let Err(e) = result {
                error!("Service error:: {e}");
            }
        }
    }

    // Initiate graceful shutdown
    info!("Initiating service shutdown");
    shutdown_tx.send(())?;

    // Wait for service to clean up
    service.shutdown().await?;

    info!("VMM service shutdown complete");
    Ok(())
}

async fn run_service(
    service: &mut VmmService,
    mut shutdown_rx: broadcast::Receiver<()>,
    mut subscriber: VmmSubscriber
) -> Result<(), VmmError> {
    // Main service event loop
    loop {
        tokio::select! {
            // Check shutdown signal
            Ok(()) = shutdown_rx.recv() => {
                info!("Shutdown signal received");
                break;
            }

            Ok(events) = subscriber.receive() => {
                for event in events {
                    //TODO: Stash in a futures unordered, and handle as they
                    //finish.
                    if let Err(e) = handle_vmm_event(service, &event).await {
                        error!("Error handling event {event:?}: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

fn create_cli() -> Command {
    todo!()
}

#[allow(unused)]
fn load_config(matches: &ArgMatches) -> Result<ServiceConfig, VmmError> {
    todo!()
}

#[allow(unused)]
async fn handle_vmm_event(service: &mut VmmService, event: &VmmEvent) -> Result<(), VmmError> {
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
            let instance_config: VmInstanceConfig = (event, &service_config).try_into().map_err(|e: VmmError| {
                VmmError::Config(e.to_string())
            })?;
            // TODO: return Future, and stash future in a `FuturesUnordered`
            // to be awaited asynchronously.
            service.create_vm(instance_config).await?;
            Ok(())
        }, 
        VmmEvent::Start { owner, recovery_id, id, requestor } => todo!(), 
        VmmEvent::Stop { owner, recovery_id, id, requestor } => todo!(),
        VmmEvent::Delete { owner, recovery_id, id, requestor } => todo!(),
        VmmEvent::Copy => todo!(),
        VmmEvent::Migrate => todo!(),
        VmmEvent::Snapshot => todo!(),
    }
}
