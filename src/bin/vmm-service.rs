use clap::Parser;
use log::{info, error};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use form_types::VmmSubscriber;
use vmm_service::{CliArgs, CliCommand}; 
use vmm_service::{
    VmmService,
    error::VmmError,
    config::{wizard::run_config_wizard, ServiceConfig},
    handle_vmm_event
};
use conductor::subscriber::SubStream;

#[cfg(feature = "dev")]
use tokio::sync::mpsc;
#[cfg(feature = "dev")]
use form_types::VmmEvent;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the logger
    simple_logger::init_with_level(log::Level::Info)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;



    // Parse command line args
    let args = CliArgs::parse();

    // TODO: Handle debug flag if set
    match args.command {
        CliCommand::Run { config, sub_addr, pub_addr, wizard } => {
            let config = if wizard {
                info!("Running configuration wizard");
                run_config_wizard()?
            } else if let Some(config_path) = config {
                info!("Loading configuration from {}", config_path.display());
                ServiceConfig::from_file(&config_path.to_string_lossy())?
            } else {
                info!("Using default conffiguration");
                ServiceConfig::default()
            };

            run_service_with_config(config, &sub_addr, &pub_addr).await?;
        }
        CliCommand::Configure {
            output,
            non_interactive,
            start,
            sub_addr,
            pub_addr
        } => {
            // Create configuration
            let config = if non_interactive {
                ServiceConfig::default()
            } else {
                run_config_wizard()?
            };

            // Save config if requested
            if let Some(path) = output {
                info!("Saving configuration to {}", path.display());
                config.save_to_file(&path.to_string_lossy())?;
            }

            // Start service if requested
            if start {
                info!("Starting service with new configuration");
                run_service_with_config(config, &sub_addr, &pub_addr).await?;
            }
        }

        CliCommand::Status => {
            info!("Checking service status");
            // TODO: implement status check
        }

    }

    Ok(())
}

// Helper function to run the service with a given configuration
async fn run_service_with_config(
    config: ServiceConfig,
    sub_addr: &str,
    pub_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    #[cfg(feature = "dev")]
    let (event_tx, event_rx) = mpsc::channel(1024); 

    // Initialize VMM Service
    #[cfg(not(feature = "dev"))]
    let mut service = VmmService::new(config).await?;
    #[cfg(feature = "dev")]
    let mut service = VmmService::new(config, event_tx).await?;

    // Build the subscriber
    let subscriber = VmmSubscriber::new(sub_addr).await?;

    // Start the service
    service.start().await?;
    info!("VMM service started successfully");

    // Set up signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    // Run the main service loop 
    #[cfg(not(feature = "dev"))]
    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT signal");
        }
        result = run_service(&mut service, shutdown_rx, subscriber) => {
            if let Err(e) = result {
                error!("Service error: {e}");
            }
        }
    }

    #[cfg(feature = "dev")]
    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT signal");
        }
        result = run_service(&mut service, shutdown_rx, subscriber, event_rx) => {
            if let Err(e) = result {
                error!("Service error: {e}");
            }
        }
    }


    // Shutdown
    info!("Initiating service shutdown");
    shutdown_tx.send(())?;
    service.shutdown().await?;
    info!("VMM service shutdown complete");

    Ok(())
}

#[cfg(not(feature = "dev"))] 
async fn run_service(
    service: &mut VmmService,
    mut shutdown_rx: broadcast::Receiver<()>,
    mut subscriber: VmmSubscriber,
) -> Result<(), VmmError> {
    // Main service event loop
    info!("Running VMM service main event handling loop...");
    loop {
        tokio::select! {
            // Check shutdown signal
            Ok(()) = shutdown_rx.recv() => {
                info!("Shutdown signal received");
                break;
            }
            Ok(events) = subscriber.receive() => {
                for event in events {
                    info!("Handling event: {event:?}");
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

#[cfg(feature = "dev")]
async fn run_service(
    service: &mut VmmService,
    mut shutdown_rx: broadcast::Receiver<()>,
    mut subscriber: VmmSubscriber,
    mut event_receiver: mpsc::Receiver<VmmEvent>,
) -> Result<(), VmmError> {
    // Main service event loop
    info!("Running VMM service main event handling loop...");
    loop {
        tokio::select! {
            // Check shutdown signal
            Ok(()) = shutdown_rx.recv() => {
                info!("Shutdown signal received");
                break;
            }
            Ok(events) = subscriber.receive() => {
                for event in events {
                    info!("Handling event: {event:?}");
                    //TODO: Stash in a futures unordered, and handle as they
                    //finish.
                    if let Err(e) = handle_vmm_event(service, &event).await {
                        error!("Error handling event {event:?}: {e}");
                    }
                }
            }
            Some(event) = event_receiver.recv() => {
                log::info!("Received test API event: {:?}", event);
                if let Err(e) = handle_vmm_event(service, &event).await {
                    log::error!("Error handling event {event:?}: {e}");
                }
            }
        }
    }

    Ok(())
}
