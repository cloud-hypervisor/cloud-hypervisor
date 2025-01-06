use std::path::PathBuf;
use http_body_util::{BodyExt, Full};
use hyper::{body::{Body, Bytes},  Method, Request};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use libc::EFD_NONBLOCK;
use seccompiler::SeccompAction;
use vmm::vm_config::VmConfig;
use vmm_service::{config::create_vm_config, ChError, ServiceConfig, VmInstanceConfig, VmmService};
use clap::Parser;
use vmm_sys_util::{eventfd::EventFd, signal::block_signal};
use std::error::Error;
use tokio::io::AsyncWriteExt;

#[derive(Parser)]
struct Cli {
    #[clap(long, short)]
    kernel_path: String,
    #[clap(long, short)]
    rootfs_path: String,
    #[clap(long, short)]
    cloud_init_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the logger
    simple_logger::init_with_level(log::Level::Info)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let socket_path = "/tmp/form-vmm-1.sock";
    let handle = tokio::task::spawn(async move {
        start_vmm(
            socket_path.to_string()
        ).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string()
            )
        })?;
        Ok::<(), std::io::Error>(())
    });

    let opts = Cli::parse();

    let kernel_path = PathBuf::from(&opts.kernel_path);
    let rootfs_path = PathBuf::from(&opts.rootfs_path);
    let cloud_init_path = PathBuf::from(&opts.cloud_init_path);
    
    println!("{kernel_path:?}: {}", kernel_path.exists());
    println!("{rootfs_path:?}: {}", rootfs_path.exists());
    println!("{cloud_init_path:?}: {}", cloud_init_path.exists());

    // Create the base service configuration
    let service_config = ServiceConfig::default();

    // Initialize the VMM service
    let (tx, _rx) = tokio::sync::mpsc::channel(1024); 
    #[allow(unused_mut)]
    let mut _vmm_service = VmmService::new(service_config, tx.clone()).await?;

    // Create a VM configuration
    #[allow(unused_mut)]
    let mut vm_config = VmInstanceConfig {
        // Path to our kernel built with cloud-hypervisor-builder
        kernel_path,
        // Path to our converted Ubuntu cloud image
        rootfs_path,
        tap_device: "vnet1".to_string(),
        ip_addr: "11.0.1.0".to_string(),
        // Path to CloudInit image
        cloud_init_path: Some(cloud_init_path),
        // Start with modest resources
        memory_mb: 2048,  // 2GB RAM
        vcpu_count: 2,    // 2 vCPUs
        name: "test-vm-1".to_string(),
        custom_cmdline: None,  // Use default kernel command line
        rng_source: None,
        console_type: vmm_service::ConsoleType::Serial,
    };

    std::thread::sleep(std::time::Duration::from_secs(5));

    println!("Creating and starting VM...");
    let vm_config = create_vm_config(&vm_config);
    println!("{vm_config}");
    let _ = send_ping().await;
    let _ = send_create(vm_config).await;
    let _ = send_boot().await;


    // Keep the program running so we can interact with the VM
    println!("\nVM is running. Press Ctrl+C to exit...");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    let _ = handle.await?;
    std::fs::remove_file(socket_path)?;

    Ok(())
}

fn start_vmm(
    api_socket: String,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // API socket initialization
    let (api_socket_path, api_socket_fd) = (Some(api_socket), None); 

    // Create channels and EventFDs
    let (api_request_sender, api_request_receiver) = std::sync::mpsc::channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).map_err(ChError::CreateApiEventFd)?;

    // Signal handling
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    for sig in &vmm::vm::Vm::HANDLED_SIGNALS {
        let _ = block_signal(*sig).map_err(|e| eprintln!("Error blocking signals: {e}"));
    }

    for sig in &vmm::Vmm::HANDLED_SIGNALS {
        let _ = block_signal(*sig).map_err(|e| eprintln!("Error blocking signals: {e}"));
    }

    // Initialize hypervisor
    let hypervisor = hypervisor::new().map_err(ChError::CreateHypervisor)?;
    let exit_evt = EventFd::new(EFD_NONBLOCK).map_err(ChError::CreateExitEventFd)?;

    // Start the VMM thread
    let vmm_thread_handle = vmm::start_vmm_thread(
        vmm::VmmVersionInfo::new(env!("BUILD_VERSION"), env!("CARGO_PKG_VERSION")),
        &api_socket_path,
        api_socket_fd,
        api_evt.try_clone().unwrap(),
        api_request_sender.clone(),
        api_request_receiver,
        exit_evt.try_clone().unwrap(),
        &SeccompAction::Trap,
        hypervisor,
        false,
    )
    .map_err(ChError::StartVmmThread)?;

    // Wait for the VMM thread to finish
    vmm_thread_handle
        .thread_handle
        .join()
        .map_err(ChError::ThreadJoin)?
        .map_err(ChError::VmmThread)?;

    Ok(api_socket_path)
}


async fn send_ping() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Create the Unix socket client
    println!("Getting client");
    let client: Client<UnixConnector, Full<Bytes>> = Client::unix();

    println!("Got client, getting URI");
    let uri = Uri::new("/tmp/form-vmm-1.sock", "localhost/api/v1/vmm.ping").into();
    
    // Create the request - using EXACTLY the same URL as curl
    println!("Got URI, sending request");
    let mut response = client.get(uri).await?;

    // Send the request
    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;

        if let Some(segment) = frame.data_ref() {
            println!("{:?}", segment);
            tokio::io::stdout().write_all(segment.iter().as_slice()).await?;
        }
    }
    println!("Response status: {}", response.status());

    Ok(())
}

async fn send_create(config: VmConfig) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
    println!("Serializing config to JSON");
    let json_body = serde_json::to_string(&config)?;
    
    println!("Getting URI");
    let uri: hyper::http::Uri = Uri::new("/tmp/form-vmm-1.sock", "localhost/api/v1/vm.create").into();

    println!("Building request");
    let request = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json_body)))?;

    println!("Sending request");
    let mut response = client.request(request).await?;

    println!("Got response, reading frames");
    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;

        if let Some(segment) = frame.data_ref() {
            println!("{:?}", segment);
            tokio::io::stdout().write_all(segment.iter().as_slice()).await?;
        }
    }
    println!("Response status: {}", response.status());

    Ok(())
}

async fn send_boot() -> Result<(), Box<dyn Error + Send + Sync>> {
    let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
    println!("Serializing config to JSON");
    println!("Getting URI");
    let uri: hyper::http::Uri = Uri::new("/tmp/form-vmm-1.sock", "localhost/api/v1/vm.boot").into();

    println!("Building request");
    let request = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from("")))?;

    println!("Sending request");
    let mut response = client.request(request).await?;

    println!("Got response, reading frames");
    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;

        if let Some(segment) = frame.data_ref() {
            println!("{:?}", segment);
            tokio::io::stdout().write_all(segment.iter().as_slice()).await?;
        }
    }
    println!("Response status: {}", response.status());

    Ok(())
}
