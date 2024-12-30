use std::path::PathBuf;
use vmm_service::{VmmService, VmInstanceConfig, ServiceConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the logger
    simple_logger::init_with_level(log::Level::Info)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Create the base service configuration
    let service_config = ServiceConfig::default();

    // Initialize the VMM service
    #[cfg(not(feature = "dev"))]
    let vmm_service = VmmService::new(service_config).await?;

    #[cfg(feature = "dev")]
    let (tx, rx) = tokio::sync::mpsc::channel(1024); 
    #[cfg(feature = "dev")]
    let vmm_service = VmmService::new(service_config, tx.clone()).await?;

    // Create a VM configuration
    let vm_config = VmInstanceConfig {
        // Path to our kernel built with cloud-hypervisor-builder
        kernel_path: PathBuf::from("/home/ans/projects/vrrb/protocol/compute/formation/form-vmm/vm-images/hypervisor-fw"),
        // Path to our converted Ubuntu cloud image
        rootfs_path: PathBuf::from("/home/ans/projects/vrrb/protocol/compute/formation/form-vmm/vm-images/focal-server-cloudimg-amd64.raw"),
        tap_device: "vnet0".to_string(),
        ip_addr: "0.0.0.0".to_string(),
        // Path to CloudInit image
        cloud_init_path: Some(PathBuf::from("/home/ans/projects/vrrb/protocol/compute/formation/form-vmm/vm-images/cloud-init.img")),
        // Start with modest resources
        memory_mb: 2048,  // 2GB RAM
        vcpu_count: 2,    // 2 vCPUs
        name: "test-vm-1".to_string(),
        custom_cmdline: None,  // Use default kernel command line
        rng_source: None,
        console_type: vmm_service::ConsoleType::Virtio,
    };

    println!("Creating and starting VM...");
    let vm_instance = vmm_service.create_vm(vm_config).await?;
    
    println!("Successfully created VM with ID: {}", vm_instance.id());
    println!("VM State: {:?}", vm_instance.state());
    
    // Keep the program running so we can interact with the VM
    println!("\nVM is running. Press Ctrl+C to exit...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
