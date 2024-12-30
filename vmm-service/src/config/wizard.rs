use std::path::PathBuf;
use dialoguer::{Input, Confirm};
use crate::{ServiceConfig, ServicePaths, DefaultVmParams, ResourceLimits, DirectoryConfig, config::NetworkConfig};

pub fn run_config_wizard() -> Result<ServiceConfig, Box<dyn std::error::Error>> {
    println!("Welcome to the Formation Virtual Machine Monitor Configuration Wizard");
    println!("Press ENTER without a response to accept default values, or provide your custom input");

    // Get base directory
    let default_base = ServicePaths::BASE_DIR;
    let base_dir: String = Input::new()
        .with_prompt("Base directory for VM related files and data (disk images, configuration files, snapshots, etc.)")
        .default(default_base.into())
        .interact_text()?;

    let base_path = PathBuf::from(base_dir);

    // Directory configuration
    println!("\nConfiguring directory paths:");
    let directories = configure_directories(&base_path)?;

    // Network Configuration
    println!("\nConfiguring network settings:");
    let network = configure_network()?;

    // Resource limits
    println!("\nConfiguring Resource limits:");
    let limits = configure_resource_limits()?;

    // Default VM Parameters
    println!("\nConfiguring default VM parameters:");
    let default_params = configure_default_params(&limits)?;

    let config = ServiceConfig {
        base_dir: base_path,
        directories,
        network,
        limits,
        default_vm_params: default_params
    };

    print_config_summary(&config);

    // Confirm configuration
    if Confirm::new()
        .with_prompt("Would you like to save this configuration?")
        .default(true)
        .interact()? 
    {
        return Ok(config);
    }

    println!("Configuration cancelled. Using defaults.");
    Ok(ServiceConfig::default())
}

fn configure_directories(base_path: &PathBuf) -> Result<DirectoryConfig, Box<dyn std::error::Error>> {
    let kernel_dir: String = Input::new()
        .with_prompt("Kernel images directory where the kernel binary is located")
        .default(base_path.join(ServicePaths::KERNEL_DIR).to_string_lossy().into())
        .interact_text()?;

    let images_dir: String = Input::new()
        .with_prompt("Base disk images directory where rootfs cloud images for various Linux OS distros are located")
        .default(base_path.join(ServicePaths::IMAGES_DIR).to_string_lossy().into())
        .interact_text()?;

    let cloud_init_dir: String = Input::new()
        .with_prompt("Cloud-Init disk images directory where cloud-init images for VMs are located")
        .default(base_path.join(ServicePaths::CLOUD_INIT_DIR).to_string_lossy().into())
        .interact_text()?;

    let working_dir: String = Input::new()
        .with_prompt("Working disk images directory, where copies of rootfs cloud images in use for VMs are located")
        .default(base_path.join(ServicePaths::WORKING_DIR).to_string_lossy().into())
        .interact_text()?;

    Ok(DirectoryConfig {
        kernel_dir: PathBuf::from(kernel_dir),
        images_dir: PathBuf::from(images_dir),
        cloud_init_dir: PathBuf::from(cloud_init_dir),
        working_dir: PathBuf::from(working_dir),
    })
}

fn configure_network() -> Result<NetworkConfig, Box<dyn std::error::Error>> {
    let default_net = NetworkConfig::default();

    let bridge_interface: String = Input::new()
        .with_prompt("Bridge interface name")
        .default(default_net.bridge_interface)
        .interact_text()?;

    let gateway: String = Input::new()
        .with_prompt("Network gateway")
        .default(default_net.gateway)
        .interact_text()?;

    let dhcp_range_start: String = Input::new()
        .with_prompt("DHCP range start")
        .default(default_net.dhcp_range_start)
        .interact_text()?;

    let dhcp_range_end: String = Input::new()
        .with_prompt("DHCP range end")
        .default(default_net.dhcp_range_end)
        .interact_text()?;

    let netmask: String = Input::new()
        .with_prompt("Network mask")
        .default(default_net.netmask)
        .interact_text()?;

    let dns_listener_addr: String = Input::new()
        .with_prompt("DNS listener address")
        .default(default_net.dns_listener_addr)
        .interact_text()?;

    let domain_suffix: String = Input::new()
        .with_prompt("Domain suffix")
        .default(default_net.domain_suffix)
        .interact_text()?;

    println!("Enter nameservers (empty line to finish):");
    let mut nameservers =  Vec::new();
    loop {
        let ns: String = Input::new()
            .with_prompt("Nameserver")
            .allow_empty(true)
            .interact_text()?;

        if ns.is_empty() {
            if nameservers.is_empty() {
                nameservers = default_net.nameservers;
            }
            break;
        }

        nameservers.push(ns);
    }

    Ok(NetworkConfig {
        bridge_interface,
        dhcp_range_start,
        dhcp_range_end,
        gateway,
        netmask,
        nameservers,
        dns_listener_addr,
        domain_suffix
    })

}

fn configure_resource_limits() -> Result<ResourceLimits, Box<dyn std::error::Error>> {
    let default_limits = ResourceLimits::default();

    let max_vms: usize = Input::new()
        .with_prompt("Maximum number of concurrent VMs on this host allowed")
        .default(default_limits.max_vms)
        .interact_text()?;

    let max_memory_per_vm: u64 = Input::new()
        .with_prompt("Maximum memory per VM in MB allowed on this host")
        .default(default_limits.max_memory_per_vm)
        .interact_text()?;

    let max_vcpus_per_vm: u8 = Input::new()
        .with_prompt("Maximum number of vCPUs per VM allowed on this host")
        .default(default_limits.max_vcpus_per_vm)
        .interact_text()?;

    let max_disk_size_per_vm: u64 = Input::new()
        .with_prompt("Maximum disk size per VM allowed on this host")
        .default(default_limits.max_disk_size_per_vm)
        .interact_text()?;

    Ok(ResourceLimits {
        max_vms,
        max_memory_per_vm,
        max_vcpus_per_vm,
        max_disk_size_per_vm
    })
}

fn configure_default_params(limits: &ResourceLimits) -> Result<DefaultVmParams, Box<dyn std::error::Error>> {
    let default_params = DefaultVmParams::default();

    let memory_mb: u64 = Input::new()
        .with_prompt("Default memory per VM (MB)")
        .default(default_params.memory_mb)
        .validate_with(|input: &u64| {
            if *input <= limits.max_memory_per_vm {
                Ok(())
            } else {
                Err("Default memory cannot exceed maximum limit")
            }
        }).interact_text()?;

    let vcpu_count: u8 = Input::new()
        .with_prompt("Default vCPUs per VM")
        .default(default_params.vcpu_count)
        .validate_with(|input: &u8| {
            if *input <= limits.max_vcpus_per_vm {
                Ok(())
            } else {
                Err("Default vCPUs cannot exceed maximum limit")
            }
        }).interact_text()?;

    let disk_size_gb: u64 = Input::new()
        .with_prompt("Default disk size per VM (GB)")
        .default(default_params.disk_size_gb)
        .validate_with(|input: &u64| {
            if *input <= limits.max_disk_size_per_vm {
                Ok(())
            } else {
                Err("Default disk size cannot exceed maximum limit")
            }
        }).interact_text()?;

    Ok(DefaultVmParams {
        memory_mb,
        vcpu_count,
        disk_size_gb
    })
}

fn print_config_summary(config: &ServiceConfig) {
    println!("\nConfiguration Summary:");
    println!("Base Directory: {}", config.base_dir.display());
    
    println!("\nDirectories:");
    println!("  Kernel: {}", config.directories.kernel_dir.display());
    println!("  Images: {}", config.directories.images_dir.display());
    println!("  Cloud-init: {}", config.directories.cloud_init_dir.display());
    println!("  Working: {}", config.directories.working_dir.display());

    println!("\nNetwork Configuration:");
    println!("  Bridge Interface: {}", config.network.bridge_interface);
    println!("  DHCP Range: {} - {}", config.network.dhcp_range_start, config.network.dhcp_range_end);
    println!("  Gateway: {}", config.network.gateway);
    println!("  Netmask: {}", config.network.netmask);
    println!("  Nameservers: {}", config.network.nameservers.join(", "));

    println!("\nResource Limits:");
    println!("  Max VMs: {}", config.limits.max_vms);
    println!("  Max Memory per VM: {}MB", config.limits.max_memory_per_vm);
    println!("  Max vCPUs per VM: {}", config.limits.max_vcpus_per_vm);
    println!("  Max Disk Size per VM: {}GB", config.limits.max_disk_size_per_vm);

    println!("\nDefault VM Parameters:");
    println!("  Memory: {}MB", config.default_vm_params.memory_mb);
    println!("  vCPUs: {}", config.default_vm_params.vcpu_count);
    println!("  Disk Size: {}GB", config.default_vm_params.disk_size_gb);
}
