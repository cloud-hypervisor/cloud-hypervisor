#![allow(unused)]
use std::{io::Write, path::{Path, PathBuf}, process::Command};
use crate::Distro;
use serde::Deserialize;

pub const PREP_MOUNT_POINT: &str = "/mnt/cloudimg";
pub const DEFAULT_NETPLAN_FILENAME: &str = "01-netplan-custom-config.yaml";
pub const DEFAULT_NETPLAN: &str = "/var/lib/formation/netplan/01-custom-netplan.yaml";
pub const FORMNET_BINARY: &str = "/var/lib/formation/formnet/formnet";
pub const BASE_DIRECTORY: &str  = "/var/lib/formation/vm-images";

pub const UBUNTU: &str = "https://cloud-images.ubuntu.com/jammy/20241217/jammy-server-cloudimg-amd64.img";
pub const FEDORA: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-AmazonEC2-41-1.4.x86_64.raw.xz";
pub const DEBIAN: &str = "https://cdimage.debian.org/images/cloud/bullseye/20241202-1949/debian-11-generic-amd64-20241202-1949.raw";
pub const CENTOS: &str = "https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2";
pub const ARCH: &str = "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2";
pub const ALPINE: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/generic_alpine-3.21.0-x86_64-bios-tiny-r0.qcow2";

type UtilError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>
}

#[derive(Debug, Deserialize)]
struct BlockDevice {
    name: String,
    #[serde(default)]
    children: Vec<BlockDevice>,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    size: Option<String>
}

pub fn ensure_directory<P: AsRef<Path>>(path: P) -> Result<(), UtilError> {
    if !path.as_ref().exists() {
        std::fs::create_dir_all(&path)?;
    }
    Ok(())
}

fn download_image(url: &str, dest: &str) -> Result<(), UtilError> {
    let status = Command::new("wget")
        .arg("-q")
        .arg("-O")
        .arg(dest)
        .arg(url)
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    println!("Download of {url} completed successfully");

    Ok(())
}

fn decompress_xz(src: &str, dest: &str) -> Result<(), UtilError> {
    let status = Command::new("xz")
        .arg("--decompress")
        .arg("--keep")
        .arg("--stdout")
        .arg(src)
        .output()?;

    if !status.status.success() {
        return Err(
            Box::new(
                std::io::Error::last_os_error()
            )
        )
    }

    std::fs::write(dest, status.stdout)?;

    Ok(())
}

fn convert_qcow2_to_raw(qcow2_path: &str, raw_path: &str) -> Result<(), UtilError> {
    println!("Attempting to convert {qcow2_path} from qcow to {raw_path} raw disk image");

    let status = Command::new("qemu-img")
        .args(&["convert", "-p", "-f", "qcow2", "-O", "raw", qcow2_path, raw_path])
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    Ok(())
}

pub async fn fetch_and_prepare_images() -> Result<(), UtilError> {
    write_default_netplan()?;
    let base = PathBuf::from(BASE_DIRECTORY);
    let urls = [
        (UBUNTU, base.join("ubuntu/22.04/base.img")),
        /*
        (FEDORA, base.join("fedora/41/base.raw.xz")),
        (DEBIAN, base.join("debian/11/base.raw")), 
        (CENTOS, base.join("centos/8/base.img")),
        (ARCH, base.join("arch/latest/base.img")), 
        (ALPINE, base.join("alpine/3.21/base.img"))
        */
    ];

    let mut handles = Vec::new();

    for (url, dest) in urls {
        handles.push(tokio::spawn(async move {
            let dest_string = dest.display().to_string();
            let dest_dir = dest.parent().ok_or(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unable to find parent for destination..."
                )
            )?;
            ensure_directory(dest_dir)?;
            download_image(url, &dest_string)?;
            if dest_string.ends_with(".img") {
                convert_qcow2_to_raw(&dest_string, &dest.parent().ok_or(
                    Box::new(
                        std::io::Error::new(
                            std::io::ErrorKind::Other, 
                            "Conversion from qcow2 to raw failed: destination has no parent"
                        )
                    ) as Box<dyn std::error::Error + Send + Sync + 'static>
                )?.join("base.raw").display().to_string())?;
            } else if dest_string.ends_with(".xz") {
                decompress_xz(&dest_string, &dest.parent().ok_or(
                    Box::new(
                        std::io::Error::new(
                            std::io::ErrorKind::Other, 
                            "Decompression of xz failed: destination has no parent"
                        )
                    ) as Box<dyn std::error::Error + Send + Sync + 'static>
                )?.join("base.raw").display().to_string())?;
            } else if dest_string.ends_with(".raw") {} else {
                return Err(
                    Box::new(
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("disk format is not valid: {}", dest.display())
                        )
                    ) as Box<dyn std::error::Error + Send + Sync + 'static>
                )
            }

            Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
        }));
    }

    for handle in handles {
        let _ = handle.await?;
    }

    println!("Base images acquired and placed in /var/lib/formation/vm-images");

    let base_imgs = [
        base.join("ubuntu/22.04/base.raw"),
        /*
        base.join("fedora/41/base.raw"),
        base.join("debian/11/base.raw"),
        base.join("centos/8/base.raw"),
        base.join("arch/latest/base.raw"),
        base.join("alpine/3.21/base.raw"),
        */
    ];

    for img in base_imgs {
        let loop_device = get_image_loop_device(&img.display().to_string())?;
        let netplan_to = PathBuf::from(PREP_MOUNT_POINT).join("etc/netplan").join(DEFAULT_NETPLAN_FILENAME);
        println!("Where to copy netplan config to: {}", netplan_to.display());

        mount_partition(
            &loop_device,
            1
        )?; 
        copy_default_netplan(
            &PathBuf::from(
                netplan_to
            )
        )?;
        copy_formnet_client(
            &PathBuf::from(
                PREP_MOUNT_POINT
            ).join("usr/local/bin/")
            .join("formnet")
            .display().to_string()
        )?;
        unmount_partition()?;
        departition_loop_device(&loop_device)?;
    }

    Ok(())
}

pub fn copy_disk_image(
    distro: Distro,
    version: &str,
    instance_id: &str,
    node_id: &str
) -> Result<(), UtilError> {
    let base_path = PathBuf::from(BASE_DIRECTORY).join(distro.to_string()).join(version).join("base.raw");
    let dest_path = PathBuf::from(BASE_DIRECTORY).join(node_id).join(format!("{}.raw", instance_id));

    ensure_directory(
        dest_path.parent().ok_or(
            Box::new(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Destination path has no parent"
                )
            )
        )?
    )?;

    std::fs::copy(
        base_path,
        dest_path
    )?;

    Ok(())
}

fn copy_default_netplan(to: impl AsRef<Path>) -> Result<(), UtilError> {
    println!("Attempting to copy default netplan to {}", to.as_ref().display());
    let parent = to.as_ref().parent().ok_or(
        Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unable to find parent of netplan directory"
            )
        )
    )?;

    std::fs::create_dir_all(&parent)?;
    std::fs::copy(
        DEFAULT_NETPLAN,
        &to
    )?;

    println!("Successfully copied default netplan to {}", to.as_ref().display());

    Ok(())
}

fn write_default_netplan() -> Result<(), UtilError> {
    println!("Attempting to write default netplan to {}", DEFAULT_NETPLAN);
    let netplan_string = r#"network:
  version: 2
  renderer: networkd

  ethernets:
    rename-this-nic:
      match:
        name: "en*"
      set-name: eth0
      dhcp4: true
    "#;

    let netplan_path = PathBuf::from(DEFAULT_NETPLAN);
    let netplan_path = netplan_path.parent().ok_or(
        Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Netplan default path has no parent"
            )
        )
    )?;

    ensure_directory(netplan_path)?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(DEFAULT_NETPLAN)?;

    file.write_all(netplan_string.as_bytes())?;

    println!("Successfully wrote default netplan to {}", DEFAULT_NETPLAN);
    Ok(())
}

fn copy_formnet_client(to: &str) -> Result<(), UtilError> {
    println!("Attempting to copy formnet binary from {FORMNET_BINARY} to {to}");

    std::fs::copy(
        FORMNET_BINARY,
        to
    )?;

    println!("Succesfully copied formnet binary from {FORMNET_BINARY} to {to}");
    Ok(())
}

pub fn ensure_bridge_exists() -> Result<(), UtilError> {
    if !brctl::BridgeController::check_bridge_exists("br0")? {
        brctl::BridgeController::create_bridge("br0")?;
    }

    Ok(())
}


pub fn add_tap_to_bridge(tap: &str) -> Result<brctl::Bridge, UtilError> {
    let bridge = if let Some(bridge) = brctl::BridgeController::get_bridge("br0")? {
        bridge
    } else {
        ensure_bridge_exists()?;
        add_tap_to_bridge(tap)?
    };

    bridge.add_interface(tap)?;

    Ok(bridge)

}

fn get_image_loop_device(image_path: &str) -> Result<String, UtilError> {
    println!("Getting loop device from {image_path}");
    let output = Command::new("sudo")
        .args(["losetup", "--partscan", "--find", "--show", image_path])
        .output()?;
    if !output.status.success() {
        return Err(Box::new(std::io::Error::last_os_error()))
    }
    let loop_device = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("Found {} is located at loop device {}", image_path, loop_device);
    Ok(loop_device)
}

fn mount_partition(loop_device: &str, partition_idx: u8) -> Result<(), UtilError> {
    println!("Ensuring {} exists...", PREP_MOUNT_POINT);
    std::fs::create_dir_all(PREP_MOUNT_POINT)?;

    let partition = format!("/dev/{}", get_fs_partition(loop_device)?);
    println!("Using partition {}", partition);

    let status = Command::new("sudo")
        .args(["mount", &partition, PREP_MOUNT_POINT])
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    println!("Successfully mounted partition");
    Ok(())
}

fn unmount_partition() -> Result<(), UtilError> {
    let status = Command::new("sudo")
        .args(["umount", PREP_MOUNT_POINT])
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    println!("Successfully unmounted partition");
    Ok(())
}

fn departition_loop_device(loop_device: &str) -> Result<(), UtilError> {
    let status = std::process::Command::new("sudo")
        .args(["losetup", "-d", loop_device])
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    println!("Successfully departitioned loop device {loop_device}");
    Ok(())
}

pub fn copy_distro_base(distro: Distro, version: &str, name: &str) -> Result<String, UtilError> {
    let instance_disk_directory = PathBuf::from(BASE_DIRECTORY).join(name);
    std::fs::create_dir_all(
        instance_disk_directory.clone()
    )?;

    std::fs::copy(
        distro.rootfs_disk_path(version),
        instance_disk_directory.join("disk.raw")
    )?;

    return Ok(instance_disk_directory.join("disk.raw").display().to_string())
}

pub fn get_fs_partition(loop_device: &str) -> Result<String, UtilError> {
    let output = std::process::Command::new("sudo")
        .args(["lsblk", "--json", loop_device])
        .output()?;

    let lsblk_output: LsblkOutput = serde_json::from_slice(&output.stdout)?;

    let root_device = &lsblk_output.blockdevices[0];

    let mut fs: &str = &format!("{}p1", loop_device);
    let mut largest: Option<u128> = None;

    for child in &root_device.children {
        let partition_name = &child.name;
        let size = child.size.as_deref().unwrap_or("unknown");
        println!("Partition: {partition_name}, Size: {size}");
        let size_in_bytes = {
            if let Ok(n) = try_convert_size_to_bytes(size) {
                Some(n)
            } else { 
                None
            }
        };

        if let Some(s) = size_in_bytes {
            if let Some(n) = largest {
                if s > n {
                    largest = Some(s);
                    fs = partition_name;
                }
            } else {
                largest = Some(s);
                fs = partition_name;
            }
        }
    }

    return Ok(fs.to_string())
}

pub fn try_convert_size_to_bytes(size: &str) -> Result<u128, UtilError> {
    let mut chars: Vec<char>  = size.chars().collect();
    let suffix = chars.pop().ok_or(
        Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "size not available"
            )
        )
    )?;

    let num: f64 = {
        let size: String = chars.iter().collect();
        let num: f64 = size.parse()?;
        num
    };

    let num_bytes = match String::from(suffix).to_lowercase().as_str() {
        "t" => {
            let nb = num * 1_000_000_000_000.0;
            nb as u128
        }
        "g" => {
            let nb = num * 1_000_000_000.0;
            nb as u128
        }
        "m" => {
            let nb = num * 1_000_000.0;
            nb as u128
        }
        "k" => {
            let nb = num * 1_000.0;
            nb as u128
        }
        _ => {
            return Err(
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to convert size"
                    )
                )
            )
        }
    };

    Ok(num_bytes)
}
