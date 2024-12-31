use std::{io::Write, path::{Path, PathBuf}, process::Command};
use crate::Distro;

pub const PREP_MOUNT_POINT: &str = "/mnt/cloudimg";
pub const DEFAULT_NETPLAN: &str = "/var/lib/formation/netplan/01-custom-netplan.yaml";
pub const FORMNET_BINARY: &str = "/var/lib/formation/formnet/formnet";
pub const BASE_DIRECTORY: &str  = "/var/lib/formation/vm-images";
pub const UBUNTU: &str = "https://cloud-images.ubuntu.com/jammy/20241217/jammy-server-cloudimg-amd64.img";
pub const FEDORA: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-AmazonEC2-41-1.4.x86_64.raw.xz";
pub const DEBIAN: &str = "https://cdimage.debian.org/images/cloud/bullseye/20241202-1949/debian-11-generic-amd64-20241202-1949.raw";
pub const CENTOS: &str = "https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2";
pub const ARCH: &str = "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2";
pub const ALPINE: &str = "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/generic_alpine-3.21.0-x86_64-bios-tiny-r0.qcow2";

pub fn ensure_directory<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
    if !path.as_ref().exists() {
        std::fs::create_dir_all(&path)?;
    }
    Ok(())
}

fn download_image(url: &str, dest: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("wget")
        .arg("-O")
        .arg(dest)
        .arg(url)
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    Ok(())
}

fn decompress_xz(src: &str, dest: &str) -> Result<(), Box<dyn std::error::Error>> {
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

fn convert_qcow2_to_raw(qcow2_path: &str, raw_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("qemu-img")
        .args(&["convert", "-f", "qcow2", "-O", "raw", qcow2_path, raw_path])
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    Ok(())
}

pub fn fetch_and_prepare_images() -> Result<(), Box<dyn std::error::Error>> {
    let base = PathBuf::from(BASE_DIRECTORY);
    let urls = [
        (UBUNTU, base.join("ubuntu/22.04/base.img")),
        (FEDORA, base.join("fedora/41/base.raw.xz")),
        (DEBIAN, base.join("debian/11/base.raw")), 
        (CENTOS, base.join("centos/8/base.img")),
        (ARCH, base.join("arch/latest/base.img")), 
        (ALPINE, base.join("alpine/3.21/base.img"))
    ];

    for (url, dest) in urls {
        let dest_string = dest.display().to_string();
        ensure_directory(dest.clone())?;
        download_image(url, &dest_string)?;
        if dest.ends_with(".img") {
            convert_qcow2_to_raw(&dest_string, &dest.parent().ok_or(
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Conversion from qcow2 to raw failed: destination has no parent"))
            )?.join("base.raw").display().to_string())?;
        } else if dest.ends_with(".xz") {
            decompress_xz(&dest_string, &dest.parent().ok_or(
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Decompression of xz failed: destination has no parent"))
            )?.join("base.raw").display().to_string())?;
        } else if dest.ends_with("raw") {
            continue;
        } else {
            return Err(
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("disk format is not valid: {}", dest.display())
                    )
                )
            )
        }
    }

    println!("Base images acquired and placed in /var/lib/formation/vm-images");

    Ok(())
}

pub fn copy_disk_image(distro: Distro, version: &str) -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}

fn copy_default_netplan(to: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::copy(
        DEFAULT_NETPLAN,
        to
    )?;

    Ok(())
}

fn write_default_netplan() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(DEFAULT_NETPLAN)?;

    file.write_all(netplan_string.as_bytes())?;

    Ok(())
}

fn get_formnet_client() -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}

fn copy_formnet_client(to: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::copy(
        FORMNET_BINARY,
        to
    )?;

    Ok(())
}

pub fn ensure_bridge_exists() -> Result<(), Box<dyn std::error::Error>> {
    if !brctl::BridgeController::check_bridge_exists("br0")? {
        brctl::BridgeController::create_bridge("br0")?;
    }

    Ok(())
}


pub fn add_tap_to_bridge(tap: &str) -> Result<brctl::Bridge, Box<dyn std::error::Error>> {
    let bridge = if let Some(bridge) = brctl::BridgeController::get_bridge("br0")? {
        bridge
    } else {
        ensure_bridge_exists()?;
        add_tap_to_bridge(tap)?
    };

    bridge.add_interface(tap)?;

    Ok(bridge)

}

fn mount_image(image_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("losetup")
        .args(["--partscan", "--find", "--show", image_path])
        .output()?;
    if !output.status.success() {
        return Err(Box::new(std::io::Error::last_os_error()))
    }
    let loop_device = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(loop_device)
}

fn mount_partition(loop_device: &str, partition_idx: u8) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(PREP_MOUNT_POINT)?;
    let partition = format!("{}p{}", loop_device, partition_idx);
    let status = Command::new("mount")
        .args([&partition, PREP_MOUNT_POINT])
        .status()?;

    if !status.success() {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    Ok(())
}
