// Copyright © 2023 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use api_client::simple_api_command;
use api_client::simple_api_command_with_fds;
use api_client::simple_api_full_command;
use api_client::simple_api_full_command_with_fds;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicI32;

const SNAPSHOT_DIR: &str = "/tmp/chv-snapshot";
const API_SOCKET_PATH: &str = "/tmp/chv";

static MEM_FD: AtomicI32 = AtomicI32::new(0);

fn create_and_boot_vm() -> Result<(), String> {
    let mut socket = UnixStream::connect(API_SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to socket: {e}"))?;

    let vm_config = r#"{
        "cpus":{"boot_vcpus": 4, "max_vcpus": 4},
        "memory":{
            "size": 0,
            "zones": [{"id": "mem0", "size": 536870912, "shared": true, "fd": -1}]
        },
        "console": {"mode": "Off"},
        "serial": {"mode": "Tty"},
        "disks":[{"path":"alpine.raw"}],
        "payload":{"kernel":"bzImage", "cmdline":"console=ttyS0 root=/dev/vda3 rw"}
    }"#;

    // Create FD.
    let fname = "/tmp/foo.memfd";
    let c_fname = std::ffi::CString::new(fname).unwrap();
    let mem_fd = unsafe { libc::memfd_create(c_fname.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(mem_fd > 0);
    assert_eq!(0, unsafe { libc::ftruncate(mem_fd, 536870912) });
    MEM_FD.store(mem_fd, std::sync::atomic::Ordering::Relaxed);

    // Create the VM.
    println!("Creating VM...");
    simple_api_full_command_with_fds(
        &mut socket,
        "PUT",
        "vm.create",
        Some(vm_config),
        vec![mem_fd],
    )
    .map_err(|e| format!("Failed to create VM: {}", e))?;
    println!("VM created successfully.");

    // Boot the VM.
    println!("Booting VM...");
    simple_api_full_command(&mut socket, "PUT", "vm.boot", None)
        .map_err(|e| format!("Failed to boot VM: {}", e))?;

    println!("VM booted successfully.");
    Ok(())
}

fn pause_and_save_vm() -> Result<(), String> {
    let mut socket = UnixStream::connect(API_SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to socket: {e}"))?;

    simple_api_command(&mut socket, "PUT", "pause", None)
        .map_err(|e| format!("Failed to pause VM: {e}"))?;

    let _ = std::fs::remove_dir_all(SNAPSHOT_DIR)
        .map_err(|e| format!("Failed to clean '{}' dir: {e}", SNAPSHOT_DIR));
    std::fs::create_dir(SNAPSHOT_DIR)
        .map_err(|e| format!("Failed to create '{}' dir: {e}", SNAPSHOT_DIR))?;

    let snapshot_config = format!("{{\"destination_url\": \"file://{SNAPSHOT_DIR}\"}}");
    simple_api_command(&mut socket, "PUT", "snapshot", Some(&snapshot_config))
        .map_err(|e| format!("Failed to snapshot the VM:{e}"))?;

    // simple_api_command(&mut socket, "PUT", "shutdown", None)
    //    .map_err(|e| format!("Failed to shut down the VM:{e}"))?;

    simple_api_command(&mut socket, "PUT", "delete", None)
        .map_err(|e| format!("Failed to shut down the VM:{e}"))?;

    println!("VM saved successfully.");
    Ok(())
}

fn restore_and_unpause_vm() -> Result<(), String> {
    let mem_fd = MEM_FD.load(std::sync::atomic::Ordering::Relaxed);
    if mem_fd == 0 {
        println!("No memfd to restore from");
        return Ok(());
    }

    let mut socket = UnixStream::connect(API_SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to socket: {e}"))?;

    let restore_config = format!(
        "{{\"source_url\":\"file://{SNAPSHOT_DIR}\",\"prefault\":false,\"mem_fds\":[-1],\"net_fds\":null}}"
    );
    simple_api_command_with_fds(
        &mut socket,
        "PUT",
        "restore",
        Some(&restore_config),
        vec![mem_fd],
    )
    .map_err(|e| format!("Failed to restore the VM:{e}"))?;

    simple_api_command(&mut socket, "PUT", "resume", None)
        .map_err(|e| format!("Failed to resume the VM:{e}"))?;

    println!("VM restored successfully.");
    Ok(())
}

fn save_restore_vm() -> Result<(), String> {
    let started = std::time::Instant::now();
    pause_and_save_vm()?;
    restore_and_unpause_vm()?;

    println!("VM saved and restored in {:?}", started.elapsed());

    Ok(())
}

fn shutdown_vmm() -> Result<(), String> {
    let socket_path = "/tmp/chv";

    let mut socket = UnixStream::connect(socket_path)
        .map_err(|e| format!("Failed to connect to socket: {}", e))?;

    simple_api_full_command(&mut socket, "PUT", "vmm.shutdown", None)
        .map_err(|e| format!("Failed to shut down the VMM: {}", e))?;
    println!("VMM shut down.");

    Ok(())
}

fn print_usage() {
    println!("\nUsage:\n");
    println!("    1: create and boot a VM");
    println!("    2: pause, snapshot, and shut down the VM");
    println!("    3: restore and unpause the VM");
    println!("    4: shutdown the VMM");
    println!("    5: pause, snapshot, shut down, restore, unpause (time the whole cycle)");
    println!("    q: quit");
    print!("\nEnter your choice [1-5]: ");
    let _ = std::io::stdout().flush();
}

fn main() -> Result<(), String> {
    use std::io::BufRead;
    loop {
        print_usage();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();

        line = line.trim().to_owned();
        if line == "q" {
            break;
        }

        let Ok(n) = line.parse::<u8>() else {
            continue;
        };

        match n {
            1 => create_and_boot_vm()?,
            2 => pause_and_save_vm()?,
            3 => restore_and_unpause_vm()?,
            4 => shutdown_vmm()?,
            5 => save_restore_vm()?,
            _ => {}
        }
    }

    Ok(())
}
