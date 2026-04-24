// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::process::{Child, Command, Stdio};
use std::thread;

use test_infra::*;
use wait_timeout::ChildExt;

use super::utils::cleanup_ovs_dpdk;

pub(crate) fn start_live_migration(
    migration_socket: &str,
    src_api_socket: &str,
    dest_api_socket: &str,
    local: bool,
) -> bool {
    // Start to receive migration from the destination VM
    let mut receive_migration = Command::new(clh_command("ch-remote"))
        .args([
            &format!("--api-socket={dest_api_socket}"),
            "receive-migration",
            &format! {"unix:{migration_socket}"},
        ])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // Give it '1s' to make sure the 'migration_socket' file is properly created
    thread::sleep(std::time::Duration::new(1, 0));
    // Start to send migration from the source VM

    let args = [
        format!("--api-socket={}", &src_api_socket),
        "send-migration".to_string(),
        format!(
            "destination_url=unix:{migration_socket},local={}",
            if local { "on" } else { "off" }
        ),
    ]
    .to_vec();

    let mut send_migration = Command::new(clh_command("ch-remote"))
        .args(&args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // The 'send-migration' command should be executed successfully within the given timeout
    let send_success = if let Some(status) = send_migration
        .wait_timeout(std::time::Duration::from_secs(30))
        .unwrap()
    {
        status.success()
    } else {
        false
    };

    if !send_success {
        let _ = send_migration.kill();
        let output = send_migration.wait_with_output().unwrap();
        eprintln!(
            "\n\n==== Start 'send_migration' output ==== \
            \n\n---stdout---\n{}\n\n---stderr---\n{} \
            \n\n==== End 'send_migration' output ====\n\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // The 'receive-migration' command should be executed successfully within the given timeout
    let receive_success = if let Some(status) = receive_migration
        .wait_timeout(std::time::Duration::from_secs(30))
        .unwrap()
    {
        status.success()
    } else {
        false
    };

    if !receive_success {
        let _ = receive_migration.kill();
        let output = receive_migration.wait_with_output().unwrap();
        eprintln!(
            "\n\n==== Start 'receive_migration' output ==== \
            \n\n---stdout---\n{}\n\n---stderr---\n{} \
            \n\n==== End 'receive_migration' output ====\n\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    send_success && receive_success
}

pub(crate) fn print_and_panic(
    src_vm: Child,
    dest_vm: Child,
    ovs_vm: Option<Child>,
    message: &str,
) -> ! {
    let mut src_vm = src_vm;
    let mut dest_vm = dest_vm;

    let _ = src_vm.kill();
    let src_output = src_vm.wait_with_output().unwrap();
    eprintln!(
        "\n\n==== Start 'source_vm' stdout ====\n\n{}\n\n==== End 'source_vm' stdout ====",
        String::from_utf8_lossy(&src_output.stdout)
    );
    eprintln!(
        "\n\n==== Start 'source_vm' stderr ====\n\n{}\n\n==== End 'source_vm' stderr ====",
        String::from_utf8_lossy(&src_output.stderr)
    );
    let _ = dest_vm.kill();
    let dest_output = dest_vm.wait_with_output().unwrap();
    eprintln!(
        "\n\n==== Start 'destination_vm' stdout ====\n\n{}\n\n==== End 'destination_vm' stdout ====",
        String::from_utf8_lossy(&dest_output.stdout)
    );
    eprintln!(
        "\n\n==== Start 'destination_vm' stderr ====\n\n{}\n\n==== End 'destination_vm' stderr ====",
        String::from_utf8_lossy(&dest_output.stderr)
    );

    if let Some(ovs_vm) = ovs_vm {
        let mut ovs_vm = ovs_vm;
        let _ = ovs_vm.kill();
        let ovs_output = ovs_vm.wait_with_output().unwrap();
        eprintln!(
            "\n\n==== Start 'ovs_vm' stdout ====\n\n{}\n\n==== End 'ovs_vm' stdout ====",
            String::from_utf8_lossy(&ovs_output.stdout)
        );
        eprintln!(
            "\n\n==== Start 'ovs_vm' stderr ====\n\n{}\n\n==== End 'ovs_vm' stderr ====",
            String::from_utf8_lossy(&ovs_output.stderr)
        );

        cleanup_ovs_dpdk();
    }

    panic!("Test failed: {message}")
}
