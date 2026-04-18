// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::string::String;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};
use std::{cmp, fs, io, thread};

use test_infra::*;
use vmm_sys_util::tempdir::TempDir;

const QCOW2_INCOMPATIBLE_FEATURES_OFFSET: u64 = 72;
// 10MB is our maximum accepted overhead.
pub(crate) const MAXIMUM_VMM_OVERHEAD_KB: u32 = 10 * 1024;

// This enum exists to make it more convenient to
// implement test for both D-Bus and REST APIs.
pub(crate) enum TargetApi {
    // API socket
    HttpApi(String),
    // well known service name, object path
    DBusApi(String, String),
}

impl TargetApi {
    pub(crate) fn new_http_api(tmp_dir: &TempDir) -> Self {
        Self::HttpApi(temp_api_path(tmp_dir))
    }

    pub(crate) fn new_dbus_api(tmp_dir: &TempDir) -> Self {
        // `tmp_dir` is in the form of "/tmp/chXXXXXX"
        // and we take the `chXXXXXX` part as a unique identifier for the guest
        let id = tmp_dir.as_path().file_name().unwrap().to_str().unwrap();

        Self::DBusApi(
            format!("org.cloudhypervisor.{id}"),
            format!("/org/cloudhypervisor/{id}"),
        )
    }

    pub(crate) fn guest_args(&self) -> Vec<String> {
        match self {
            TargetApi::HttpApi(api_socket) => {
                vec![format!("--api-socket={}", api_socket.as_str())]
            }
            TargetApi::DBusApi(service_name, object_path) => {
                vec![
                    format!("--dbus-service-name={}", service_name.as_str()),
                    format!("--dbus-object-path={}", object_path.as_str()),
                ]
            }
        }
    }

    pub(crate) fn remote_args(&self) -> Vec<String> {
        // `guest_args` and `remote_args` are consistent with each other
        self.guest_args()
    }

    pub(crate) fn remote_command(&self, command: &str, arg: Option<&str>) -> bool {
        let mut cmd = Command::new(clh_command("ch-remote"));
        cmd.args(self.remote_args());
        cmd.arg(command);

        if let Some(arg) = arg {
            cmd.arg(arg);
        }

        let output = cmd.output().unwrap();
        if output.status.success() {
            true
        } else {
            eprintln!("Error running ch-remote command: {:?}", &cmd);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("stderr: {stderr}");
            false
        }
    }
}

pub(crate) fn temp_api_path(tmp_dir: &TempDir) -> String {
    String::from(
        tmp_dir
            .as_path()
            .join("cloud-hypervisor.sock")
            .to_str()
            .unwrap(),
    )
}

pub(crate) fn wait_for_virtiofsd_socket(socket: &str) {
    // Wait for virtiofds to start
    let deadline = Instant::now() + Duration::from_secs(10);
    while !Path::new(socket).exists() {
        if Instant::now() > deadline {
            panic!("virtiofsd socket did not appear within 10s");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn prepare_virtiofsd(
    tmp_dir: &TempDir,
    shared_dir: &str,
) -> (std::process::Child, String) {
    let mut workload_path = dirs::home_dir().unwrap();
    workload_path.push("workloads");

    let mut virtiofsd_path = workload_path;
    virtiofsd_path.push("virtiofsd");
    let virtiofsd_path = String::from(virtiofsd_path.to_str().unwrap());

    let virtiofsd_socket_path =
        String::from(tmp_dir.as_path().join("virtiofs.sock").to_str().unwrap());

    // Start the daemon
    let child = Command::new(virtiofsd_path.as_str())
        .args(["--shared-dir", shared_dir])
        .args(["--socket-path", virtiofsd_socket_path.as_str()])
        .args(["--cache", "never"])
        .args(["--tag", "myfs"])
        .spawn()
        .unwrap();

    wait_for_virtiofsd_socket(virtiofsd_socket_path.as_str());

    (child, virtiofsd_socket_path)
}

pub(crate) fn prepare_vubd(
    tmp_dir: &TempDir,
    blk_img: &str,
    num_queues: usize,
    rdonly: bool,
    direct: bool,
) -> (std::process::Child, String) {
    let mut workload_path = dirs::home_dir().unwrap();
    workload_path.push("workloads");

    let mut blk_file_path = workload_path;
    blk_file_path.push(blk_img);
    let blk_file_path = String::from(blk_file_path.to_str().unwrap());

    let vubd_socket_path = String::from(tmp_dir.as_path().join("vub.sock").to_str().unwrap());

    // Start the daemon
    let child = Command::new(clh_command("vhost_user_block"))
        .args([
            "--block-backend",
            format!(
                "path={blk_file_path},socket={vubd_socket_path},num_queues={num_queues},readonly={rdonly},direct={direct}"
            )
            .as_str(),
        ])
        .spawn()
        .unwrap();

    thread::sleep(std::time::Duration::new(10, 0));

    (child, vubd_socket_path)
}

pub(crate) fn temp_vsock_path(tmp_dir: &TempDir) -> String {
    String::from(tmp_dir.as_path().join("vsock").to_str().unwrap())
}

pub(crate) fn temp_event_monitor_path(tmp_dir: &TempDir) -> String {
    String::from(tmp_dir.as_path().join("event.json").to_str().unwrap())
}

// Creates the directory and returns the path.
pub(crate) fn temp_snapshot_dir_path(tmp_dir: &TempDir) -> String {
    let snapshot_dir = String::from(tmp_dir.as_path().join("snapshot").to_str().unwrap());
    std::fs::create_dir(&snapshot_dir).unwrap();
    snapshot_dir
}

pub(crate) fn temp_vmcore_file_path(tmp_dir: &TempDir) -> String {
    String::from(tmp_dir.as_path().join("vmcore").to_str().unwrap())
}

pub(crate) fn cloud_hypervisor_release_path() -> String {
    let mut workload_path = dirs::home_dir().unwrap();
    workload_path.push("workloads");

    let mut ch_release_path = workload_path;
    #[cfg(target_arch = "x86_64")]
    ch_release_path.push("cloud-hypervisor-static");
    #[cfg(target_arch = "aarch64")]
    ch_release_path.push("cloud-hypervisor-static-aarch64");

    ch_release_path.into_os_string().into_string().unwrap()
}

pub(crate) fn prepare_vhost_user_net_daemon(
    tmp_dir: &TempDir,
    ip: &str,
    tap: Option<&str>,
    mtu: Option<u16>,
    num_queues: usize,
    client_mode: bool,
) -> (std::process::Command, String) {
    let vunet_socket_path = String::from(tmp_dir.as_path().join("vunet.sock").to_str().unwrap());

    // Start the daemon
    let mut net_params = format!(
        "ip={ip},mask=255.255.255.128,socket={vunet_socket_path},num_queues={num_queues},queue_size=1024,client={client_mode}"
    );

    if let Some(tap) = tap {
        net_params.push_str(format!(",tap={tap}").as_str());
    }

    if let Some(mtu) = mtu {
        net_params.push_str(format!(",mtu={mtu}").as_str());
    }

    let mut command = Command::new(clh_command("vhost_user_net"));
    command.args(["--net-backend", net_params.as_str()]);

    (command, vunet_socket_path)
}

pub(crate) fn prepare_swtpm_daemon(tmp_dir: &TempDir) -> (std::process::Command, String) {
    let swtpm_tpm_dir = String::from(tmp_dir.as_path().join("swtpm").to_str().unwrap());
    let swtpm_socket_path = String::from(
        tmp_dir
            .as_path()
            .join("swtpm")
            .join("swtpm.sock")
            .to_str()
            .unwrap(),
    );
    std::fs::create_dir(&swtpm_tpm_dir).unwrap();

    let mut swtpm_command = Command::new("swtpm");
    let swtpm_args = [
        "socket",
        "--tpmstate",
        &format!("dir={swtpm_tpm_dir}"),
        "--ctrl",
        &format!("type=unixio,path={swtpm_socket_path}"),
        "--flags",
        "startup-clear",
        "--tpm2",
    ];
    swtpm_command.args(swtpm_args);

    (swtpm_command, swtpm_socket_path)
}

pub(crate) fn resize_command(
    api_socket: &str,
    desired_vcpus: Option<u8>,
    desired_ram: Option<usize>,
    desired_balloon: Option<usize>,
    event_file: Option<&str>,
) -> bool {
    let mut cmd = Command::new(clh_command("ch-remote"));
    cmd.args([&format!("--api-socket={api_socket}"), "resize"]);

    if let Some(desired_vcpus) = desired_vcpus {
        cmd.arg(format!("--cpus={desired_vcpus}"));
    }

    if let Some(desired_ram) = desired_ram {
        cmd.arg(format!("--memory={desired_ram}"));
    }

    if let Some(desired_balloon) = desired_balloon {
        cmd.arg(format!("--balloon={desired_balloon}"));
    }

    let ret = cmd.status().expect("Failed to launch ch-remote").success();

    if let Some(event_path) = event_file {
        let latest_events = [
            &MetaEvent {
                event: "resizing".to_string(),
                device_id: None,
            },
            &MetaEvent {
                event: "resized".to_string(),
                device_id: None,
            },
        ];
        // See: #5938
        thread::sleep(std::time::Duration::new(1, 0));
        assert!(check_latest_events_exact(&latest_events, event_path));
    }

    ret
}

pub(crate) fn resize_zone_command(api_socket: &str, id: &str, desired_size: &str) -> bool {
    let mut cmd = Command::new(clh_command("ch-remote"));
    cmd.args([
        &format!("--api-socket={api_socket}"),
        "resize-zone",
        &format!("--id={id}"),
        &format!("--size={desired_size}"),
    ]);

    cmd.status().expect("Failed to launch ch-remote").success()
}

pub(crate) fn resize_disk_command(api_socket: &str, id: &str, desired_size: &str) -> bool {
    let mut cmd = Command::new(clh_command("ch-remote"));
    cmd.args([
        &format!("--api-socket={api_socket}"),
        "resize-disk",
        &format!("--disk={id}"),
        &format!("--size={desired_size}"),
    ]);

    cmd.status().expect("Failed to launch ch-remote").success()
}

// setup OVS-DPDK bridge and ports
pub(crate) fn setup_ovs_dpdk() {
    // setup OVS-DPDK
    assert!(exec_host_command_status("service openvswitch-switch start").success());
    assert!(exec_host_command_status("ovs-vsctl init").success());
    assert!(
        exec_host_command_status("ovs-vsctl set Open_vSwitch . other_config:dpdk-init=true")
            .success()
    );
    assert!(exec_host_command_status("service openvswitch-switch restart").success());

    // Create OVS-DPDK bridge and ports
    assert!(
        exec_host_command_status(
            "ovs-vsctl add-br ovsbr0 -- set bridge ovsbr0 datapath_type=netdev",
        )
        .success()
    );
    assert!(exec_host_command_status("ovs-vsctl add-port ovsbr0 vhost-user1 -- set Interface vhost-user1 type=dpdkvhostuserclient options:vhost-server-path=/tmp/dpdkvhostclient1").success());
    assert!(exec_host_command_status("ovs-vsctl add-port ovsbr0 vhost-user2 -- set Interface vhost-user2 type=dpdkvhostuserclient options:vhost-server-path=/tmp/dpdkvhostclient2").success());
    assert!(exec_host_command_status("ip link set up dev ovsbr0").success());
    assert!(exec_host_command_status("service openvswitch-switch restart").success());
}

pub(crate) fn cleanup_ovs_dpdk() {
    assert!(exec_host_command_status("ovs-vsctl del-br ovsbr0").success());
    exec_host_command_status("rm -f ovs-vsctl /tmp/dpdkvhostclient1 /tmp/dpdkvhostclient2");
}

// Setup two guests and ensure they are connected through ovs-dpdk
pub(crate) fn setup_ovs_dpdk_guests(
    guest1: &Guest,
    guest2: &Guest,
    api_socket: &str,
    release_binary: bool,
) -> (Child, Child) {
    setup_ovs_dpdk();

    let clh_path = if release_binary {
        cloud_hypervisor_release_path()
    } else {
        clh_command("cloud-hypervisor")
    };

    let mut child1 = GuestCommand::new_with_binary_path(guest1, &clh_path)
                    .args(["--cpus", "boot=2"])
                    .args(["--memory", "size=0,shared=on"])
                    .args(["--memory-zone", "id=mem0,size=1G,shared=on,host_numa_node=0"])
                    .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                    .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                    .default_disks()
                    .args(["--net", guest1.default_net_string().as_str(), "vhost_user=true,socket=/tmp/dpdkvhostclient1,num_queues=2,queue_size=256,vhost_mode=server"])
                    .capture_output()
                    .spawn()
                    .unwrap();

    #[cfg(target_arch = "x86_64")]
    let guest_net_iface = "ens5";
    #[cfg(target_arch = "aarch64")]
    let guest_net_iface = "enp0s5";

    let r = std::panic::catch_unwind(|| {
        guest1.wait_vm_boot().unwrap();

        guest1
            .ssh_command(&format!(
                "sudo ip addr add 172.100.0.1/24 dev {guest_net_iface}"
            ))
            .unwrap();
        guest1
            .ssh_command(&format!("sudo ip link set up dev {guest_net_iface}"))
            .unwrap();

        let guest_ip = guest1.network.guest_ip0.clone();
        thread::spawn(move || {
            ssh_command_ip(
                "nc -l 12345",
                &guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
            .unwrap();
        });
    });
    if r.is_err() {
        cleanup_ovs_dpdk();

        let _ = child1.kill();
        let output = child1.wait_with_output().unwrap();
        handle_child_output(r, &output);
        panic!("Test should already be failed/panicked"); // To explicitly mark this block never return
    }

    let mut child2 = GuestCommand::new_with_binary_path(guest2, &clh_path)
                    .args(["--api-socket", api_socket])
                    .args(["--cpus", "boot=2"])
                    .args(["--memory", "size=0,shared=on"])
                    .args(["--memory-zone", "id=mem0,size=1G,shared=on,host_numa_node=0"])
                    .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
                    .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
                    .default_disks()
                    .args(["--net", guest2.default_net_string().as_str(), "vhost_user=true,socket=/tmp/dpdkvhostclient2,num_queues=2,queue_size=256,vhost_mode=server"])
                    .capture_output()
                    .spawn()
                    .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest2.wait_vm_boot().unwrap();

        guest2
            .ssh_command(&format!(
                "sudo ip addr add 172.100.0.2/24 dev {guest_net_iface}"
            ))
            .unwrap();
        guest2
            .ssh_command(&format!("sudo ip link set up dev {guest_net_iface}"))
            .unwrap();

        // Check the connection works properly between the two VMs
        guest2.ssh_command("nc -vz 172.100.0.1 12345").unwrap();
    });
    if r.is_err() {
        cleanup_ovs_dpdk();

        let _ = child1.kill();
        let _ = child2.kill();
        let output = child2.wait_with_output().unwrap();
        handle_child_output(r, &output);
        panic!("Test should already be failed/panicked"); // To explicitly mark this block never return
    }

    (child1, child2)
}

pub enum FwType {
    Ovmf,
    RustHypervisorFirmware,
}

pub(crate) fn fw_path(_fw_type: FwType) -> String {
    let mut workload_path = dirs::home_dir().unwrap();
    workload_path.push("workloads");

    let mut fw_path = workload_path;
    #[cfg(target_arch = "aarch64")]
    fw_path.push("CLOUDHV_EFI.fd");
    #[cfg(target_arch = "x86_64")]
    {
        match _fw_type {
            FwType::Ovmf => fw_path.push(OVMF_NAME),
            FwType::RustHypervisorFirmware => fw_path.push("hypervisor-fw"),
        }
    }

    fw_path.to_str().unwrap().to_string()
}

// Parse the event_monitor file based on the format that each event
// is followed by a double newline
fn parse_event_file(event_file: &str) -> Vec<serde_json::Value> {
    let content = fs::read(event_file).unwrap();
    let mut ret = Vec::new();
    for entry in String::from_utf8_lossy(&content)
        .trim()
        .split("\n\n")
        .collect::<Vec<&str>>()
    {
        ret.push(serde_json::from_str(entry).unwrap());
    }

    ret
}

// Return true if all events from the input 'expected_events' are matched sequentially
// with events from the 'event_file'
pub(crate) fn check_sequential_events(expected_events: &[&MetaEvent], event_file: &str) -> bool {
    if !Path::new(event_file).exists() {
        return false;
    }
    let json_events = parse_event_file(event_file);
    let len = expected_events.len();
    let mut idx = 0;
    for e in &json_events {
        if idx == len {
            break;
        }
        if expected_events[idx].match_with_json_event(e) {
            idx += 1;
        }
    }

    let ret = idx == len;

    if !ret {
        eprintln!(
            "\n\n==== Start 'check_sequential_events' failed ==== \
             \n\nexpected_events={expected_events:?}\nactual_events={json_events:?} \
             \n\n==== End 'check_sequential_events' failed ====",
        );
    }

    ret
}

// Return true if all events from the input 'expected_events' are matched exactly
// with events from the 'event_file'
pub(crate) fn check_sequential_events_exact(
    expected_events: &[&MetaEvent],
    event_file: &str,
) -> bool {
    if !Path::new(event_file).exists() {
        return false;
    }
    let json_events = parse_event_file(event_file);
    if expected_events.len() > json_events.len() {
        return false;
    }
    let json_events = &json_events[..expected_events.len()];

    for (idx, e) in json_events.iter().enumerate() {
        if !expected_events[idx].match_with_json_event(e) {
            eprintln!(
                "\n\n==== Start 'check_sequential_events_exact' failed ==== \
                 \n\nexpected_events={expected_events:?}\nactual_events={json_events:?} \
                 \n\n==== End 'check_sequential_events_exact' failed ====",
            );

            return false;
        }
    }

    true
}

// Return true if events from the input 'latest_events' are matched exactly
// with the most recent events from the 'event_file'
pub(crate) fn check_latest_events_exact(latest_events: &[&MetaEvent], event_file: &str) -> bool {
    if !Path::new(event_file).exists() {
        return false;
    }
    let json_events = parse_event_file(event_file);
    if latest_events.len() > json_events.len() {
        return false;
    }
    let json_events = &json_events[(json_events.len() - latest_events.len())..];

    for (idx, e) in json_events.iter().enumerate() {
        if !latest_events[idx].match_with_json_event(e) {
            eprintln!(
                "\n\n==== Start 'check_latest_events_exact' failed ==== \
                 \n\nexpected_events={latest_events:?}\nactual_events={json_events:?} \
                 \n\n==== End 'check_latest_events_exact' failed ====",
            );

            return false;
        }
    }

    true
}

pub(super) fn get_msi_interrupt_pattern() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        "PCI-MSI".to_string()
    }
    #[cfg(target_arch = "aarch64")]
    {
        if cfg!(feature = "mshv") {
            "GICv2m-PCI-MSIX".to_string()
        } else {
            "ITS-PCI-MSIX".to_string()
        }
    }
}

pub(super) type PrepareNetDaemon = dyn Fn(
    &TempDir,
    &str,
    Option<&str>,
    Option<u16>,
    usize,
    bool,
) -> (std::process::Command, String);

pub(super) fn get_ksm_pages_shared() -> u32 {
    fs::read_to_string("/sys/kernel/mm/ksm/pages_shared")
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap()
}

fn _get_vmm_overhead(pid: u32, guest_memory_size: u32) -> HashMap<String, u32> {
    let smaps = fs::File::open(format!("/proc/{pid}/smaps")).unwrap();
    let reader = io::BufReader::new(smaps);

    let mut skip_map: bool = false;
    let mut region_name: String = String::new();
    let mut region_maps = HashMap::new();
    for line in reader.lines() {
        let l = line.unwrap();

        if l.contains('-') {
            let values: Vec<&str> = l.split_whitespace().collect();
            region_name = values.last().unwrap().trim().to_string();
            if region_name == "0" {
                region_name = "anonymous".to_string();
            }
        }

        // Each section begins with something that looks like:
        // Size:               2184 kB
        if l.starts_with("Size:") {
            let values: Vec<&str> = l.split_whitespace().collect();
            let map_size = values[1].parse::<u32>().unwrap();
            // We skip the assigned guest RAM map, its RSS is only
            // dependent on the guest actual memory usage.
            // Everything else can be added to the VMM overhead.
            skip_map = map_size >= guest_memory_size;
            continue;
        }

        // If this is a map we're taking into account, then we only
        // count the RSS. The sum of all counted RSS is the VMM overhead.
        if !skip_map && l.starts_with("Rss:") {
            let values: Vec<&str> = l.split_whitespace().collect();
            let value = values[1].trim().parse::<u32>().unwrap();
            *region_maps.entry(region_name.clone()).or_insert(0) += value;
        }
    }

    region_maps
}

pub(crate) fn get_vmm_overhead(pid: u32, guest_memory_size: u32) -> u32 {
    let mut total = 0;

    for (region_name, value) in &_get_vmm_overhead(pid, guest_memory_size) {
        eprintln!("{region_name}: {value}");
        total += value;
    }

    total
}

pub(crate) fn process_rss_kib(pid: u32) -> usize {
    let command = format!("ps -q {pid} -o rss=");
    let rss = exec_host_command_output(&command);
    String::from_utf8_lossy(&rss.stdout).trim().parse().unwrap()
}

#[derive(PartialEq, Eq, PartialOrd)]
pub struct Counters {
    rx_bytes: u64,
    rx_frames: u64,
    tx_bytes: u64,
    tx_frames: u64,
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
}

pub(crate) fn get_counters(api_socket: &str) -> Counters {
    // Get counters
    let (cmd_success, cmd_output, _) = remote_command_w_output(api_socket, "counters", None);
    assert!(cmd_success);

    let counters: HashMap<&str, HashMap<&str, u64>> =
        serde_json::from_slice(&cmd_output).unwrap_or_default();

    let rx_bytes = *counters.get("_net2").unwrap().get("rx_bytes").unwrap();
    let rx_frames = *counters.get("_net2").unwrap().get("rx_frames").unwrap();
    let tx_bytes = *counters.get("_net2").unwrap().get("tx_bytes").unwrap();
    let tx_frames = *counters.get("_net2").unwrap().get("tx_frames").unwrap();

    let read_bytes = *counters.get("_disk0").unwrap().get("read_bytes").unwrap();
    let write_bytes = *counters.get("_disk0").unwrap().get("write_bytes").unwrap();
    let read_ops = *counters.get("_disk0").unwrap().get("read_ops").unwrap();
    let write_ops = *counters.get("_disk0").unwrap().get("write_ops").unwrap();

    Counters {
        rx_bytes,
        rx_frames,
        tx_bytes,
        tx_frames,
        read_bytes,
        write_bytes,
        read_ops,
        write_ops,
    }
}

pub(super) fn pty_read(mut pty: std::fs::File) -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        loop {
            thread::sleep(std::time::Duration::new(1, 0));
            let mut buf = [0; 512];
            match pty.read(&mut buf) {
                Ok(_bytes) => {
                    let output = std::str::from_utf8(&buf).unwrap().to_string();
                    match tx.send(output) {
                        Ok(_) => (),
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

pub(crate) fn get_pty_path(api_socket: &str, pty_type: &str) -> PathBuf {
    let (cmd_success, cmd_output, _) = remote_command_w_output(api_socket, "info", None);
    assert!(cmd_success);
    let info: serde_json::Value = serde_json::from_slice(&cmd_output).unwrap_or_default();
    assert_eq!("Pty", info["config"][pty_type]["mode"]);
    PathBuf::from(
        info["config"][pty_type]["file"]
            .as_str()
            .expect("Missing pty path"),
    )
}

// VFIO test network setup.
// We reserve a different IP class for it: 172.18.0.0/24.
#[cfg(target_arch = "x86_64")]
pub(crate) fn setup_vfio_network_interfaces() {
    // 'vfio-br0'
    assert!(exec_host_command_status("sudo ip link add name vfio-br0 type bridge").success());
    assert!(exec_host_command_status("sudo ip link set vfio-br0 up").success());
    assert!(exec_host_command_status("sudo ip addr add 172.18.0.1/24 dev vfio-br0").success());
    // 'vfio-tap0'
    assert!(exec_host_command_status("sudo ip tuntap add vfio-tap0 mode tap").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap0 master vfio-br0").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap0 up").success());
    // 'vfio-tap1'
    assert!(exec_host_command_status("sudo ip tuntap add vfio-tap1 mode tap").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap1 master vfio-br0").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap1 up").success());
    // 'vfio-tap2'
    assert!(exec_host_command_status("sudo ip tuntap add vfio-tap2 mode tap").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap2 master vfio-br0").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap2 up").success());
    // 'vfio-tap3'
    assert!(exec_host_command_status("sudo ip tuntap add vfio-tap3 mode tap").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap3 master vfio-br0").success());
    assert!(exec_host_command_status("sudo ip link set vfio-tap3 up").success());
}

// Tear VFIO test network down
#[cfg(target_arch = "x86_64")]
pub(crate) fn cleanup_vfio_network_interfaces() {
    assert!(exec_host_command_status("sudo ip link del vfio-br0").success());
    assert!(exec_host_command_status("sudo ip link del vfio-tap0").success());
    assert!(exec_host_command_status("sudo ip link del vfio-tap1").success());
    assert!(exec_host_command_status("sudo ip link del vfio-tap2").success());
    assert!(exec_host_command_status("sudo ip link del vfio-tap3").success());
}

pub(crate) fn balloon_size(api_socket: &str) -> u64 {
    let (cmd_success, cmd_output, _) = remote_command_w_output(api_socket, "info", None);
    assert!(cmd_success);

    let info: serde_json::Value = serde_json::from_slice(&cmd_output).unwrap_or_default();
    let total_mem = &info["config"]["memory"]["size"]
        .to_string()
        .parse::<u64>()
        .unwrap();
    let actual_mem = &info["memory_actual_size"]
        .to_string()
        .parse::<u64>()
        .unwrap();
    total_mem - actual_mem
}

pub(crate) fn vm_state(api_socket: &str) -> String {
    let (cmd_success, cmd_output, _) = remote_command_w_output(api_socket, "info", None);
    assert!(cmd_success);

    let info: serde_json::Value = serde_json::from_slice(&cmd_output).unwrap_or_default();
    let state = &info["state"].as_str().unwrap();

    state.to_string()
}

pub(crate) fn make_virtio_block_guest(factory: &GuestFactory, image_name: &str) -> Guest {
    let disk_config = UbuntuDiskConfig::new(image_name.to_string());
    factory.create_guest(Box::new(disk_config)).with_cpu(4)
}

pub(crate) fn compute_backing_checksum(
    path_or_image_name: impl AsRef<std::path::Path>,
) -> Option<(std::path::PathBuf, String, u32)> {
    let path = resolve_disk_path(path_or_image_name);

    let mut file = File::open(&path).ok()?;
    if !matches!(
        block::detect_image_type(&mut file).ok()?,
        block::ImageType::Qcow2
    ) {
        return None;
    }

    let info = get_image_info(&path)?;

    let backing_file = info["backing-filename"].as_str()?;
    let backing_path = if std::path::Path::new(backing_file).is_absolute() {
        std::path::PathBuf::from(backing_file)
    } else {
        path.parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(backing_file)
    };

    let backing_info = get_image_info(&backing_path)?;
    let backing_format = backing_info["format"].as_str()?.to_string();
    let mut file = File::open(&backing_path).ok()?;
    let file_size = file.metadata().ok()?.len();
    let checksum = compute_file_checksum(&mut file, file_size);

    Some((backing_path, backing_format, checksum))
}

/// Uses `qemu-img check` to verify disk image consistency.
///
/// Supported formats are `qcow2` (compressed and uncompressed),
/// `vhdx`, `qed`, `parallels`, `vmdk`, and `vdi`. See man page
/// for more details.
///
/// It takes either a full path to the image or just the name of
/// the image located in the `workloads` directory.
///
/// For QCOW2 images with backing files, also verifies the backing file
/// integrity and checks that the backing file hasn't been modified
/// during the test.
///
/// For QCOW2 v3 images, also verifies the dirty bit is cleared.
pub(crate) fn disk_check_consistency(
    path_or_image_name: impl AsRef<std::path::Path>,
    initial_backing_checksum: Option<(std::path::PathBuf, String, u32)>,
) {
    let path = resolve_disk_path(path_or_image_name);
    let output = run_qemu_img(&path, &["check"], None);

    assert!(
        output.status.success(),
        "qemu-img check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    match check_dirty_flag(&path) {
        Ok(Some(dirty)) => {
            assert!(!dirty, "QCOW2 image shutdown unclean");
        }
        Ok(None) => {} // Not a QCOW2 v3 image, skip dirty flag check
        Err(e) => panic!("Failed to check dirty flag: {e}"),
    }

    if let Some((backing_path, format, initial_checksum)) = initial_backing_checksum {
        if format.parse::<block::qcow::ImageType>().ok() != Some(block::qcow::ImageType::Raw) {
            let output = run_qemu_img(&backing_path, &["check"], None);

            assert!(
                output.status.success(),
                "qemu-img check of backing file failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let mut file = File::open(&backing_path).unwrap();
        let file_size = file.metadata().unwrap().len();
        assert_eq!(
            initial_checksum,
            compute_file_checksum(&mut file, file_size)
        );
    }
}

pub(crate) fn run_qemu_img(
    path: &std::path::Path,
    args: &[&str],
    trailing_args: Option<&[&str]>,
) -> std::process::Output {
    let mut cmd = std::process::Command::new("qemu-img");
    cmd.arg(args[0])
        .args(&args[1..])
        .arg(path.to_str().unwrap());
    if let Some(extra) = trailing_args {
        cmd.args(extra);
    }
    cmd.output().unwrap()
}

fn get_image_info(path: &std::path::Path) -> Option<serde_json::Value> {
    let output = run_qemu_img(path, &["info", "-U", "--output=json"], None);

    output.status.success().then_some(())?;
    serde_json::from_slice(&output.stdout).ok()
}

fn get_qcow2_v3_info(path: &Path) -> Result<Option<serde_json::Value>, String> {
    let info = get_image_info(path)
        .ok_or_else(|| format!("qemu-img info failed for {}", path.display()))?;
    if info["format"].as_str() != Some("qcow2") {
        return Ok(None);
    }
    // QCOW2 v3 has compat "1.1", v2 has "0.10"
    if info["format-specific"]["data"]["compat"].as_str() != Some("1.1") {
        return Ok(None);
    }
    Ok(Some(info))
}

pub(crate) fn check_dirty_flag(path: &Path) -> Result<Option<bool>, String> {
    Ok(get_qcow2_v3_info(path)?.and_then(|info| info["dirty-flag"].as_bool()))
}

pub(crate) fn check_corrupt_flag(path: &Path) -> Result<Option<bool>, String> {
    Ok(get_qcow2_v3_info(path)?
        .and_then(|info| info["format-specific"]["data"]["corrupt"].as_bool()))
}

pub(crate) fn set_corrupt_flag(path: &Path, corrupt: bool) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    file.seek(SeekFrom::Start(QCOW2_INCOMPATIBLE_FEATURES_OFFSET))?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    let mut features = u64::from_be_bytes(buf);

    if corrupt {
        features |= 0x02;
    } else {
        features &= !0x02;
    }

    file.seek(SeekFrom::Start(QCOW2_INCOMPATIBLE_FEATURES_OFFSET))?;
    file.write_all(&features.to_be_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn resolve_disk_path(path_or_image_name: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    if path_or_image_name.as_ref().exists() {
        // A full path is provided
        path_or_image_name.as_ref().to_path_buf()
    } else {
        // An image name is provided
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");
        workload_path.as_path().join(path_or_image_name.as_ref())
    }
}

pub(crate) fn compute_file_checksum(reader: &mut dyn std::io::Read, size: u64) -> u32 {
    // Read first 16MB or entire data if smaller
    let read_size = cmp::min(size, 16 * 1024 * 1024) as usize;

    let mut buffer = vec![0u8; read_size];
    reader.read_exact(&mut buffer).unwrap();

    // DJB2 hash
    let mut hash: u32 = 5381;
    for byte in buffer.iter() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u32);
    }
    hash
}

pub(crate) fn get_reboot_count(guest: &Guest) -> u32 {
    guest
        .ssh_command("sudo last | grep -c reboot")
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap_or_default()
}

pub(crate) fn enable_guest_watchdog(guest: &Guest, watchdog_sec: u32) {
    // Check for PCI device
    assert!(
        guest
            .does_device_vendor_pair_match("0x1063", "0x1af4")
            .unwrap_or_default()
    );

    // Enable systemd watchdog
    guest
        .ssh_command(&format!(
            "echo RuntimeWatchdogSec={watchdog_sec}s | sudo tee -a /etc/systemd/system.conf"
        ))
        .unwrap();

    guest.ssh_command("sudo systemctl daemon-reexec").unwrap();
}

pub(crate) fn make_guest_panic(guest: &Guest) {
    // Check for pvpanic device
    assert!(
        guest
            .does_device_vendor_pair_match("0x0011", "0x1b36")
            .unwrap_or_default()
    );

    // Trigger guest a panic
    guest.ssh_command("screen -dmS reboot sh -c \"sleep 5; echo s | tee /proc/sysrq-trigger; echo c | sudo tee /proc/sysrq-trigger\"").unwrap();
}

/// Extracts a BDF from a CHV returned response
pub(crate) fn bdf_from_hotplug_response(
    s: &str,
) -> (
    u16, /* Segment ID */
    u8,  /* Bus ID */
    u8,  /* Device ID */
    u8,  /* Function ID */
) {
    let json: serde_json::Value = serde_json::from_str(s).expect("should be valid JSON");
    let bdf_str = json["bdf"]
        .as_str()
        .expect("should contain string key `bdf`");

    // BDF format: "SSSS:BB:DD.F"
    let parts: Vec<&str> = bdf_str.split(&[':', '.'][..]).collect();
    assert_eq!(parts.len(), 4, "unexpected BDF format: {bdf_str}");

    let segment_id = u16::from_str_radix(parts[0], 16).unwrap();
    let bus_id = u8::from_str_radix(parts[1], 16).unwrap();
    let device_id = u8::from_str_radix(parts[2], 16).unwrap();
    let function_id = u8::from_str_radix(parts[3], 16).unwrap();

    (segment_id, bus_id, device_id, function_id)
}
