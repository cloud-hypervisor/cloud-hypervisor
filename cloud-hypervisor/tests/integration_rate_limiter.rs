// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(dead_code)]
use test_infra::*;
use vmm_sys_util::tempdir::TempDir;

mod common;
use common::utils::*;

const NET_RATE_LIMITER_RUNTIME: u32 = 20;
const BLOCK_RATE_LIMITER_RUNTIME: u32 = 20;
const BLOCK_RATE_LIMITER_RAMP_TIME: u32 = 5;

// Check if the 'measured' rate is within the expected 'difference' (in percentage)
// compared to given 'limit' rate.
fn check_rate_limit(measured: f64, limit: f64, difference: f64) -> bool {
    let upper_limit = limit * (1_f64 + difference);
    let lower_limit = limit * (1_f64 - difference);

    if measured > lower_limit && measured < upper_limit {
        return true;
    }

    eprintln!(
        "\n\n==== Start 'check_rate_limit' failed ==== \
        \n\nmeasured={measured}, , lower_limit={lower_limit}, upper_limit={upper_limit} \
        \n\n==== End 'check_rate_limit' failed ====\n\n"
    );

    false
}

fn _test_rate_limiter_net(rx: bool) {
    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));

    let num_queues = 2;
    let queue_size = 256;
    let bw_size = 104857600_u64; // bytes
    let bw_refill_time = 1000; // ms
    let limit_bps = (bw_size * 8 * 1000) as f64 / bw_refill_time as f64;

    let net_params = format!(
        "tap=,mac={},ip={},mask=255.255.255.128,num_queues={},queue_size={},bw_size={},bw_one_time_burst=0,bw_refill_time={}",
        guest.network.guest_mac0,
        guest.network.host_ip0,
        num_queues,
        queue_size,
        bw_size,
        bw_refill_time,
    );

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", &format!("boot={}", num_queues / 2)])
        .args(["--memory", "size=1G"])
        .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .default_disks()
        .args(["--net", net_params.as_str()])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();
        let measured_bps = measure_virtio_net_throughput(
            NET_RATE_LIMITER_RUNTIME,
            num_queues / 2,
            &guest,
            rx,
            true,
        )
        .unwrap();
        assert!(check_rate_limit(measured_bps, limit_bps, 0.1));
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}

#[test]
fn test_rate_limiter_net_rx() {
    _test_rate_limiter_net(true);
}

#[test]
fn test_rate_limiter_net_tx() {
    _test_rate_limiter_net(false);
}

fn _test_rate_limiter_block(bandwidth: bool, num_queues: u32) {
    let fio_ops = FioOps::RandRW;

    let bw_size = if bandwidth {
        104857600_u64 // bytes
    } else {
        1000_u64 // I/O
    };
    let bw_refill_time = 1000; // ms
    let limit_rate = (bw_size * 1000) as f64 / bw_refill_time as f64;

    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);
    let test_img_dir = TempDir::new_with_prefix("/var/tmp/ch").unwrap();
    let blk_rate_limiter_test_img =
        String::from(test_img_dir.as_path().join("blk.img").to_str().unwrap());

    // Create the test block image
    assert!(
        exec_host_command_output(&format!(
            "dd if=/dev/zero of={blk_rate_limiter_test_img} bs=1M count=1024"
        ))
        .status
        .success()
    );

    let test_blk_params = if bandwidth {
        format!(
            "path={blk_rate_limiter_test_img},num_queues={num_queues},bw_size={bw_size},bw_one_time_burst=0,bw_refill_time={bw_refill_time},image_type=raw"
        )
    } else {
        format!(
            "path={blk_rate_limiter_test_img},num_queues={num_queues},ops_size={bw_size},ops_one_time_burst=0,ops_refill_time={bw_refill_time},image_type=raw"
        )
    };

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", &format!("boot={num_queues}")])
        .args(["--memory", "size=1G"])
        .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .args([
            "--disk",
            format!(
                "path={}",
                guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
            )
            .as_str(),
            format!(
                "path={}",
                guest.disk_config.disk(DiskType::CloudInit).unwrap()
            )
            .as_str(),
            test_blk_params.as_str(),
        ])
        .default_net()
        .args(["--api-socket", &api_socket])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        let fio_command = format!(
            "sudo fio --filename=/dev/vdc --name=test --output-format=json \
            --direct=1 --bs=4k --ioengine=io_uring --iodepth=64 \
            --rw={fio_ops} --runtime={BLOCK_RATE_LIMITER_RUNTIME} \
            --ramp_time={BLOCK_RATE_LIMITER_RAMP_TIME} --numjobs={num_queues}",
        );
        let output = guest.ssh_command(&fio_command).unwrap();

        // Parse fio output
        let measured_rate = if bandwidth {
            parse_fio_output(&output, &fio_ops, num_queues).unwrap()
        } else {
            parse_fio_output_iops(&output, &fio_ops, num_queues).unwrap()
        };
        assert!(check_rate_limit(measured_rate, limit_rate, 0.1));
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}

fn _test_rate_limiter_group_block(bandwidth: bool, num_queues: u32, num_disks: u32) {
    let fio_ops = FioOps::RandRW;

    let bw_size = if bandwidth {
        104857600_u64 // bytes
    } else {
        1000_u64 // I/O
    };
    let bw_refill_time = 1000; // ms
    let limit_rate = (bw_size * 1000) as f64 / bw_refill_time as f64;

    let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
    let guest = Guest::new(Box::new(disk_config));
    let api_socket = temp_api_path(&guest.tmp_dir);
    let test_img_dir = TempDir::new_with_prefix("/var/tmp/ch").unwrap();

    let rate_limit_group_arg = if bandwidth {
        format!("id=group0,bw_size={bw_size},bw_one_time_burst=0,bw_refill_time={bw_refill_time}")
    } else {
        format!(
            "id=group0,ops_size={bw_size},ops_one_time_burst=0,ops_refill_time={bw_refill_time}"
        )
    };

    let mut disk_args = vec![
        "--disk".to_string(),
        format!(
            "path={}",
            guest.disk_config.disk(DiskType::OperatingSystem).unwrap()
        ),
        format!(
            "path={}",
            guest.disk_config.disk(DiskType::CloudInit).unwrap()
        ),
    ];

    for i in 0..num_disks {
        let test_img_path = String::from(
            test_img_dir
                .as_path()
                .join(format!("blk{i}.img"))
                .to_str()
                .unwrap(),
        );

        assert!(
            exec_host_command_output(&format!(
                "dd if=/dev/zero of={test_img_path} bs=1M count=1024"
            ))
            .status
            .success()
        );

        disk_args.push(format!(
            "path={test_img_path},num_queues={num_queues},rate_limit_group=group0,image_type=raw"
        ));
    }

    let mut child = GuestCommand::new(&guest)
        .args(["--cpus", &format!("boot={}", num_queues * num_disks)])
        .args(["--memory", "size=1G"])
        .args(["--kernel", direct_kernel_boot_path().to_str().unwrap()])
        .args(["--cmdline", DIRECT_KERNEL_BOOT_CMDLINE])
        .args(["--rate-limit-group", &rate_limit_group_arg])
        .args(disk_args)
        .default_net()
        .args(["--api-socket", &api_socket])
        .capture_output()
        .spawn()
        .unwrap();

    let r = std::panic::catch_unwind(|| {
        guest.wait_vm_boot().unwrap();

        let mut fio_command = format!(
            "sudo fio --name=global --output-format=json \
            --direct=1 --bs=4k --ioengine=io_uring --iodepth=64 \
            --rw={fio_ops} --runtime={BLOCK_RATE_LIMITER_RUNTIME} \
            --ramp_time={BLOCK_RATE_LIMITER_RAMP_TIME} --numjobs={num_queues}",
        );

        // Generate additional argument for each disk:
        // --name=job0 --filename=/dev/vdc \
        // --name=job1 --filename=/dev/vdd \
        // --name=job2 --filename=/dev/vde \
        // ...
        for i in 0..num_disks {
            let c: char = 'c';
            let arg = format!(
                " --name=job{i} --filename=/dev/vd{}",
                char::from_u32((c as u32) + i).unwrap()
            );
            fio_command += &arg;
        }
        let output = guest.ssh_command(&fio_command).unwrap();

        // Parse fio output
        let measured_rate = if bandwidth {
            parse_fio_output(&output, &fio_ops, num_queues * num_disks).unwrap()
        } else {
            parse_fio_output_iops(&output, &fio_ops, num_queues * num_disks).unwrap()
        };
        assert!(check_rate_limit(measured_rate, limit_rate, 0.2));
    });

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    handle_child_output(r, &output);
}

#[test]
fn test_rate_limiter_block_bandwidth() {
    _test_rate_limiter_block(true, 1);
    _test_rate_limiter_block(true, 2);
}

#[test]
fn test_rate_limiter_group_block_bandwidth() {
    _test_rate_limiter_group_block(true, 1, 1);
    _test_rate_limiter_group_block(true, 2, 1);
    _test_rate_limiter_group_block(true, 1, 2);
    _test_rate_limiter_group_block(true, 2, 2);
}

#[test]
fn test_rate_limiter_block_iops() {
    _test_rate_limiter_block(false, 1);
    _test_rate_limiter_block(false, 2);
}

#[test]
fn test_rate_limiter_group_block_iops() {
    _test_rate_limiter_group_block(false, 1, 1);
    _test_rate_limiter_group_block(false, 2, 1);
    _test_rate_limiter_group_block(false, 1, 2);
    _test_rate_limiter_group_block(false, 2, 2);
}
