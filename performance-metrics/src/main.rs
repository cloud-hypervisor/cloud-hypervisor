// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Custom harness to run performance tests
mod performance_tests;

use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::{env, fmt, thread};

use clap::{Arg, ArgAction, Command as ClapCommand};
use performance_tests::*;
use serde::{Deserialize, Serialize};
use test_infra::FioOps;
use thiserror::Error;

#[derive(Error, Debug)]
enum Error {
    #[error("Error: test timed-out")]
    TestTimeout,
    #[error("Error: test failed")]
    TestFailed,
}

#[derive(Deserialize, Serialize)]
pub struct PerformanceTestResult {
    name: String,
    mean: f64,
    std_dev: f64,
    max: f64,
    min: f64,
}

#[derive(Deserialize, Serialize)]
pub struct MetricsReport {
    pub git_human_readable: String,
    pub git_revision: String,
    pub git_commit_date: String,
    pub date: String,
    pub results: Vec<PerformanceTestResult>,
}

impl Default for MetricsReport {
    fn default() -> Self {
        let mut git_human_readable = String::new();
        if let Ok(git_out) = Command::new("git").args(["describe", "--dirty"]).output() {
            if git_out.status.success() {
                git_human_readable = String::from_utf8(git_out.stdout)
                    .unwrap()
                    .trim()
                    .to_string();
            } else {
                eprintln!(
                    "Error generating human readable git reference: {}",
                    String::from_utf8(git_out.stderr).unwrap()
                );
            }
        }

        let mut git_revision = String::new();
        if let Ok(git_out) = Command::new("git").args(["rev-parse", "HEAD"]).output() {
            if git_out.status.success() {
                git_revision = String::from_utf8(git_out.stdout)
                    .unwrap()
                    .trim()
                    .to_string();
            } else {
                eprintln!(
                    "Error generating git reference: {}",
                    String::from_utf8(git_out.stderr).unwrap()
                );
            }
        }

        let mut git_commit_date = String::new();
        if let Ok(git_out) = Command::new("git")
            .args(["show", "-s", "--format=%cd"])
            .output()
        {
            if git_out.status.success() {
                git_commit_date = String::from_utf8(git_out.stdout)
                    .unwrap()
                    .trim()
                    .to_string();
            } else {
                eprintln!(
                    "Error generating git commit date: {}",
                    String::from_utf8(git_out.stderr).unwrap()
                );
            }
        }

        MetricsReport {
            git_human_readable,
            git_revision,
            git_commit_date,
            date: date(),
            results: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub enum ImageFormat {
    #[default]
    Raw,
    Qcow2,
    Vhd,
    Vhdx,
}

impl std::str::FromStr for ImageFormat {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw" => Ok(ImageFormat::Raw),
            "qcow2" => Ok(ImageFormat::Qcow2),
            "vhd" => Ok(ImageFormat::Vhd),
            "vhdx" => Ok(ImageFormat::Vhdx),
            _ => Err(()),
        }
    }
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ImageFormat::Raw => write!(f, "raw"),
            ImageFormat::Qcow2 => write!(f, "qcow2"),
            ImageFormat::Vhd => write!(f, "vhd"),
            ImageFormat::Vhdx => write!(f, "vhdx"),
        }
    }
}

#[derive(Default)]
pub struct PerformanceTestOverrides {
    test_iterations: Option<u32>,
    test_timeout: Option<u32>,
    test_image_format: Option<ImageFormat>,
}

impl fmt::Display for PerformanceTestOverrides {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(test_iterations) = self.test_iterations {
            write!(f, "test_iterations = {test_iterations}, ")?;
        }
        if let Some(test_timeout) = self.test_timeout {
            write!(f, "test_timeout = {test_timeout}")?;
        }

        if let Some(test_image_format) = self.test_image_format {
            write!(f, "test_image_format = {test_image_format}")?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct BlockControl {
    pub fio_ops: FioOps,
    pub bandwidth: bool,
    pub test_file: &'static str,
}

#[derive(Clone)]
pub struct PerformanceTestControl {
    test_timeout: u32,
    test_iterations: u32,
    num_queues: Option<u32>,
    queue_size: Option<u32>,
    net_control: Option<(bool, bool)>, // First bool is for RX(true)/TX(false), second bool is for bandwidth or PPS
    block_control: Option<BlockControl>,
    num_boot_vcpus: Option<u8>,
}

impl fmt::Display for PerformanceTestControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!(
            "test_timeout = {}s, test_iterations = {}",
            self.test_timeout, self.test_iterations
        );
        if let Some(o) = self.num_queues {
            output = format!("{output}, num_queues = {o}");
        }
        if let Some(o) = self.queue_size {
            output = format!("{output}, queue_size = {o}");
        }
        if let Some(o) = self.net_control {
            let (rx, bw) = o;
            output = format!("{output}, rx = {rx}, bandwidth = {bw}");
        }
        if let Some(o) = &self.block_control {
            output = format!(
                "{output}, fio_ops = {}, bandwidth = {}, test_file = {}",
                o.fio_ops, o.bandwidth, o.test_file
            );
        }

        write!(f, "{output}")
    }
}

impl PerformanceTestControl {
    const fn default() -> Self {
        Self {
            test_timeout: 10,
            test_iterations: 5,
            num_queues: None,
            queue_size: None,
            net_control: None,
            block_control: None,
            num_boot_vcpus: Some(1),
        }
    }
}

/// A performance test should finish within the a certain time-out and
/// return a performance metrics number (including the average number and
/// standard deviation)
struct PerformanceTest {
    pub name: &'static str,
    pub func_ptr: fn(&PerformanceTestControl) -> f64,
    pub control: PerformanceTestControl,
    unit_adjuster: fn(f64) -> f64,
}

impl PerformanceTest {
    pub fn run(&self, overrides: &PerformanceTestOverrides) -> PerformanceTestResult {
        let mut metrics = Vec::new();
        for _ in 0..overrides
            .test_iterations
            .unwrap_or(self.control.test_iterations)
        {
            // update the timeout in control if passed explicitly and run testcase with it
            if let Some(test_timeout) = overrides.test_timeout {
                let mut control: PerformanceTestControl = self.control.clone();
                control.test_timeout = test_timeout;
                metrics.push((self.func_ptr)(&control));
            } else {
                metrics.push((self.func_ptr)(&self.control));
            }
        }

        let mean = (self.unit_adjuster)(mean(&metrics).unwrap());
        let std_dev = (self.unit_adjuster)(std_deviation(&metrics).unwrap());
        let max = (self.unit_adjuster)(metrics.clone().into_iter().reduce(f64::max).unwrap());
        let min = (self.unit_adjuster)(metrics.clone().into_iter().reduce(f64::min).unwrap());

        PerformanceTestResult {
            name: self.name.to_string(),
            mean,
            std_dev,
            max,
            min,
        }
    }

    // Calculate the timeout for each test
    // Note: To cover the setup/cleanup time, 20s is added for each iteration of the test
    pub fn calc_timeout(&self, test_iterations: &Option<u32>, test_timeout: &Option<u32>) -> u64 {
        ((test_timeout.unwrap_or(self.control.test_timeout) + 20)
            * test_iterations.unwrap_or(self.control.test_iterations)) as u64
    }
}

fn mean(data: &[f64]) -> Option<f64> {
    let count = data.len();

    if count > 0 {
        Some(data.iter().sum::<f64>() / count as f64)
    } else {
        None
    }
}

fn std_deviation(data: &[f64]) -> Option<f64> {
    let count = data.len();

    if count > 0 {
        let mean = mean(data).unwrap();
        let variance = data
            .iter()
            .map(|value| {
                let diff = mean - *value;
                diff * diff
            })
            .sum::<f64>()
            / count as f64;

        Some(variance.sqrt())
    } else {
        None
    }
}

mod adjuster {
    pub fn identity(v: f64) -> f64 {
        v
    }

    pub fn s_to_ms(v: f64) -> f64 {
        v * 1000.0
    }

    pub fn bps_to_gbps(v: f64) -> f64 {
        v / (1_000_000_000_f64)
    }

    #[allow(non_snake_case)]
    pub fn Bps_to_MiBps(v: f64) -> f64 {
        v / (1 << 20) as f64
    }
}

const TEST_LIST: [PerformanceTest; 32] = [
    PerformanceTest {
        name: "boot_time_ms",
        func_ptr: performance_boot_time,
        control: PerformanceTestControl {
            test_timeout: 2,
            test_iterations: 10,
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::s_to_ms,
    },
    PerformanceTest {
        name: "boot_time_pmem_ms",
        func_ptr: performance_boot_time_pmem,
        control: PerformanceTestControl {
            test_timeout: 2,
            test_iterations: 10,
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::s_to_ms,
    },
    PerformanceTest {
        name: "boot_time_16_vcpus_ms",
        func_ptr: performance_boot_time,
        control: PerformanceTestControl {
            test_timeout: 2,
            test_iterations: 10,
            num_boot_vcpus: Some(16),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::s_to_ms,
    },
    PerformanceTest {
        name: "restore_latency_time_ms",
        func_ptr: performance_restore_latency,
        control: PerformanceTestControl {
            test_timeout: 2,
            test_iterations: 10,
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "boot_time_16_vcpus_pmem_ms",
        func_ptr: performance_boot_time_pmem,
        control: PerformanceTestControl {
            test_timeout: 2,
            test_iterations: 10,
            num_boot_vcpus: Some(16),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::s_to_ms,
    },
    PerformanceTest {
        name: "virtio_net_latency_us",
        func_ptr: performance_net_latency,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(256),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "virtio_net_throughput_single_queue_rx_gbps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(256),
            net_control: Some((true, true)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::bps_to_gbps,
    },
    PerformanceTest {
        name: "virtio_net_throughput_single_queue_tx_gbps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(256),
            net_control: Some((false, true)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::bps_to_gbps,
    },
    PerformanceTest {
        name: "virtio_net_throughput_multi_queue_rx_gbps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(4),
            queue_size: Some(256),
            net_control: Some((true, true)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::bps_to_gbps,
    },
    PerformanceTest {
        name: "virtio_net_throughput_multi_queue_tx_gbps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(4),
            queue_size: Some(256),
            net_control: Some((false, true)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::bps_to_gbps,
    },
    PerformanceTest {
        name: "virtio_net_throughput_single_queue_rx_pps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(256),
            net_control: Some((true, false)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "virtio_net_throughput_single_queue_tx_pps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(256),
            net_control: Some((false, false)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "virtio_net_throughput_multi_queue_rx_pps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(4),
            queue_size: Some(256),
            net_control: Some((true, false)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "virtio_net_throughput_multi_queue_tx_pps",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            num_queues: Some(4),
            queue_size: Some(256),
            net_control: Some((false, false)),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_read_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Read,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_write_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Write,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_random_read_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomRead,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_random_write_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomWrite,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_multi_queue_read_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Read,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_multi_queue_write_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Write,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_multi_queue_random_read_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomRead,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_multi_queue_random_write_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomWrite,
                bandwidth: true,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_read_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Read,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_write_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Write,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_random_read_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomRead,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_random_write_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomWrite,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_multi_queue_read_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Read,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_multi_queue_write_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Write,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_multi_queue_random_read_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomRead,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_multi_queue_random_write_IOPS",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(2),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomWrite,
                bandwidth: false,
                test_file: BLK_IO_TEST_IMG,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::identity,
    },
    PerformanceTest {
        name: "block_qcow2_backing_qcow2_read_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::Read,
                bandwidth: true,
                test_file: OVERLAY_WITH_QCOW2_BACKING,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
    PerformanceTest {
        name: "block_qcow2_backing_qcow2_random_read_MiBps",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            num_queues: Some(1),
            queue_size: Some(128),
            block_control: Some(BlockControl {
                fio_ops: FioOps::RandomRead,
                bandwidth: true,
                test_file: OVERLAY_WITH_QCOW2_BACKING,
            }),
            ..PerformanceTestControl::default()
        },
        unit_adjuster: adjuster::Bps_to_MiBps,
    },
];

fn run_test_with_timeout(
    test: &'static PerformanceTest,
    overrides: &Arc<PerformanceTestOverrides>,
) -> Result<PerformanceTestResult, Error> {
    let (sender, receiver) = channel::<Result<PerformanceTestResult, Error>>();
    let test_iterations = overrides.test_iterations;
    let test_timeout = overrides.test_timeout;
    let overrides = overrides.clone();
    thread::spawn(move || {
        println!(
            "Test '{}' running .. (control: {}, overrides: {})",
            test.name, test.control, overrides
        );

        let output = match std::panic::catch_unwind(|| test.run(&overrides)) {
            Ok(test_result) => {
                println!(
                    "Test '{}' .. ok: mean = {}, std_dev = {}",
                    test_result.name, test_result.mean, test_result.std_dev
                );
                Ok(test_result)
            }
            Err(_) => Err(Error::TestFailed),
        };

        let _ = sender.send(output);
    });

    // Todo: Need to cleanup/kill all hanging child processes
    let test_timeout = test.calc_timeout(&test_iterations, &test_timeout);
    receiver
        .recv_timeout(Duration::from_secs(test_timeout))
        .map_err(|_| {
            eprintln!(
                "[Error] Test '{}' time-out after {} seconds",
                test.name, test_timeout
            );
            Error::TestTimeout
        })?
}

fn date() -> String {
    let output = test_infra::exec_host_command_output("date");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn main() {
    let cmd_arguments = ClapCommand::new("performance-metrics")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Generate the performance metrics data for Cloud Hypervisor")
        .arg(
            Arg::new("test-filter")
                .long("test-filter")
                .help("Filter metrics tests to run based on provided keywords")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("list-tests")
                .long("list-tests")
                .help("Print the list of available metrics tests")
                .num_args(0)
                .action(ArgAction::SetTrue)
                .required(false),
        )
        .arg(
            Arg::new("report-file")
                .long("report-file")
                .help("Report file. Standard error is used if not specified")
                .num_args(1),
        )
        .arg(
            Arg::new("iterations")
                .long("iterations")
                .help("Override number of test iterations")
                .num_args(1),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Override test timeout, Ex. --timeout 5")
                .num_args(1),
        )
        .arg(
            Arg::new("image-format")
                .long("image-format")
                .help(
                    "Override the image format used for block tests, supported values: qcow2, raw, vhd, vhdx. \
                     Default is 'raw'.",
                )
                .num_args(1),
        )
        .get_matches();

    // It seems that the tool (ethr) used for testing the virtio-net latency
    // is not stable on AArch64, and therefore the latency test is currently
    // skipped on AArch64.
    let test_list: Vec<&PerformanceTest> = TEST_LIST
        .iter()
        .filter(|t| !(cfg!(target_arch = "aarch64") && t.name == "virtio_net_latency_us"))
        .collect();

    if cmd_arguments.get_flag("list-tests") {
        for test in test_list.iter() {
            println!("\"{}\" ({})", test.name, test.control);
        }

        return;
    }

    let test_filter = match cmd_arguments.get_many::<String>("test-filter") {
        Some(s) => s.collect(),
        None => Vec::new(),
    };

    // Run performance tests sequentially and report results (in both readable/json format)
    let mut metrics_report: MetricsReport = Default::default();

    let overrides = Arc::new(PerformanceTestOverrides {
        test_iterations: cmd_arguments
            .get_one::<String>("iterations")
            .map(|s| s.parse())
            .transpose()
            .unwrap_or_default(),
        test_timeout: cmd_arguments
            .get_one::<String>("timeout")
            .map(|s| s.parse())
            .transpose()
            .unwrap_or_default(),
        test_image_format: cmd_arguments
            .get_one::<String>("image-format")
            .map(|s| s.parse())
            .transpose()
            .unwrap_or_default(),
    });

    init_tests(&overrides);

    for test in test_list.iter() {
        if test_filter.is_empty() || test_filter.iter().any(|&s| test.name.contains(s)) {
            match run_test_with_timeout(test, &overrides) {
                Ok(r) => {
                    metrics_report.results.push(r);
                }
                Err(e) => {
                    eprintln!("Aborting test due to error: '{e:?}'");
                    std::process::exit(1);
                }
            }
        }
    }

    cleanup_tests();

    let mut report_file: Box<dyn std::io::Write + Send> =
        if let Some(file) = cmd_arguments.get_one::<String>("report-file") {
            Box::new(
                std::fs::File::create(std::path::Path::new(file))
                    .map_err(|e| {
                        eprintln!("Error opening report file: {file}: {e}");
                        std::process::exit(1);
                    })
                    .unwrap(),
            )
        } else {
            Box::new(std::io::stdout())
        };

    report_file
        .write_all(
            serde_json::to_string_pretty(&metrics_report)
                .unwrap()
                .as_bytes(),
        )
        .map_err(|e| {
            eprintln!("Error writing report file: {e}");
            std::process::exit(1);
        })
        .unwrap();
}
