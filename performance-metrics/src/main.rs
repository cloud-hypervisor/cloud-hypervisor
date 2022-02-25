// Custom harness to run performance tests
extern crate test_infra;
#[macro_use(crate_authors)]
extern crate clap;

mod performance_tests;

use clap::{Arg, Command as ClapCommand};
use performance_tests::*;
use serde_derive::{Deserialize, Serialize};
use std::{env, fmt, process::Command, sync::mpsc::channel, thread, time::Duration};
use thiserror::Error;

#[derive(Error, Debug)]
enum Error {
    #[error("Error: test timed-out")]
    TestTimeout,
    #[error("Error: test failed")]
    TestFailed,
    #[error("Error creating log file: {0}")]
    ReportFileCreation(std::io::Error),
    #[error("Error writing log file: {0}")]
    ReportFileWrite(std::io::Error),
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
    pub git_committer_date: String,
    pub date: String,
    pub results: Vec<PerformanceTestResult>,
}

impl Default for MetricsReport {
    fn default() -> Self {
        let mut git_human_readable = "".to_string();
        if let Ok(git_out) = Command::new("git").args(&["describe", "--dirty"]).output() {
            if git_out.status.success() {
                if let Ok(git_out_str) = String::from_utf8(git_out.stdout) {
                    git_human_readable = git_out_str;
                }
            }
        }

        let mut git_revision = "".to_string();
        if let Ok(git_out) = Command::new("git").args(&["rev-parse", "HEAD"]).output() {
            if git_out.status.success() {
                if let Ok(git_out_str) = String::from_utf8(git_out.stdout) {
                    git_revision = git_out_str;
                }
            }
        }

        let mut git_committer_date = "".to_string();
        if let Ok(git_out) = Command::new("git")
            .args(&["show", "-s", "--format=%cd"])
            .output()
        {
            if git_out.status.success() {
                if let Ok(git_out_str) = String::from_utf8(git_out.stdout) {
                    git_committer_date = git_out_str;
                }
            }
        }

        MetricsReport {
            git_human_readable,
            git_revision,
            git_committer_date,
            date: date(),
            results: Vec::new(),
        }
    }
}

pub struct PerformanceTestControl {
    test_time: u32,
    test_iterations: u32,
    queue_num: Option<u32>,
    queue_size: Option<u32>,
    net_rx: Option<bool>,
    fio_ops: Option<FioOps>,
}

impl fmt::Display for PerformanceTestControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!(
            "test_time = {}s, test_iterations = {}",
            self.test_time, self.test_iterations
        );
        if let Some(o) = self.queue_num {
            output = format!("{}, queue_num = {}", output, o);
        }
        if let Some(o) = self.queue_size {
            output = format!("{}, queue_size = {}", output, o);
        }
        if let Some(o) = self.net_rx {
            output = format!("{}, net_rx = {}", output, o);
        }
        if let Some(o) = &self.fio_ops {
            output = format!("{}, fio_ops = {}", output, o);
        }

        write!(f, "{}", output)
    }
}

impl PerformanceTestControl {
    const fn default() -> Self {
        Self {
            test_time: 10,
            test_iterations: 5,
            queue_num: None,
            queue_size: None,
            net_rx: None,
            fio_ops: None,
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
}

impl PerformanceTest {
    pub fn run(&self) -> PerformanceTestResult {
        let mut metrics = Vec::new();
        for _ in 0..self.control.test_iterations {
            metrics.push((self.func_ptr)(&self.control));
        }

        let mean = mean(&metrics).unwrap();
        let std_dev = std_deviation(&metrics).unwrap();
        let max = metrics.clone().into_iter().reduce(f64::max).unwrap();
        let min = metrics.clone().into_iter().reduce(f64::min).unwrap();

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
    pub fn calc_timeout(&self) -> u64 {
        ((self.control.test_time + 20) * self.control.test_iterations) as u64
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

const TEST_LIST: [PerformanceTest; 15] = [
    PerformanceTest {
        name: "performance_boot_time",
        func_ptr: performance_boot_time,
        control: PerformanceTestControl {
            test_time: 2,
            test_iterations: 10,
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_boot_time_pmem",
        func_ptr: performance_boot_time_pmem,
        control: PerformanceTestControl {
            test_time: 2,
            test_iterations: 10,
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_virtio_net_latency",
        func_ptr: performance_net_latency,
        control: PerformanceTestControl::default(),
    },
    PerformanceTest {
        name: "performance_virtio_net_throughput_bps_single_queue_rx",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            queue_num: Some(1), // used as 'queue_pairs'
            queue_size: Some(256),
            net_rx: Some(true),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_virtio_net_throughput_bps_single_queue_tx",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            queue_num: Some(1), // used as 'queue_pairs'
            queue_size: Some(256),
            net_rx: Some(false),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_virtio_net_throughput_bps_multi_queue_rx",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            queue_num: Some(2), // used as 'queue_pairs'
            queue_size: Some(1024),
            net_rx: Some(true),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_virtio_net_throughput_bps_multi_queue_tx",
        func_ptr: performance_net_throughput,
        control: PerformanceTestControl {
            queue_num: Some(2), // used as 'queue_pairs'
            queue_size: Some(1024),
            net_rx: Some(false),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_read",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(1),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::Read),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_write",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(1),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::Write),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_random_read",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(1),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::RandomRead),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_random_write",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(1),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::RandomWrite),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_multi_queue_read",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(2),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::Read),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_multi_queue_write",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(2),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::Write),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_multi_queue_random_read",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(2),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::RandomRead),
            ..PerformanceTestControl::default()
        },
    },
    PerformanceTest {
        name: "performance_block_io_bps_multi_queue_random_write",
        func_ptr: performance_block_io,
        control: PerformanceTestControl {
            queue_num: Some(2),
            queue_size: Some(1024),
            fio_ops: Some(FioOps::RandomWrite),
            ..PerformanceTestControl::default()
        },
    },
];

fn run_test_with_timetout(test: &'static PerformanceTest) -> Result<PerformanceTestResult, Error> {
    let (sender, receiver) = channel::<Result<PerformanceTestResult, Error>>();
    thread::spawn(move || {
        println!("Test '{}' running .. ({})", test.name, test.control);

        let output = match std::panic::catch_unwind(|| test.run()) {
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
    let test_timeout = test.calc_timeout();
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
        .version(env!("GIT_HUMAN_READABLE"))
        .author(crate_authors!())
        .about("Generate the performance metrics data for Cloud Hypervisor")
        .arg(
            Arg::new("test-filter")
                .long("test-filter")
                .help("Filter metrics tests to run based on provided keywords")
                .multiple_occurrences(true)
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::new("list-tests")
                .long("list-tests")
                .help("Print the list of availale metrics tests")
                .multiple_occurrences(true)
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::new("report-file")
                .long("report-file")
                .help("Report file. Standard error is used if not specified")
                .takes_value(true),
        )
        .get_matches();

    if cmd_arguments.is_present("list-tests") {
        println!("List of available metrics tests:\n");
        for test in TEST_LIST.iter() {
            println!("\"{}\" ({})", test.name, test.control);
        }

        return;
    }

    let test_filter = match cmd_arguments.values_of("test-filter") {
        Some(s) => s.collect(),
        None => Vec::new(),
    };

    let mut report_file: Box<dyn std::io::Write + Send> =
        if let Some(file) = cmd_arguments.value_of("report-file") {
            Box::new(
                std::fs::File::create(std::path::Path::new(file))
                    .map_err(Error::ReportFileCreation)
                    .unwrap(),
            )
        } else {
            Box::new(std::io::stderr())
        };

    // Run performance tests sequentially and report results (in both readable/json format)
    let mut metrics_report: MetricsReport = Default::default();

    init_tests();

    for test in TEST_LIST.iter() {
        if test_filter.is_empty() || test_filter.iter().any(|&s| test.name.contains(s)) {
            match run_test_with_timetout(test) {
                Ok(r) => {
                    metrics_report.results.push(r);
                }
                Err(e) => {
                    eprintln!("Aborting test due to error: '{:?}'", e);
                    break;
                }
            };
        }
    }

    cleanup_tests();

    // Todo: Report/upload to the metrics database
    report_file
        .write(
            serde_json::to_string_pretty(&metrics_report)
                .unwrap()
                .as_bytes(),
        )
        .map_err(Error::ReportFileWrite)
        .unwrap();
}
