// Custom harness to run performance tests

#[macro_use]
extern crate lazy_static;
extern crate test_infra;

mod performance_tests;

use performance_tests::*;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

pub struct PerformanceTestControl {
    test_time: u32,
    test_iterations: u32,
    queue_num: Option<u32>,
    queue_size: Option<u32>,
    net_rx: Option<bool>,
    fio_ops: Option<FioOps>,
}

impl Default for PerformanceTestControl {
    fn default() -> Self {
        Self {
            test_time: 10,
            test_iterations: 30,
            queue_num: Default::default(),
            queue_size: Default::default(),
            net_rx: Default::default(),
            fio_ops: Default::default(),
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

impl Hash for PerformanceTest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for PerformanceTest {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for PerformanceTest {}

impl PerformanceTest {
    pub fn run(&self) -> (f64, f64) {
        println!("Running test: '{}' ...", self.name);

        let mut metrics = Vec::new();
        for _ in 0..self.control.test_iterations {
            metrics.push((self.func_ptr)(&self.control));
        }

        let mean = mean(&metrics).unwrap();
        let std_dev = std_deviation(&metrics).unwrap();

        println!(
            "{} ... ok: mean = {}, std_dev = {}",
            self.name, mean, std_dev
        );

        (mean, std_dev)
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

lazy_static! {
    static ref TEST_LIST: HashSet<PerformanceTest> = {
        let mut m = HashSet::new();
        m.insert(PerformanceTest {
            name: "performance_boot_time",
            func_ptr: performance_boot_time,
            control: PerformanceTestControl {
                test_time: 2,
                test_iterations: 10,
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_boot_time_pmem",
            func_ptr: performance_boot_time_pmem,
            control: PerformanceTestControl {
                test_time: 2,
                test_iterations: 10,
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_virtio_net_latency",
            func_ptr: performance_net_latency,
            control: Default::default(),
        });
        m.insert(PerformanceTest {
            name: "performance_virtio_net_throughput_single_queue_rx",
            func_ptr: performance_net_throughput,
            control: PerformanceTestControl {
                queue_num: Some(1), // used as 'queue_pairs'
                queue_size: Some(256),
                net_rx: Some(true),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_virtio_net_throughput_single_queue_tx",
            func_ptr: performance_net_throughput,
            control: PerformanceTestControl {
                queue_num: Some(1), // used as 'queue_pairs'
                queue_size: Some(256),
                net_rx: Some(false),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_virtio_net_throughput_multi_queue_rx",
            func_ptr: performance_net_throughput,
            control: PerformanceTestControl {
                queue_num: Some(2), // used as 'queue_pairs'
                queue_size: Some(1024),
                net_rx: Some(true),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_virtio_net_throughput_multi_queue_tx",
            func_ptr: performance_net_throughput,
            control: PerformanceTestControl {
                queue_num: Some(2), // used as 'queue_pairs'
                queue_size: Some(1024),
                net_rx: Some(false),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_read",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(1),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::Read),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_write",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(1),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::Write),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_random_read",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(1),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::RandomRead),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_random_write",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(1),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::RandomWrite),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_multi_queue_read",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(2),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::Read),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_multi_queue_write",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(2),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::Write),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_multi_queue_random_read",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(2),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::RandomRead),
                ..Default::default()
            }
        });
        m.insert(PerformanceTest {
            name: "performance_block_io_multi_queue_random_write",
            func_ptr: performance_block_io,
            control: PerformanceTestControl {
                queue_num: Some(2),
                queue_size: Some(1024),
                fio_ops: Some(FioOps::RandomWrite),
                ..Default::default()
            }
        });
        m
    };
}

fn main() {
    // Run performance tests sequentially and report results (in both readable/json format)
    // Todo: test filter, report in readable/json format, capture test output unless failed;
    for test in TEST_LIST.iter() {
        test.run();
    }
}
