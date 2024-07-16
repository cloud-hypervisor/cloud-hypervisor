# Performance Metrics

Cloud Hypervisor provides a [performance metrics](https://github.com/cloud-hypervisor/cloud-hypervisor/tree/main/performance-metrics)
binary for users to generate metrics data from their own
environment. This document describes how to generate metrics data
quickly by using Cloud Hypervisor's development script,
e.g. `dev_cli.sh`. The only prerequisite is [Docker installation](https://docs.docker.com/engine/install/).
Please note that upon its first invocation, this script will pull a
fairly large container image.

## Run the Performance Tests

To generate metrics data for all available performance tests (including
boot time, block I/O throughput, and network throughput & latency) and
output the result into a json file:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- --report-file /tmp/metrics.json
```

To get a list of available performance tests:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- --list-tests
```

To generate metrics data for selected performance tests, e.g. boot time only:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- --report-file /tmp/metrics.json --test-filter boot_time
```

To set custom timeout or test iterations for all performance tests:
```
$ ./scripts/dev_cli.sh tests --metrics -- -- --timeout 5 --iterations 10
```

## Performance Tests Details

The following table lists the supported performance tests with default
timeout and number of iterations. The `timeout` defines the maximum
execution time of each test for each iteration. The `iteration` defines
how many times a test needs to be executed to generate the final metrics
data.

| **Type**   | **Metric**                                 | **Timeout(s)** | **Iterations** |
|------------|--------------------------------------------|----------------|----------------|
| Boot Time  | boot_time_ms                               | 2              | 10             |
|            | boot_time_pmem_ms                          | 2              | 10             |
|            | boot_time_16_vcpus_ms                      | 2              | 10             |
|            | boot_time_16_vcpus_pmem_ms                 | 2              | 10             |
| Virtio Net | virtio_net_latency_us                      | 10             | 5              |
|            | virtio_net_throughput_single_queue_rx_gbps | 10             | 5              |
|            | virtio_net_throughput_single_queue_tx_gbps | 10             | 5              |
|            | virtio_net_throughput_multi_queue_rx_gbps  | 10             | 5              |
|            | virtio_net_throughput_multi_queue_tx_gbps  | 10             | 5              |
| Block      | block_read_MiBps                           | 10             | 5              |
|            | block_write_MiBps                          | 10             | 5              |
|            | block_random_read_MiBps                    | 10             | 5              |
|            | block_random_write_MiBps                   | 10             | 5              |
|            | block_multi_queue_read_MiBps               | 10             | 5              |
|            | block_multi_queue_write_MiBps              | 10             | 5              |
|            | block_multi_queue_random_read_MiBps        | 10             | 5              |
|            | block_multi_queue_random_write_MiBps       | 10             | 5              |
|            | block_read_IOPS                            | 10             | 5              |
|            | block_write_IOPS                           | 10             | 5              |
|            | block_random_read_IOPS                     | 10             | 5              |
|            | block_random_write_IOPS                    | 10             | 5              |
|            | block_multi_queue_read_IOPS                | 10             | 5              |
|            | block_multi_queue_write_IOPS               | 10             | 5              |
|            | block_multi_queue_random_read_IOPS         | 10             | 5              |
|            | block_multi_queue_random_write_IOPS        | 10             | 5              |

## Output Format

Performance-metrics output the result into a json file if `report-file`
param is set. The fields included in JSON include:

| Field Name         | Content                                  |
|--------------------|------------------------------------------|
| git_human_readable | Recent tag information of git repository |
| git_revision       | Commit id of HEAD                        |
| git_commit_date    | Commit date of HEAD                      |
| date               | Date for executing the program           |
| results            | A list of metrics                        |

A sample example is below.

```json
{
  "git_human_readable": "v38.0-421-gc67f7997-dirty",
  "git_revision": "c67f799717f99efc0a798683520278da25d5f8b9",
  "git_commit_date": "Fri Jul 12 00:02:26 2024 +0000",
  "date": "Mon Jul 15 17:33:19 CST 2024",
  "results": [
    {
      "name": "boot_time_ms",
      "mean": xxx,
      "std_dev": xxx,
      "max": xxx,
      "min": xxx
    },
    {
      "name": "block_multi_queue_read_MiBps",
      "mean": xxx,
      "std_dev": xxx,
      "max": xxx,
      "min": xxx
    },
    ...
  ]
}
```
