# Performance Metrics

Cloud Hypervisor provides a [performance metrics](https://github.com/cloud-hypervisor/cloud-hypervisor/tree/main/performance-metrics)
binary for users to generate metrics data from their own
environment. This document describes how to generate metrics data
quickly by using Cloud Hypervisor's development script,
e.g. `dev_cli.sh`. See [testing.md](testing.md#prerequisites) for the
prerequisites.
Please note that upon its first invocation, this script will pull a
fairly large container image.

## Run the Performance Tests

To generate metrics data for all available performance tests (including
boot time, block I/O throughput, and network throughput & latency) and
output the result into a json file:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- \
    --report-file /root/workloads/metrics.json
```

The report file must be in a directory that is mounted from the host.
`/root/workloads` in the container is `$HOME/workloads` on the host.
Files in the container's `/tmp` are lost when the container exits.

To get a list of available performance tests:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- --list-tests
```

To generate metrics data for selected performance tests, e.g. boot time only:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- \
    --report-file /root/workloads/metrics.json --test-filter boot_time
```

To set custom timeout or test iterations for all performance tests:

```
$ ./scripts/dev_cli.sh tests --metrics -- -- --timeout 5 --iterations 10
```

## Performance Tests Details

The `timeout` defines the maximum
execution time of each test for each iteration. The `iteration` defines
how many times a test needs to be executed to generate the final metrics
data.

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

## Example

Here is an example of generating metrics data for the boot time using
`pmem`:

```bash
$ ./scripts/dev_cli.sh tests --metrics -- -- --test-filter boot_time_pmem_ms
```

Here is a sample output:

```json
{
  "git_human_readable": "v40.0",
  "git_revision": "e9b263975786abbf895469b93dfc00f21ce39a88",
  "git_commit_date": "Fri Jun 21 08:40:44 2024 +0000",
  "date": "Tue Jul 16 16:35:29 UTC 2024",
  "results": [
    {
      "name": "boot_time_pmem_ms",
      "mean": 105.9461,
      "std_dev": 7.140993312558129,
      "max": 120.01499999999999,
      "min": 92.37600000000002,
      "status": "PASSED"
    }
  ]
}
```

Note that the metrics data above is for illustration purpose only and
does not represent the actual performance of Cloud Hypervisor on your
system.
