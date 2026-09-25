#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$BENCHMARK_DIR/.." && pwd)

if [[ -n ${BENCHMARK_CONFIG:-} ]]; then
    source "$BENCHMARK_CONFIG"
elif [[ -f "$BENCHMARK_DIR/benchmark.env" ]]; then
    source "$BENCHMARK_DIR/benchmark.env"
fi

BIN_DIR=${BIN_DIR:-$REPO_ROOT/target/release}
CH_BIN=${CH_BIN:-$BIN_DIR/cloud-hypervisor}
REMOTE_BIN=${REMOTE_BIN:-$BIN_DIR/ch-remote}
OFFLOAD_BIN=${OFFLOAD_BIN:-$BIN_DIR/offload_daemon}
SOURCE_API_SOCKET=${SOURCE_API_SOCKET:-/tmp/ch-compression-source.sock}
RESTORE_API_SOCKET=${RESTORE_API_SOCKET:-/tmp/ch-compression-restore.sock}
OFFLOAD_SOCKET=${OFFLOAD_SOCKET:-/tmp/ch-compression-offload.sock}
RESTORE_SOCKET=${RESTORE_SOCKET:-/tmp/ch-compression-restore-data.sock}
RESULTS_DIR=${RESULTS_DIR:-$REPO_ROOT/benchmark/results}
SNAPSHOT_ROOT=${SNAPSHOT_ROOT:-$RESULTS_DIR/snapshots}
RESULTS_CSV=${RESULTS_CSV:-$RESULTS_DIR/results.csv}
LOG_DIR=${LOG_DIR:-$RESULTS_DIR/logs}
TIME_BIN=${TIME_BIN:-/usr/bin/time}
SOCKET_TIMEOUT=${SOCKET_TIMEOUT:-30}
SOURCE_PID_FILE=${SOURCE_PID_FILE:-$RESULTS_DIR/source-vm.pid}
SOURCE_VMM_LOG=${SOURCE_VMM_LOG:-$LOG_DIR/source-vm.log}
SOURCE_SERIAL_LOG=${SOURCE_SERIAL_LOG:-$LOG_DIR/source-serial.log}

mkdir -p "$SNAPSHOT_ROOT" "$RESULTS_DIR" "$LOG_DIR"

NUMA_PREFIX=()
if [[ -n ${NUMA_NODE:-} ]]; then
    command -v numactl >/dev/null || {
        echo "NUMA_NODE requires numactl" >&2
        exit 1
    }
    NUMA_PREFIX=(numactl "--cpunodebind=$NUMA_NODE" "--membind=$NUMA_NODE")
fi

OFFLOAD_PREFIX=()
if [[ -n ${OFFLOAD_CPU:-} ]]; then
    command -v taskset >/dev/null || {
        echo "OFFLOAD_CPU requires taskset" >&2
        exit 1
    }
    OFFLOAD_PREFIX=(taskset --cpu-list "$OFFLOAD_CPU")
fi

require_executable() {
    local executable=$1
    if [[ ! -x "$executable" ]]; then
        echo "Required executable not found: $executable" >&2
        exit 1
    fi
}

wait_for_socket() {
    local socket_path=$1
    local waited=0
    while [[ ! -S "$socket_path" ]]; do
        if ((waited >= SOCKET_TIMEOUT * 10)); then
            echo "Timed out waiting for socket: $socket_path" >&2
            return 1
        fi
        sleep 0.1
        ((waited += 1))
    done
}

elapsed_ms() {
    local start_ns=$1
    local end_ns=$2
    awk -v start="$start_ns" -v end="$end_ns" \
        'BEGIN { printf "%.3f", (end - start) / 1000000 }'
}

snapshot_size_bytes() {
    local snapshot_dir=$1
    du -B1 -s "$snapshot_dir" | awk '{print $1}'
}

initialize_results() {
    local expected_header='dataset,phase,codec,chunk_size,workers,iteration,elapsed_ms,cpu_util_pct,stored_bytes,snapshot_dir'
    local legacy_header='phase,codec,chunk_size,workers,iteration,elapsed_ms,cpu_util_pct,stored_bytes,snapshot_dir'
    if [[ ! -e "$RESULTS_CSV" ]]; then
        printf '%s\n' "$expected_header" >"$RESULTS_CSV"
        return
    fi

    local current_header
    IFS= read -r current_header <"$RESULTS_CSV"
    if [[ "$current_header" == "$legacy_header" ]]; then
        local upgraded_results
        upgraded_results=$(mktemp "${RESULTS_CSV}.XXXXXX")
        awk 'NR == 1 { print "dataset," $0; next } { print "unknown," $0 }' \
            "$RESULTS_CSV" >"$upgraded_results"
        mv -- "$upgraded_results" "$RESULTS_CSV"
    elif [[ "$current_header" != "$expected_header" ]]; then
        echo "Unsupported results header: $current_header" >&2
        exit 1
    fi
}

record_result() {
    local phase=$1
    local codec=$2
    local chunk_size=$3
    local workers=$4
    local iteration=$5
    local duration_ms=$6
    local cpu_util_pct=$7
    local stored_bytes=$8
    local snapshot_dir=$9
    local dataset=${BENCHMARK_DATASET:-${MEMORY_PATTERN:-unknown}}

    initialize_results
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$dataset" "$phase" "$codec" "$chunk_size" "$workers" "$iteration" \
        "$duration_ms" "$cpu_util_pct" "$stored_bytes" "$snapshot_dir" >>"$RESULTS_CSV"
}

read_cpu_utilization() {
    local time_file=$1
    tr -d '%[:space:]' <"$time_file"
}

drop_page_cache() {
    if [[ ${COLD_CACHE:-0} != 1 ]]; then
        return
    fi
    if ((EUID != 0)); then
        echo "COLD_CACHE=1 requires root; run the benchmark as root." >&2
        exit 1
    fi
    sync
    echo 3 >/proc/sys/vm/drop_caches
}

terminate_process() {
    local pid=${1:-}
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}