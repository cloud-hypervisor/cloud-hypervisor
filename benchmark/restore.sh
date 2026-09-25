#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

usage() {
    echo "Usage: $0 SNAPSHOT_DIR CODEC CHUNK_SIZE WORKERS ITERATION" >&2
    exit 2
}

[[ $# -eq 5 ]] || usage

snapshot_dir=$1
codec=$2
chunk_size=$3
workers=$4
iteration=$5
run_name="restore-${codec}-c${chunk_size}-w${workers}-i${iteration}"
vmm_log="$LOG_DIR/$run_name-vmm.log"
receiver_log="$LOG_DIR/$run_name-receiver.log"
daemon_log="$LOG_DIR/$run_name-daemon.log"
cpu_time_file="$LOG_DIR/$run_name-cpu.txt"

require_executable "$CH_BIN"
require_executable "$REMOTE_BIN"
require_executable "$OFFLOAD_BIN"
require_executable "$TIME_BIN"
[[ -d "$snapshot_dir" ]] || {
    echo "Snapshot directory not found: $snapshot_dir" >&2
    exit 1
}

rm -f -- "$RESTORE_API_SOCKET" "$RESTORE_SOCKET"

vmm_pid=
receiver_pid=
cleanup() {
    terminate_process "$receiver_pid"
    terminate_process "$vmm_pid"
    rm -f -- "$RESTORE_API_SOCKET" "$RESTORE_SOCKET"
}
trap cleanup EXIT INT TERM

RUST_LOG=${RUST_LOG:-info} "${NUMA_PREFIX[@]}" "$CH_BIN" --api-socket "$RESTORE_API_SOCKET" \
    >"$vmm_log" 2>&1 &
vmm_pid=$!
wait_for_socket "$RESTORE_API_SOCKET"

"$REMOTE_BIN" --api-socket "$RESTORE_API_SOCKET" receive-migration \
    "receiver_url=unix:$RESTORE_SOCKET" >"$receiver_log" 2>&1 &
receiver_pid=$!
wait_for_socket "$RESTORE_SOCKET"

drop_page_cache

restore_args=(
    restore
    --socket "$RESTORE_SOCKET"
    --input-dir "$snapshot_dir"
    --workers "$workers"
)
if [[ ${RESUME_VM:-1} == 1 ]]; then
    restore_args+=(--resume)
fi

start_ns=$(date +%s%N)
"$TIME_BIN" --format='%P' --output="$cpu_time_file" \
    env RUST_LOG=${RUST_LOG:-info} "${NUMA_PREFIX[@]}" "${OFFLOAD_PREFIX[@]}" \
    "$OFFLOAD_BIN" "${restore_args[@]}" \
    >"$daemon_log" 2>&1
wait "$receiver_pid"
receiver_pid=
end_ns=$(date +%s%N)

duration_ms=$(elapsed_ms "$start_ns" "$end_ns")
cpu_util_pct=$(read_cpu_utilization "$cpu_time_file")
stored_bytes=$(snapshot_size_bytes "$snapshot_dir")
if [[ ${RECORD_RESULT:-1} == 1 ]]; then
    record_result restore "$codec" "$chunk_size" "$workers" "$iteration" \
        "$duration_ms" "$cpu_util_pct" "$stored_bytes" "$snapshot_dir"
fi

printf 'restore codec=%s chunk=%s workers=%s elapsed_ms=%s cpu=%s%% bytes=%s\n' \
    "$codec" "$chunk_size" "$workers" "$duration_ms" "$cpu_util_pct" "$stored_bytes"
grep -E 'Decompressed|Restore replay finished' "$daemon_log" || true
grep -E 'Migration \(incoming\)' "$vmm_log" || true