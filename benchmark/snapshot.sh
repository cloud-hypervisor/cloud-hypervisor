#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

usage() {
    echo "Usage: $0 CODEC CHUNK_SIZE WORKERS ITERATION [SNAPSHOT_DIR]" >&2
    echo "CODEC: raw, lz4, zstd, qpl-hardware-static, qpl-hardware-dynamic, qpl-hardware-static-async, qpl-hardware-dynamic-async, qpl-hardware, or qpl-auto" >&2
    exit 2
}

[[ $# -ge 4 && $# -le 5 ]] || usage

codec=$1
chunk_size=$2
workers=$3
iteration=$4
snapshot_dir=${5:-$SNAPSHOT_ROOT/${codec}-c${chunk_size}-w${workers}-i${iteration}}
run_name="snapshot-${codec}-c${chunk_size}-w${workers}-i${iteration}"
daemon_log="$LOG_DIR/$run_name-daemon.log"
cpu_time_file="$LOG_DIR/$run_name-cpu.txt"

require_executable "$REMOTE_BIN"
require_executable "$OFFLOAD_BIN"
require_executable "$TIME_BIN"
[[ -S "$SOURCE_API_SOCKET" ]] || {
    echo "Source API socket is not available: $SOURCE_API_SOCKET" >&2
    echo "Start and pause a shared-memory VM before running this script." >&2
    exit 1
}

case "$codec" in
    raw | lz4 | zstd | qpl-hardware-static | qpl-hardware-dynamic | qpl-hardware-static-async | qpl-hardware-dynamic-async | qpl-hardware | qpl-auto) ;;
    *) usage ;;
esac

rm -rf -- "$snapshot_dir"
rm -f -- "$OFFLOAD_SOCKET" "$OFFLOAD_SOCKET.lock"

daemon_args=(
    snapshot
    --socket "$OFFLOAD_SOCKET"
    --output-dir "$snapshot_dir"
)
if [[ "$codec" != raw ]]; then
    daemon_args+=(
        --compression "$codec"
        --chunk-size "$chunk_size"
        --workers "$workers"
    )
fi
if [[ "$codec" == zstd ]]; then
    daemon_args+=(--zstd-level "${ZSTD_LEVEL:-1}")
fi

daemon_pid=
cleanup() {
    terminate_process "$daemon_pid"
    rm -f -- "$OFFLOAD_SOCKET"
}
trap cleanup EXIT INT TERM

"$TIME_BIN" --format='%P' --output="$cpu_time_file" \
    env RUST_LOG=${RUST_LOG:-info} "${NUMA_PREFIX[@]}" "${OFFLOAD_PREFIX[@]}" \
    "$OFFLOAD_BIN" "${daemon_args[@]}" \
    >"$daemon_log" 2>&1 &
daemon_pid=$!
wait_for_socket "$OFFLOAD_SOCKET"

start_ns=$(date +%s%N)
"$REMOTE_BIN" --api-socket "$SOURCE_API_SOCKET" send-migration \
    "destination_url=unix:$OFFLOAD_SOCKET,memory_mode=memfds,preserve_source=on"
wait "$daemon_pid"
daemon_pid=
end_ns=$(date +%s%N)

duration_ms=$(elapsed_ms "$start_ns" "$end_ns")
cpu_util_pct=$(read_cpu_utilization "$cpu_time_file")
stored_bytes=$(snapshot_size_bytes "$snapshot_dir")
if [[ ${RECORD_RESULT:-1} == 1 ]]; then
    record_result snapshot "$codec" "$chunk_size" "$workers" "$iteration" \
        "$duration_ms" "$cpu_util_pct" "$stored_bytes" "$snapshot_dir"
fi

printf 'snapshot codec=%s chunk=%s workers=%s elapsed_ms=%s cpu=%s%% bytes=%s\n' \
    "$codec" "$chunk_size" "$workers" "$duration_ms" "$cpu_util_pct" "$stored_bytes"
grep -E 'Compressed slot|Snapshot persisted' "$daemon_log" || true