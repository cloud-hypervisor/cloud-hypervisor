#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

usage() {
    echo "Usage: $0 snapshot|restore" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
phase=$1
[[ "$phase" == snapshot || "$phase" == restore ]] || usage

read -r -a codecs <<<"${CODECS:-raw lz4 zstd qpl-hardware-static qpl-hardware-dynamic qpl-hardware-static-async qpl-hardware-dynamic-async}"
read -r -a chunk_sizes <<<"${CHUNK_SIZES:-65536 262144 1048576 2097152}"
iterations=${ITERATIONS:-5}
warmups=${WARMUPS:-1}
snapshot_iteration=${RESTORE_SNAPSHOT_ITERATION:-1}
keep_all_snapshots=${KEEP_ALL_SNAPSHOTS:-0}

workers_for_codec() {
    local selected_codec=$1
    local selected_phase=$2
    local counts
    case "$selected_codec" in
        qpl-*-async)
            if [[ "$selected_phase" == snapshot ]]; then
                counts=${QPL_ASYNC_SNAPSHOT_DEPTHS:-8 16 32}
            else
                counts=${QPL_ASYNC_RESTORE_DEPTHS:-32 64 128}
            fi
            ;;
        qpl-*) counts=${QPL_SYNC_WORKER_COUNTS:-4 8 16} ;;
        *) counts=${SOFTWARE_WORKER_COUNTS:-${WORKER_COUNTS:-1 2 4}} ;;
    esac
    printf '%s\n' "$counts"
}

snapshot_workers_for_codec() {
    local selected_codec=$1
    if [[ "$selected_codec" == raw ]]; then
        printf '1\n'
        return
    fi
    local counts
    counts=$(workers_for_codec "$selected_codec" snapshot)
    printf '%s\n' "${counts%% *}"
}

if [[ ${RESET_RESULTS:-0} == 1 ]]; then
    rm -f -- "$RESULTS_CSV"
fi

run_snapshot_case() {
    local codec=$1
    local chunk_size=$2
    local workers=$3
    local iteration=$4
    local record=$5
    local output_dir=$SNAPSHOT_ROOT/${codec}-c${chunk_size}-w${workers}-i${iteration}

    RECORD_RESULT=$record "$BENCHMARK_DIR/snapshot.sh" \
        "$codec" "$chunk_size" "$workers" "$iteration" "$output_dir"
    if [[ "$record" == 0 || \
        ("$keep_all_snapshots" != 1 && "$iteration" != "$snapshot_iteration") ]]; then
        rm -rf -- "$output_dir"
    fi
}

run_restore_case() {
    local codec=$1
    local chunk_size=$2
    local workers=$3
    local iteration=$4
    local record=$5
    local snapshot_workers
    snapshot_workers=$(snapshot_workers_for_codec "$codec")
    local input_dir=$SNAPSHOT_ROOT/${codec}-c${chunk_size}-w${snapshot_workers}-i${snapshot_iteration}

    RECORD_RESULT=$record "$BENCHMARK_DIR/restore.sh" \
        "$input_dir" "$codec" "$chunk_size" "$workers" "$iteration"
}

for codec in "${codecs[@]}"; do
    if [[ "$codec" == raw ]]; then
        cases=("0:1")
    else
        cases=()
        read -r -a worker_counts <<<"$(workers_for_codec "$codec" "$phase")"
        for chunk_size in "${chunk_sizes[@]}"; do
            for workers in "${worker_counts[@]}"; do
                cases+=("$chunk_size:$workers")
            done
        done
    fi

    for benchmark_case in "${cases[@]}"; do
        IFS=: read -r chunk_size workers <<<"$benchmark_case"
        for ((iteration = 1; iteration <= warmups; iteration += 1)); do
            warmup_iteration="warmup-${iteration}"
            if [[ "$phase" == snapshot ]]; then
                run_snapshot_case "$codec" "$chunk_size" "$workers" \
                    "$warmup_iteration" 0
            else
                run_restore_case "$codec" "$chunk_size" "$workers" \
                    "$warmup_iteration" 0
            fi
        done
        for ((iteration = 1; iteration <= iterations; iteration += 1)); do
            if [[ "$phase" == snapshot ]]; then
                run_snapshot_case "$codec" "$chunk_size" "$workers" "$iteration" 1
            else
                run_restore_case "$codec" "$chunk_size" "$workers" "$iteration" 1
            fi
        done
    done
done

"$BENCHMARK_DIR/summarize.py" "$RESULTS_CSV"