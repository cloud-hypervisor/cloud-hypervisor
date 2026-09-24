#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

cloud_hypervisor_pids() {
    local proc_exe executable
    for proc_exe in /proc/[0-9]*/exe; do
        executable=$(readlink "$proc_exe" 2>/dev/null) || continue
        if [[ ${executable##*/} == cloud-hypervisor ]]; then
            printf '%s\n' "${proc_exe#/proc/}" | cut -d/ -f1
        fi
    done
}

shutdown_socket() {
    local socket_path=$1
    if [[ -S "$socket_path" && -x "$REMOTE_BIN" ]]; then
        "$REMOTE_BIN" --api-socket "$socket_path" shutdown >/dev/null 2>&1 || true
    fi
}

mapfile -t vm_pids < <(cloud_hypervisor_pids)
if ((${#vm_pids[@]} > 0)); then
    echo "Stopping existing Cloud Hypervisor VMs: ${vm_pids[*]}"
    shutdown_socket "$SOURCE_API_SOCKET"
    shutdown_socket "$RESTORE_API_SOCKET"

    for pid in "${vm_pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for _ in {1..50}; do
        remaining=0
        for pid in "${vm_pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                remaining=1
                break
            fi
        done
        [[ "$remaining" == 0 ]] && break
        sleep 0.1
    done
    for pid in "${vm_pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Force stopping Cloud Hypervisor PID $pid"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
else
    echo "No existing Cloud Hypervisor VMs found"
fi

rm -f -- \
    "$SOURCE_PID_FILE" \
    "$SOURCE_API_SOCKET" \
    "$RESTORE_API_SOCKET" \
    "$OFFLOAD_SOCKET" \
    "$OFFLOAD_SOCKET.lock" \
    "$RESTORE_SOCKET"

echo "Cloud Hypervisor benchmark state is clean"