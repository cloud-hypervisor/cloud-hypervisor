#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

usage() {
    cat >&2 <<EOF
Usage:
  KERNEL_PATH=/path/vmlinux DISK_PATH=/path/disk.raw $0 start [-- EXTRA_CH_ARGS...]
  $0 pause|resume|stop|status
EOF
    exit 2
}

running_pid() {
    [[ -f "$SOURCE_PID_FILE" ]] || return 1
    local pid
    pid=$(<"$SOURCE_PID_FILE")
    kill -0 "$pid" 2>/dev/null || return 1
    printf '%s\n' "$pid"
}

start_vm() {
    require_executable "$CH_BIN"
    if pid=$(running_pid); then
        echo "Source VM is already running with PID $pid" >&2
        exit 1
    fi
    : "${KERNEL_PATH:?Set KERNEL_PATH to an uncompressed guest kernel}"
    : "${DISK_PATH:?Set DISK_PATH to a bootable guest disk image}"
    [[ -f "$KERNEL_PATH" ]] || {
        echo "Kernel not found: $KERNEL_PATH" >&2
        exit 1
    }
    [[ -f "$DISK_PATH" ]] || {
        echo "Disk image not found: $DISK_PATH" >&2
        exit 1
    }

    local image_type=${IMAGE_TYPE:-}
    if [[ -z "$image_type" ]]; then
        case "$DISK_PATH" in
            *.qcow2) image_type=qcow2 ;;
            *) image_type=raw ;;
        esac
    fi

    local vm_disk=$DISK_PATH
    if [[ ${COPY_DISK:-1} == 1 ]]; then
        local extension=${DISK_PATH##*.}
        vm_disk=${WORKING_DISK_PATH:-$RESULTS_DIR/source-working.$extension}
        echo "Creating benchmark disk copy: $vm_disk"
        cp --reflink=auto --sparse=always "$DISK_PATH" "$vm_disk"
    fi

    local disk_config="path=$vm_disk,image_type=$image_type"
    if [[ -n ${DISK_OPTIONS:-} ]]; then
        disk_config+=",$DISK_OPTIONS"
    fi

    local disk_args=(--disk "$disk_config")
    if [[ ${CREATE_CLOUD_INIT:-1} == 1 ]]; then
        "$BENCHMARK_DIR/create-cloud-init.sh"
        disk_args+=("path=${CLOUD_INIT_PATH:-$RESULTS_DIR/cloud-init.img},image_type=raw")
    fi

    if [[ ${1:-} == -- ]]; then
        shift
    fi
    local extra_args=("$@")

    rm -f -- "$SOURCE_API_SOCKET" "$SOURCE_PID_FILE"
    : >"$SOURCE_VMM_LOG"
    : >"$SOURCE_SERIAL_LOG"
    "${NUMA_PREFIX[@]}" "$CH_BIN" \
        --api-socket "$SOURCE_API_SOCKET" \
        --cpus "boot=${VCPUS:-2}" \
        --memory "size=${MEMORY_SIZE:-1G},shared=on" \
        --kernel "$KERNEL_PATH" \
        --cmdline "${KERNEL_CMDLINE:-root=/dev/vda1 console=hvc0 rw}" \
        "${disk_args[@]}" \
        --serial off \
        --console "file=$SOURCE_SERIAL_LOG" \
        "${extra_args[@]}" >"$SOURCE_VMM_LOG" 2>&1 &
    local pid=$!
    printf '%s\n' "$pid" >"$SOURCE_PID_FILE"
    if ! wait_for_socket "$SOURCE_API_SOCKET"; then
        terminate_process "$pid"
        rm -f -- "$SOURCE_PID_FILE"
        exit 1
    fi
    echo "Source VM started: PID $pid"
    echo "API socket: $SOURCE_API_SOCKET"
    echo "Serial log: $SOURCE_SERIAL_LOG"
    echo "Wait for guest boot, then run benchmark/prepare-memory.sh."
}

control_vm() {
    local action=$1
    require_executable "$REMOTE_BIN"
    [[ -S "$SOURCE_API_SOCKET" ]] || {
        echo "Source API socket is not available: $SOURCE_API_SOCKET" >&2
        exit 1
    }
    "$REMOTE_BIN" --api-socket "$SOURCE_API_SOCKET" "$action"
    echo "Source VM: $action"
}

stop_vm() {
    local pid=
    pid=$(running_pid || true)
    if [[ -S "$SOURCE_API_SOCKET" ]]; then
        "$REMOTE_BIN" --api-socket "$SOURCE_API_SOCKET" shutdown || true
    fi
    for _ in {1..50}; do
        if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    terminate_process "$pid"
    rm -f -- "$SOURCE_PID_FILE" "$SOURCE_API_SOCKET"
    echo "Source VM stopped"
}

status_vm() {
    if pid=$(running_pid); then
        echo "Source VM running: PID $pid, API socket $SOURCE_API_SOCKET"
    else
        echo "Source VM is not running"
        return 1
    fi
}

[[ $# -ge 1 ]] || usage
action=$1
shift
case "$action" in
    start) start_vm "$@" ;;
    pause | resume) control_vm "$action" ;;
    stop) stop_vm ;;
    status) status_vm ;;
    *) usage ;;
esac