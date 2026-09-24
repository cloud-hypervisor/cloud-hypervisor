#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$BENCHMARK_DIR/.." && pwd)
source "$BENCHMARK_DIR/common.sh"

usage() {
    cat <<EOF
Usage: $0 [--dry-run]

Runs the complete compression benchmark:
  build -> download assets -> create TAP -> start VM -> prepare memory
  -> snapshot matrix -> stop source VM -> restore matrix -> KPI report

Configuration is read from benchmark/benchmark.env and environment variables.
EOF
}

dry_run=0
case ${1:-} in
    "") ;;
    --dry-run) dry_run=1 ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

BUILD_BINARIES=${BUILD_BINARIES:-1}
DOWNLOAD_ASSETS=${DOWNLOAD_ASSETS:-1}
ASSET_DIR=${ASSET_DIR:-$BENCHMARK_DIR/assets}
KERNEL_PATH=${KERNEL_PATH:-$ASSET_DIR/vmlinux-x86_64}
DISK_PATH=${DISK_PATH:-$ASSET_DIR/jammy-server-cloudimg-amd64-custom-20241017-0.qcow2}
TAP_NAME=${TAP_NAME:-tap0}
TAP_HOST_CIDR=${TAP_HOST_CIDR:-192.168.2.1/25}
GUEST_MAC=${GUEST_MAC:-12:34:56:78:90:ab}
GUEST_SSH_TARGET=${GUEST_SSH_TARGET:-cloud@192.168.2.2}
SSH_PASSWORD=${SSH_PASSWORD:-cloud123}
MEMORY_SIZE=${MEMORY_SIZE:-4G}
VCPUS=${VCPUS:-4}
WORKING_SET_MIB=${WORKING_SET_MIB:-1536}
MEMORY_PATTERN=${MEMORY_PATTERN:-random}
WITH_QPL=${WITH_QPL:-1}
CHUNK_SIZES=${CHUNK_SIZES:-1048576}
SOFTWARE_WORKER_COUNTS=${SOFTWARE_WORKER_COUNTS:-${WORKER_COUNTS:-1 2 4}}
QPL_SYNC_WORKER_COUNTS=${QPL_SYNC_WORKER_COUNTS:-4 8 16}
QPL_ASYNC_SNAPSHOT_DEPTHS=${QPL_ASYNC_SNAPSHOT_DEPTHS:-8 16 32}
QPL_ASYNC_RESTORE_DEPTHS=${QPL_ASYNC_RESTORE_DEPTHS:-32 64 128}
ITERATIONS=${ITERATIONS:-3}
WARMUPS=${WARMUPS:-1}
CLEAN_RESULTS=${CLEAN_RESULTS:-1}
CLEANUP_TAP=${CLEANUP_TAP:-1}
CLEANUP_EXISTING_VMS=${CLEANUP_EXISTING_VMS:-1}
REPORT_CSV=${REPORT_CSV:-$RESULTS_DIR/kpi-report.csv}
AUTO_SETUP=${AUTO_SETUP:-1}

if [[ -z ${CODECS:-} ]]; then
    if [[ "$WITH_QPL" == 1 ]]; then
        CODECS="raw lz4 zstd qpl-hardware-static qpl-hardware-dynamic qpl-hardware-static-async qpl-hardware-dynamic-async"
    else
        CODECS="raw lz4 zstd"
    fi
fi

cat <<EOF
Cloud Hypervisor compression benchmark
  kernel:       $KERNEL_PATH
  disk:         $DISK_PATH
  VM:           $VCPUS vCPUs, $MEMORY_SIZE RAM
  guest data:   $WORKING_SET_MIB MiB, $MEMORY_PATTERN
  codecs:       $CODECS
    chunk sizes:  $CHUNK_SIZES
    CPU workers:  $SOFTWARE_WORKER_COUNTS
    QPL sync:     $QPL_SYNC_WORKER_COUNTS
    QPL async:    snapshot [$QPL_ASYNC_SNAPSHOT_DEPTHS], restore [$QPL_ASYNC_RESTORE_DEPTHS]
    NUMA node:    ${NUMA_NODE:-unbound}
  iterations:   $ITERATIONS measured + $WARMUPS warm-up
  results:      $RESULTS_DIR
EOF

if [[ "$dry_run" == 1 ]]; then
    exit 0
fi

source_vm_started=0
tap_created=0

run_privileged() {
    if ((EUID == 0)); then
        "$@"
    else
        command -v sudo >/dev/null || {
            echo "sudo is required to create the TAP interface" >&2
            exit 1
        }
        sudo "$@"
    fi
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ "$source_vm_started" == 1 ]]; then
        "$BENCHMARK_DIR/source-vm.sh" stop || true
    fi
    if [[ "$tap_created" == 1 && "$CLEANUP_TAP" == 1 ]]; then
        run_privileged ip link delete "$TAP_NAME" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

if [[ "$CLEANUP_EXISTING_VMS" == 1 ]]; then
    echo "==> Cleaning up existing Cloud Hypervisor VMs"
    "$BENCHMARK_DIR/cleanup-vms.sh"
fi

if ! WITH_QPL=$WITH_QPL "$BENCHMARK_DIR/setup.sh" --check; then
    if [[ "$AUTO_SETUP" != 1 ]]; then
        echo "Dependencies are missing and AUTO_SETUP=0." >&2
        echo "Run: $BENCHMARK_DIR/setup.sh" >&2
        exit 1
    fi
    echo "==> Installing missing benchmark dependencies"
    WITH_QPL=$WITH_QPL "$BENCHMARK_DIR/setup.sh"
fi
export PATH="${HOME:-}/.cargo/bin:$PATH"

if [[ "$BUILD_BINARIES" == 1 ]]; then
    echo "==> Building benchmark binaries"
    WITH_QPL=$WITH_QPL "$BENCHMARK_DIR/build.sh"
fi

if [[ ! -f "$KERNEL_PATH" || ! -f "$DISK_PATH" ]]; then
    if [[ "$DOWNLOAD_ASSETS" != 1 ]]; then
        echo "Kernel or disk image is missing and DOWNLOAD_ASSETS=0" >&2
        exit 1
    fi
    echo "==> Downloading canonical test assets"
    ASSET_DIR=$ASSET_DIR "$BENCHMARK_DIR/download-assets.sh"
fi

require_executable "$CH_BIN"
require_executable "$REMOTE_BIN"
require_executable "$OFFLOAD_BIN"
command -v ip >/dev/null || {
    echo "iproute2 is required to configure guest networking" >&2
    exit 1
}
if [[ -n "$SSH_PASSWORD" ]]; then
    command -v sshpass >/dev/null || {
        echo "sshpass is required for the canonical guest password login" >&2
        echo "Install sshpass or configure SSH_KEY and clear SSH_PASSWORD." >&2
        exit 1
    }
fi

if ! ip link show "$TAP_NAME" >/dev/null 2>&1; then
    echo "==> Creating TAP interface $TAP_NAME"
    tap_owner=${SUDO_USER:-${USER:-$(id -un)}}
    run_privileged ip tuntap add "$TAP_NAME" mode tap user "$tap_owner"
    tap_created=1
fi
if ! ip -o address show dev "$TAP_NAME" | grep -Fq "${TAP_HOST_CIDR%/*}/"; then
    run_privileged ip address add "$TAP_HOST_CIDR" dev "$TAP_NAME"
fi
run_privileged ip link set "$TAP_NAME" up

if [[ "$CLEAN_RESULTS" == 1 ]]; then
    echo "==> Removing previous benchmark results"
    rm -rf -- "$SNAPSHOT_ROOT"
    rm -f -- "$RESULTS_CSV" "$REPORT_CSV"
    mkdir -p "$SNAPSHOT_ROOT"
fi

echo "==> Starting source VM"
start_args=(--net "tap=$TAP_NAME,mac=$GUEST_MAC")
if [[ -n ${EXTRA_CH_ARGS:-} ]]; then
    read -r -a configured_args <<<"$EXTRA_CH_ARGS"
    start_args+=("${configured_args[@]}")
fi
KERNEL_PATH=$KERNEL_PATH \
DISK_PATH=$DISK_PATH \
MEMORY_SIZE=$MEMORY_SIZE \
VCPUS=$VCPUS \
    "$BENCHMARK_DIR/source-vm.sh" start -- "${start_args[@]}"
source_vm_started=1

echo "==> Preparing guest memory and pausing source VM"
GUEST_SSH_TARGET=$GUEST_SSH_TARGET \
SSH_KEY=${SSH_KEY:-} \
SSH_PASSWORD=$SSH_PASSWORD \
WORKING_SET_MIB=$WORKING_SET_MIB \
MEMORY_PATTERN=$MEMORY_PATTERN \
PAUSE_AFTER_PREPARE=1 \
    "$BENCHMARK_DIR/prepare-memory.sh"

export CODECS CHUNK_SIZES SOFTWARE_WORKER_COUNTS QPL_SYNC_WORKER_COUNTS
export QPL_ASYNC_SNAPSHOT_DEPTHS QPL_ASYNC_RESTORE_DEPTHS ITERATIONS WARMUPS WITH_QPL

echo "==> Running snapshot matrix"
RESET_RESULTS=1 "$BENCHMARK_DIR/run-matrix.sh" snapshot

echo "==> Stopping source VM before restore"
"$BENCHMARK_DIR/source-vm.sh" stop
source_vm_started=0

echo "==> Running restore matrix"
RESET_RESULTS=0 "$BENCHMARK_DIR/run-matrix.sh" restore

echo "==> Key performance indicators"
"$BENCHMARK_DIR/report.py" "$RESULTS_CSV" "$REPORT_CSV"

echo "Benchmark complete"
echo "  Raw results: $RESULTS_CSV"
echo "  KPI report:  $REPORT_CSV"