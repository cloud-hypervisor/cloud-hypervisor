#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

: "${GUEST_SSH_TARGET:?Set GUEST_SSH_TARGET, for example cloud@192.168.2.2}"

working_set_mib=${WORKING_SET_MIB:-1536}
pattern=${MEMORY_PATTERN:-random}
guest_timeout=${GUEST_TIMEOUT:-120}

case "$pattern" in
    zero | repeat | random) ;;
    *)
        echo "MEMORY_PATTERN must be zero, repeat, or random" >&2
        exit 2
        ;;
esac

ssh_command=(ssh)
ssh_options=(
    -o BatchMode=yes
    -o ConnectTimeout=2
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
)
if [[ -n ${SSH_KEY:-} ]]; then
    ssh_options+=(-i "$SSH_KEY")
fi
if [[ -n ${SSH_PASSWORD:-} ]]; then
    command -v sshpass >/dev/null || {
        echo "SSH_PASSWORD requires sshpass" >&2
        exit 1
    }
    export SSHPASS=$SSH_PASSWORD
    ssh_command=(sshpass -e ssh)
    ssh_options=(
        -o BatchMode=no
        -o ConnectTimeout=2
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
    )
fi
if [[ -n ${SSH_OPTIONS:-} ]]; then
    read -r -a configured_options <<<"$SSH_OPTIONS"
    ssh_options+=("${configured_options[@]}")
fi

echo "Waiting for SSH at $GUEST_SSH_TARGET"
waited=0
until "${ssh_command[@]}" "${ssh_options[@]}" "$GUEST_SSH_TARGET" true 2>/dev/null; do
    if ((waited >= guest_timeout)); then
        echo "Timed out waiting for guest SSH" >&2
        exit 1
    fi
    sleep 1
    ((waited += 1))
done

echo "Creating ${working_set_mib} MiB '$pattern' working set in guest RAM"
"${ssh_command[@]}" "${ssh_options[@]}" "$GUEST_SSH_TARGET" sh -s -- \
    "$working_set_mib" "$pattern" <<'GUEST_SCRIPT'
set -eu

working_set_mib=$1
pattern=$2
output=/dev/shm/ch-snapshot-benchmark.bin
bytes=$((working_set_mib * 1024 * 1024))

case "$pattern" in
    zero)
        dd if=/dev/zero of="$output" bs=1M count="$working_set_mib" status=none
        ;;
    repeat)
        yes cloud-hypervisor-snapshot-benchmark | head -c "$bytes" >"$output"
        ;;
    random)
        dd if=/dev/urandom of="$output" bs=1M count="$working_set_mib" status=none
        ;;
esac

sync
wc -c "$output"
GUEST_SCRIPT

if [[ ${PAUSE_AFTER_PREPARE:-1} == 1 ]]; then
    "$BENCHMARK_DIR/source-vm.sh" pause
fi

echo "Guest working set is ready. Run: ./benchmark/run-matrix.sh snapshot"