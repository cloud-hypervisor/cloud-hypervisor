#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
memory_pattern_override_set=${MEMORY_PATTERN+x}
memory_pattern_override=${MEMORY_PATTERN:-}
source "$BENCHMARK_DIR/common.sh"
if [[ -n "$memory_pattern_override_set" ]]; then
    MEMORY_PATTERN=$memory_pattern_override
fi

: "${GUEST_SSH_TARGET:?Set GUEST_SSH_TARGET, for example cloud@192.168.2.2}"

working_set_mib=${WORKING_SET_MIB:-1536}
shm_size_mib=${SHM_SIZE_MIB:-}
pattern=${MEMORY_PATTERN:-random}
guest_timeout=${GUEST_TIMEOUT:-120}
guest_silesia_path=/tmp/ch-silesia.tar
guest_redis_dir=/tmp/ch-redis-bin
redis_value_size=${REDIS_VALUE_SIZE:-4096}
redis_auto_install=${REDIS_AUTO_INSTALL:-1}

case "$pattern" in
    zero | repeat | random | silesia | redis) ;;
    *)
        echo "MEMORY_PATTERN must be zero, repeat, random, silesia, or redis" >&2
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

if [[ "$pattern" == silesia ]]; then
    silesia_path=${SILESIA_PATH:-$BENCHMARK_DIR/assets/silesia.tar}
    if [[ ! -f "$silesia_path" ]]; then
        SILESIA_PATH=$silesia_path "$BENCHMARK_DIR/download-silesia.sh"
    fi
    echo "Copying Silesia corpus to the guest"
    if [[ -n ${SSH_PASSWORD:-} ]]; then
        SSHPASS=$SSH_PASSWORD sshpass -e scp "${ssh_options[@]}" \
            "$silesia_path" "$GUEST_SSH_TARGET:$guest_silesia_path"
    else
        scp "${ssh_options[@]}" \
            "$silesia_path" "$GUEST_SSH_TARGET:$guest_silesia_path"
    fi
fi

if [[ "$pattern" == redis ]]; then
    redis_server_path=${REDIS_SERVER_PATH:-$(command -v redis-server || true)}
    redis_cli_path=${REDIS_CLI_PATH:-$(command -v redis-cli || true)}
    if [[ -n "$redis_server_path" && -n "$redis_cli_path" ]]; then
        "${ssh_command[@]}" "${ssh_options[@]}" "$GUEST_SSH_TARGET" \
            "mkdir -p '$guest_redis_dir'"
        echo "Copying Redis binaries to the guest"
        if [[ -n ${SSH_PASSWORD:-} ]]; then
            SSHPASS=$SSH_PASSWORD sshpass -e scp "${ssh_options[@]}" \
                "$redis_server_path" "$redis_cli_path" \
                "$GUEST_SSH_TARGET:$guest_redis_dir/"
        else
            scp "${ssh_options[@]}" \
                "$redis_server_path" "$redis_cli_path" \
                "$GUEST_SSH_TARGET:$guest_redis_dir/"
        fi
    fi
fi

echo "Creating ${working_set_mib} MiB '$pattern' working set in guest RAM"
"${ssh_command[@]}" "${ssh_options[@]}" "$GUEST_SSH_TARGET" sh -s -- \
    "$working_set_mib" "$pattern" "$guest_silesia_path" "$guest_redis_dir" \
    "$redis_value_size" "$redis_auto_install" "$shm_size_mib" <<'GUEST_SCRIPT'
set -eu

working_set_mib=$1
pattern=$2
guest_silesia_path=$3
guest_redis_dir=$4
redis_value_size=$5
redis_auto_install=$6
shm_size_mib=$7
output=/dev/shm/ch-snapshot-benchmark.bin
bytes=$((working_set_mib * 1024 * 1024))

rm -f "$output"
if [ -n "$shm_size_mib" ]; then
    sudo mount -o "remount,size=${shm_size_mib}M" /dev/shm
fi
available_mib=$(df -Pm /dev/shm | awk 'NR == 2 { print $4 }')
if [ "$available_mib" -lt "$working_set_mib" ]; then
    echo "/dev/shm has ${available_mib} MiB available; ${working_set_mib} MiB required" >&2
    exit 1
fi

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
    silesia)
        : >"$output"
        while [ "$(wc -c <"$output")" -lt "$bytes" ]; do
            cat "$guest_silesia_path" >>"$output"
        done
        truncate -s "$bytes" "$output"
        ;;
    redis)
        redis_server=$guest_redis_dir/redis-server
        redis_cli=$guest_redis_dir/redis-cli
        chmod +x "$redis_server" "$redis_cli" 2>/dev/null || true
        if ! "$redis_server" --version >/dev/null 2>&1 || ! "$redis_cli" --version >/dev/null 2>&1; then
            redis_server=$(command -v redis-server || true)
            redis_cli=$(command -v redis-cli || true)
        fi
        if [ -z "$redis_server" ] || [ -z "$redis_cli" ]; then
            if [ "$redis_auto_install" != 1 ]; then
                echo "Redis is unavailable; set REDIS_SERVER_PATH and REDIS_CLI_PATH or install it in the guest" >&2
                exit 1
            fi
            sudo apt-get update
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y redis-server redis-tools
            redis_server=$(command -v redis-server)
            redis_cli=$(command -v redis-cli)
        fi
        "$redis_cli" shutdown nosave >/dev/null 2>&1 || true
        "$redis_server" --daemonize yes --save '' --appendonly no --bind 127.0.0.1
        redis_ready=0
        for _ in $(seq 1 100); do
            if [ "$("$redis_cli" ping 2>/dev/null || true)" = PONG ]; then
                redis_ready=1
                break
            fi
            sleep 0.05
        done
        if [ "$redis_ready" != 1 ]; then
            echo "Redis did not become ready" >&2
            exit 1
        fi
        "$redis_cli" flushall >/dev/null
        key_index=0
        batch_limit=4096
        used_memory=$("$redis_cli" --raw info memory | sed -n 's/^used_memory:\([0-9]*\).*/\1/p')
        while [ "$used_memory" -lt "$bytes" ]; do
            remaining=$((bytes - used_memory))
            batch_keys=$(((remaining + redis_value_size - 1) / redis_value_size))
            if [ "$batch_keys" -gt "$batch_limit" ]; then
                batch_keys=$batch_limit
            fi
            python3 - "$key_index" "$batch_keys" "$redis_value_size" <<'PYTHON' | "$redis_cli" --pipe >/dev/null
import hashlib
import sys

first_key = int(sys.argv[1])
key_count = int(sys.argv[2])
value_size = int(sys.argv[3])
if value_size <= 0:
    raise SystemExit("REDIS_VALUE_SIZE must be positive")

for index in range(first_key, first_key + key_count):
    key = f"snapshot:{index}".encode()
    digest = hashlib.sha256(key).digest()
    value = (digest * ((value_size + len(digest) - 1) // len(digest)))[:value_size]
    command = (
        b"*3\r\n$3\r\nSET\r\n$"
        + str(len(key)).encode()
        + b"\r\n"
        + key
        + b"\r\n$"
        + str(len(value)).encode()
        + b"\r\n"
        + value
        + b"\r\n"
    )
    sys.stdout.buffer.write(command)
PYTHON
            key_index=$((key_index + batch_keys))
            used_memory=$("$redis_cli" --raw info memory | sed -n 's/^used_memory:\([0-9]*\).*/\1/p')
        done
        "$redis_cli" dbsize
        "$redis_cli" info memory | grep -E '^used_memory(_rss)?_human:'
        ;;
esac

sync
if [ "$pattern" != redis ]; then
    wc -c "$output"
fi
GUEST_SCRIPT

if [[ ${PAUSE_AFTER_PREPARE:-1} == 1 ]]; then
    "$BENCHMARK_DIR/source-vm.sh" pause
fi

echo "Guest working set is ready. Run: ./benchmark/run-matrix.sh snapshot"