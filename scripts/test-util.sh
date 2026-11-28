#!/usr/bin/env bash
# shellcheck disable=SC1009,SC2048,SC2086,SC1073,SC1040,SC1072
# shellcheck source=/dev/null
set -x

test_filter=""

# Auto-detect the underlying hypervisor based on the device node exposed
# by the host kernel: /dev/mshv for MSHV, /dev/kvm for KVM.
# shellcheck disable=SC2034
detect_hypervisor() {
    if [ -e /dev/mshv ]; then
        hypervisor="mshv"
    elif [ -e /dev/kvm ]; then
        hypervisor="kvm"
    else
        echo "ERROR: no hypervisor device found (/dev/mshv or /dev/kvm)" >&2
        exit 1
    fi
}

cmd_help() {
    echo ""
    echo "Cloud Hypervisor $(basename "$0")"
    echo "Usage: $(basename "$0") [<args>]"
    echo ""
    echo "Available arguments:"
    echo ""
    echo "    --hypervisor   Underlying hypervisor. Options kvm, mshv. Auto-detected from the host device node when omitted."
    echo "    --test-filter  Tests to run"
    echo "    --test-exclude Tests to skip (only for the metrics tests)"
    echo ""
    echo "    --help         Display this help message."
    echo ""
}

# shellcheck disable=SC2034
process_common_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
        "-h" | "--help") {
            cmd_help
            exit 1
        } ;;
        "--hypervisor")
            shift
            hypervisor="$1"
            ;;
        "--test-filter")
            shift
            test_filter="$1"
            ;;
        "--test-exclude")
            shift
            test_exclude="$1"
            ;;
        "--") {
            shift
            break
        } ;;
        *)
            echo "Unknown test scripts argument: $1. Please use '-- --help' for help."
            exit
            ;;
        esac
        shift
    done
    # Auto-detect the hypervisor when it was not provided explicitly.
    if [ -z "$hypervisor" ]; then
        detect_hypervisor
    fi
    if [[ ! ("$hypervisor" = "kvm" || "$hypervisor" = "mshv") ]]; then
        echo "ERROR: hypervisor must be kvm or mshv" >&2
        exit 1
    fi
    # shellcheck disable=SC2034
    test_binary_args=("$@")
}

# Print one sample of host load, memory and /tmp usage as a line of the
# load.csv telemetry file. The pressure values are percentages of time
# stalled over the last 10 seconds.
sample_load() {
    awk -v time="$(date +%s)" \
        -v vms="$(cat /proc/[0-9]*/comm 2>/dev/null | grep -c '^cloud-hyperviso')" \
        -v tmp_used="$(df -m --output=used /tmp | tail -1 | tr -d ' ')" '
        function pressure(file, kind,    line, fields, value) {
            while ((getline line <file) > 0) {
                split(line, fields, "[ =]")
                if (fields[1] == kind)
                    value = fields[3]
            }
            close(file)
            return value
        }
        BEGIN {
            getline line <"/proc/loadavg"
            split(line, load, " ")
            while ((getline line <"/proc/meminfo") > 0) {
                split(line, fields, "[: ]+")
                mem[fields[1]] = fields[2]
            }
            printf "%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s\n", time, load[1], vms,
                mem["MemAvailable"] / 1024, mem["Shmem"] / 1024,
                (mem["SwapTotal"] - mem["SwapFree"]) / 1024, tmp_used,
                pressure("/proc/pressure/cpu", "some"),
                pressure("/proc/pressure/memory", "some"),
                pressure("/proc/pressure/memory", "full"),
                pressure("/proc/pressure/io", "some")
        }'
}

# Collect telemetry for the integration tests in $WORKLOADS_DIR/telemetry
# until the calling script exits: a sample of host load every 10 seconds in
# load.csv, and the guest boot timings that test_infra appends to boots.csv.
start_telemetry() {
    local dir="$WORKLOADS_DIR/telemetry"

    mkdir -p "$dir"
    echo "time,load1,vms,mem_available_mib,shmem_mib,swap_used_mib,tmp_used_mib,cpu_some,memory_some,memory_full,io_some" >"$dir/load.csv"
    echo "time,test,attempt,disk_prepare_s,boot_wait_s,since_created_s,booted" >"$dir/boots.csv"
    (
        set +x
        while true; do
            sample_load >>"$dir/load.csv"
            sleep 10
        done
    ) &
    # shellcheck disable=SC2064
    trap "kill $!" EXIT
}

setup_hugepages_pool() {
    local HUGEPAGE_SIZE="$1"
    local PAGE_NUM="$2"
    local NR_HUGEPAGE_PATH="/sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SIZE}kB/nr_hugepages"

    if [ "$(cat ${NR_HUGEPAGE_PATH} 2>/dev/null || echo 0)" -lt "$PAGE_NUM" ]; then
        echo "$PAGE_NUM" | sudo tee ${NR_HUGEPAGE_PATH}
    fi
}
