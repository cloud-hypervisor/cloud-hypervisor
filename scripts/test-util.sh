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
    echo "    --hypervisor  Underlying hypervisor. Options kvm, mshv. Auto-detected from the host device node when omitted."
    echo "    --test-filter Tests to run"
    echo ""
    echo "    --help        Display this help message."
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

setup_hugepages_pool() {
    local HUGEPAGE_SIZE="$1"
    local PAGE_NUM="$2"
    local NR_HUGEPAGE_PATH="/sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SIZE}kB/nr_hugepages"

    if [ "$(cat ${NR_HUGEPAGE_PATH} 2>/dev/null || echo 0)" -lt "$PAGE_NUM" ]; then
        echo "$PAGE_NUM" | sudo tee ${NR_HUGEPAGE_PATH}
    fi
}
