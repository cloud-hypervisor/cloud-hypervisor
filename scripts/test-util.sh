#!/bin/bash
hypervisor="kvm"
cmd_help() {
    echo ""
    echo "Cloud Hypervisor $(basename $0)"
    echo "Usage: $(basename $0) [<args>]"
    echo ""
    echo "Available arguments:"
    echo ""
    echo "    --hypervisor  Underlying hypervisor. Options kvm, mshv"
    echo ""
    echo "    --help        Display this help message."
    echo ""
}

process_common_args() {
    while [ $# -gt 0 ]; do
	case "$1" in
            "-h"|"--help")  { cmd_help; exit 1; } ;;
            "--hypervisor")
                shift
                hypervisor="$1"
                ;;
            *)
            # We only care about hypervisor , do nothing for other arguments
		;;
	esac
	shift
    done
    if [[ "$hypervisor" != "kvm" ]]; then
        echo "Hypervisor value must be kvm"
        exit 1
    fi
}