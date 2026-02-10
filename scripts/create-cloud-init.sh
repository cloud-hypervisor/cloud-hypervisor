#!/usr/bin/env bash
set -ex

usage() {
    echo "Usage: $0 [-o|--output <output_file>]"
    echo ""
    echo "Options:"
    echo "  -o, --output    Specify output file path (default: /tmp/ubuntu-cloudinit.img)"
    echo "  -h, --help      Show this help message"
}

OUTPUT_FILE=/tmp/ubuntu-cloudinit.img

while [ "$1" != "" ]; do
    echo "Processing argument: $1"
    case $1 in
    -o | --output)
        OUTPUT_FILE=$2
        shift # Remove argument (-o) name from `$@`
        shift # Remove argument value (file path) from `$@`
        ;;
    -h | --help)
        usage # run usage function on help
        exit 0
        ;;
    *)
        usage # run usage function if wrong argument provided
        exit 1
        ;;
    esac
done

rm -f "$OUTPUT_FILE"
mkdosfs -n CIDATA -C "$OUTPUT_FILE" 8192
mcopy -oi "$OUTPUT_FILE" -s test_data/cloud-init/ubuntu/local/user-data ::
mcopy -oi "$OUTPUT_FILE" -s test_data/cloud-init/ubuntu/local/meta-data ::
mcopy -oi "$OUTPUT_FILE" -s test_data/cloud-init/ubuntu/local/network-config ::
