#!/bin/bash
set -x

source $HOME/.cargo/env

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

FW_URL=$(curl --silent https://api.github.com/repos/intel/rust-hypervisor-firmware/releases/latest | grep "browser_download_url" | grep -o 'https://.*[^ "]')
FW="$WORKLOADS_DIR/hypervisor-fw"
if [ ! -f "$FW" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $FW_URL
    popd
fi

OS_IMAGE_NAME="clear-29620-cloud.img"
OS_IMAGE_URL="https://download.clearlinux.org/releases/29620/clear/clear-29620-cloud.img.xz"
OS_IMAGE="$WORKLOADS_DIR/$OS_IMAGE_NAME"
if [ ! -f "$OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    wget --quiet $OS_IMAGE_URL
    unxz $OS_IMAGE_NAME.xz
popd
fi

rm /tmp/cloudinit.img
mkdosfs -n config-2 -C /tmp/cloudinit.img 8192
mcopy -oi /tmp/cloudinit.img -s test_data/cloud-init/openstack ::

cargo build
sudo setcap cap_net_admin+ep target/debug/cloud-hypervisor

# Tests must be executed serially for now as they have a hardcoded IP address
cargo test --features "integration_tests" -- --test-threads=1