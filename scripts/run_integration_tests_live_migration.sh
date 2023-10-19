#!/bin/bash
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ] ;  then
    test_features="--features mshv"
fi

cp scripts/sha1sums-x86_64 $WORKLOADS_DIR

FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.qcow2"
FOCAL_OS_IMAGE_URL="https://cloud-hypervisor.azureedge.net/$FOCAL_OS_IMAGE_NAME"
FOCAL_OS_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $FOCAL_OS_IMAGE_URL || exit 1
    popd
fi

FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.raw"
FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $FOCAL_OS_IMAGE_NAME $FOCAL_OS_RAW_IMAGE_NAME || exit 1
    popd
fi

pushd $WORKLOADS_DIR
grep focal sha1sums-x86_64 | sha1sum --check
if [ $? -ne 0 ]; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd

# Download Cloud Hypervisor binary from its last stable release
LAST_RELEASE_VERSION="v34.0"
CH_RELEASE_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$LAST_RELEASE_VERSION/cloud-hypervisor-static"
CH_RELEASE_NAME="cloud-hypervisor-static"
pushd $WORKLOADS_DIR
time wget --quiet $CH_RELEASE_URL -O "$CH_RELEASE_NAME" || exit 1
chmod +x $CH_RELEASE_NAME
popd

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux"
if [ ! -f "$VMLINUX_IMAGE" ]; then
    build_custom_linux
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target $BUILD_TARGET

# Test ovs-dpdk relies on hugepages
HUGEPAGESIZE=`grep Hugepagesize /proc/meminfo | awk '{print $2}'`
PAGE_NUM=`echo $((12288 * 1024 / $HUGEPAGESIZE))`
echo $PAGE_NUM | sudo tee /proc/sys/vm/nr_hugepages
sudo chmod a+rwX /dev/hugepages

export RUST_BACKTRACE=1
time cargo test $test_features "live_migration_parallel::$test_filter" -- ${test_binary_args[*]}
RES=$?

# Run some tests in sequence since the result could be affected by other tests
# running in parallel.
if [ $RES -eq 0 ]; then
    export RUST_BACKTRACE=1
    time cargo test $test_features "live_migration_sequential::$test_filter" -- --test-threads=1 ${test_binary_args[*]}
    RES=$?
fi

exit $RES
