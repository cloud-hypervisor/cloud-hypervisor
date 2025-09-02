#!/usr/bin/env bash
# shellcheck disable=SC2048,SC2086
set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

process_common_args "$@"

migratable_version=v39.0
# For now these values are default for kvm
test_features=""

if [ "$hypervisor" = "mshv" ]; then
    test_features="--features mshv"
fi

# if migratable version is set to override the default
if [ -n "${MIGRATABLE_VERSION}" ]; then
    # validate the version if matched with vxx.0
    if ! [[ "${MIGRATABLE_VERSION}" =~ ^v[0-9]{2,}\.[0-9]$ ]]; then
        echo "MIGRATABLE_VERSION should be in format vxx.0, e.g. v47.0"
        exit 1
    fi
    migratable_version=${MIGRATABLE_VERSION}
fi
cp scripts/sha1sums-x86_64 "$WORKLOADS_DIR"

FOCAL_OS_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.qcow2"
FOCAL_OS_IMAGE_URL="https://ch-images.azureedge.net/$FOCAL_OS_IMAGE_NAME"
FOCAL_OS_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time wget --quiet $FOCAL_OS_IMAGE_URL || exit 1
    popd || exit
fi

FOCAL_OS_RAW_IMAGE_NAME="focal-server-cloudimg-amd64-custom-20210609-0.raw"
FOCAL_OS_RAW_IMAGE="$WORKLOADS_DIR/$FOCAL_OS_RAW_IMAGE_NAME"
if [ ! -f "$FOCAL_OS_RAW_IMAGE" ]; then
    pushd "$WORKLOADS_DIR" || exit
    time qemu-img convert -p -f qcow2 -O raw $FOCAL_OS_IMAGE_NAME $FOCAL_OS_RAW_IMAGE_NAME || exit 1
    popd || exit
fi

pushd "$WORKLOADS_DIR" || exit
if ! grep focal sha1sums-x86_64 | sha1sum --check; then
    echo "sha1sum validation of images failed, remove invalid images to fix the issue."
    exit 1
fi
popd || exit

# Download Cloud Hypervisor binary from its last stable release
CH_RELEASE_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${migratable_version}/cloud-hypervisor-static"
CH_RELEASE_NAME="cloud-hypervisor-static"
pushd "$WORKLOADS_DIR" || exit
time wget --quiet $CH_RELEASE_URL -O "$CH_RELEASE_NAME" || exit 1
chmod +x $CH_RELEASE_NAME
popd || exit

# Build custom kernel based on virtio-pmem and virtio-fs upstream patches
VMLINUX_IMAGE="$WORKLOADS_DIR/vmlinux-x86_64"
if [ ! -f "$VMLINUX_IMAGE" ]; then
    # Prepare linux image (build from source or download pre-built)
    prepare_linux
fi

CFLAGS=""
if [[ "${BUILD_TARGET}" == "x86_64-unknown-linux-musl" ]]; then
    # shellcheck disable=SC2034
    CFLAGS="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
fi

cargo build --features mshv --all --release --target "$BUILD_TARGET"

# Test ovs-dpdk relies on hugepages
HUGEPAGESIZE=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
PAGE_NUM=$((12288 * 1024 / HUGEPAGESIZE))
echo "$PAGE_NUM" | sudo tee /proc/sys/vm/nr_hugepages
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
