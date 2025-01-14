#!/usr/bin/env bash
hypervisor="kvm"
test_filter=""
build_kernel=false

# Checkout source code of a GIT repo with specified branch and commit
# Args:
#   $1: Target directory
#   $2: GIT URL of the repo
#   $3: Required branch
#   $4: Required commit (optional)
checkout_repo() {
    SRC_DIR="$1"
    GIT_URL="$2"
    GIT_BRANCH="$3"
    GIT_COMMIT="$4"

    # Check whether the local HEAD commit same as the requested commit or not.
    # If commit is not specified, compare local HEAD and remote HEAD.
    # Remove the folder if there is difference.
    if [ -d "$SRC_DIR" ]; then
        pushd "$SRC_DIR" || exit
        git fetch
        SRC_LOCAL_COMMIT=$(git rev-parse HEAD)
        if [ -z "$GIT_COMMIT" ]; then
            GIT_COMMIT=$(git rev-parse remotes/origin/"$GIT_BRANCH")
        fi
        popd || exit
        if [ "$SRC_LOCAL_COMMIT" != "$GIT_COMMIT" ]; then
            rm -rf "$SRC_DIR"
        fi
    fi

    # Checkout the specified branch and commit (if required)
    if [ ! -d "$SRC_DIR" ]; then
        git clone --depth 1 "$GIT_URL" -b "$GIT_BRANCH" "$SRC_DIR"
        if [ "$GIT_COMMIT" ]; then
            pushd "$SRC_DIR" || exit
            git fetch --depth 1 origin "$GIT_COMMIT"
            git reset --hard FETCH_HEAD
            popd || exit
        fi
    fi
}

# Not actively used by CI
build_custom_linux() {
    ARCH=$(uname -m)
    SRCDIR=$PWD
    LINUX_CUSTOM_DIR="$WORKLOADS_DIR/linux-custom"
    LINUX_CUSTOM_BRANCH="ch-6.12"
    LINUX_CUSTOM_URL="https://github.com/cloud-hypervisor/linux.git"

    checkout_repo "$LINUX_CUSTOM_DIR" "$LINUX_CUSTOM_URL" "$LINUX_CUSTOM_BRANCH"

    cp "$SRCDIR"/resources/linux-config-"${ARCH}" "$LINUX_CUSTOM_DIR"/.config

    pushd "$LINUX_CUSTOM_DIR" || exit
    make -j "$(nproc)"
    if [ "${ARCH}" == "x86_64" ]; then
        cp vmlinux "$WORKLOADS_DIR/" || exit 1
        cp arch/x86/boot/bzImage "$WORKLOADS_DIR/" || exit 1
    elif [ "${ARCH}" == "aarch64" ]; then
        cp arch/arm64/boot/Image "$WORKLOADS_DIR/" || exit 1
        cp arch/arm64/boot/Image.gz "$WORKLOADS_DIR/" || exit 1
    fi
    popd || exit
}

cmd_help() {
    echo ""
    echo "Cloud Hypervisor $(basename "$0")"
    echo "Usage: $(basename "$0") [<args>]"
    echo ""
    echo "Available arguments:"
    echo ""
    echo "    --hypervisor  Underlying hypervisor. Options kvm, mshv"
    echo "    --test-filter Tests to run"
    echo "    --build-guest-kernel Build guest kernel from source instead of downloading pre-built"
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
        "--build-guest-kernel")
            build_kernel=true
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
    if [[ ! ("$hypervisor" = "kvm" || "$hypervisor" = "mshv") ]]; then
        die "Hypervisor value must be kvm or mshv"
    fi
    # shellcheck disable=SC2034
    test_binary_args=("$@")
}

download_hypervisor_fw() {
    FW_TAG="0.5.0"
    if [ -n "$AUTH_DOWNLOAD_TOKEN" ]; then
        echo "Using authenticated download from GitHub"
        FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/tags/${FW_TAG} \
            --header "Authorization: Token $AUTH_DOWNLOAD_TOKEN" \
            --header "X-GitHub-Api-Version: 2022-11-28" | grep "browser_download_url" |
            grep -oP '"https://[^"]*hypervisor-fw"' | sed -e 's/^"//' -e 's/"$//')
    else
        echo "Using anonymous download from GitHub"
        FW_URL=$(curl --silent https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/tags/${FW_TAG} |
            grep "browser_download_url" | grep -oP '"https://[^"]*hypervisor-fw"' | sed -e 's/^"//' -e 's/"$//')
    fi
    FW="$WORKLOADS_DIR/hypervisor-fw"
    pushd "$WORKLOADS_DIR" || exit
    rm -f "$FW"
    time wget --quiet "$FW_URL" || exit 1
    popd || exit
}

download_linux() {
    KERNEL_TAG="ch-release-v6.12.8-20250114"
    if [ -n "$AUTH_DOWNLOAD_TOKEN" ]; then
        echo "Using authenticated download from GitHub"
        KERNEL_URLS=$(curl --silent https://api.github.com/repos/cloud-hypervisor/linux/releases/tags/${KERNEL_TAG} \
            --header "Authorization: Token $AUTH_DOWNLOAD_TOKEN" \
            --header "X-GitHub-Api-Version: 2022-11-28" | grep "browser_download_url" | grep -o 'https://.*[^ "]')
    else
        echo "Using anonymous download from GitHub"
        KERNEL_URLS=$(curl --silent https://api.github.com/repos/cloud-hypervisor/linux/releases/tags/${KERNEL_TAG} | grep "browser_download_url" | grep -o 'https://.*[^ "]')
    fi
    pushd "$WORKLOADS_DIR" || exit
    for url in $KERNEL_URLS; do
        wget -N --quiet "$url" || exit 1
    done

    popd || exit
}

prepare_linux() {
    if [ "$build_kernel" = true ]; then
        echo "Building kernel from source"
        build_custom_linux
        echo "Using kernel built from source"
    else
        echo "Downloading pre-built kernel from GitHub"
        download_linux
        echo "Using kernel downloaded from GitHub"
    fi
}

download_ovmf() {
    OVMF_FW_TAG="ch-a54f262b09"
    OVMF_FW_URL="https://github.com/cloud-hypervisor/edk2/releases/download/$OVMF_FW_TAG/CLOUDHV.fd"
    OVMF_FW="$WORKLOADS_DIR/CLOUDHV.fd"
    pushd "$WORKLOADS_DIR" || exit
    rm -f "$OVMF_FW"
    time wget --quiet $OVMF_FW_URL || exit 1
    popd || exit
}
