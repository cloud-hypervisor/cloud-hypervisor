#!/usr/bin/env bash

set -euo pipefail

MINIMUM_RUST_VERSION=${MINIMUM_RUST_VERSION:-1.89.0}
QPL_VERSION=${QPL_VERSION:-1.9.0}
QPL_INCLUDE_DIR=${QPL_INCLUDE_DIR:-/usr/local/include}
QPL_LIB_DIR=${QPL_LIB_DIR:-/usr/local/lib64}
WITH_QPL=${WITH_QPL:-1}

required_commands=(curl gcc g++ make cmake ninja pkg-config ssh sshpass ip qemu-img python3 mkdosfs mcopy)

find_cargo() {
    if [[ -n ${CARGO_BIN:-} && -x ${CARGO_BIN:-} ]]; then
        printf '%s\n' "$CARGO_BIN"
    elif command -v cargo >/dev/null 2>&1; then
        command -v cargo
    elif [[ -x ${HOME:-}/.cargo/bin/cargo ]]; then
        printf '%s\n' "$HOME/.cargo/bin/cargo"
    else
        return 1
    fi
}

version_at_least() {
    [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1) == "$2" ]]
}

host_commands_missing() {
    local command_name
    for command_name in "${required_commands[@]}"; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

check_dependencies() {
    local missing=0 command_name cargo_bin rust_version
    for command_name in "${required_commands[@]}"; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "Missing command: $command_name" >&2
            missing=1
        fi
    done

    if cargo_bin=$(find_cargo); then
        rust_version=$("$cargo_bin" --version | awk '{print $2}')
        if ! version_at_least "$rust_version" "$MINIMUM_RUST_VERSION"; then
            echo "Rust $MINIMUM_RUST_VERSION or newer is required; found $rust_version" >&2
            missing=1
        fi
    else
        echo "Missing command: cargo" >&2
        missing=1
    fi

    if [[ "$WITH_QPL" == 1 ]]; then
        if [[ ! -f "$QPL_INCLUDE_DIR/qpl/qpl.h" ]]; then
            echo "Missing QPL header: $QPL_INCLUDE_DIR/qpl/qpl.h" >&2
            missing=1
        fi
        if [[ ! -f "$QPL_LIB_DIR/libqpl.a" ]]; then
            echo "Missing static QPL library: $QPL_LIB_DIR/libqpl.a" >&2
            missing=1
        fi
    fi
    return "$missing"
}

run_privileged() {
    if ((EUID == 0)); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "Root privileges or sudo are required to install dependencies." >&2
        exit 1
    fi
}

install_packages() {
    if command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y \
            git gcc gcc-c++ make cmake ninja-build pkgconf-pkg-config \
            m4 bison flex libuuid-devel qemu-img openssh-clients sshpass \
            iproute curl python3 tar gzip dosfstools mtools
    elif command -v yum >/dev/null 2>&1; then
        run_privileged yum install -y \
            git gcc gcc-c++ make cmake ninja-build pkgconfig \
            m4 bison flex libuuid-devel qemu-img openssh-clients sshpass \
            iproute curl python3 tar gzip dosfstools mtools
    elif command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get update
        run_privileged apt-get install -y \
            git build-essential cmake ninja-build pkg-config m4 bison flex \
            uuid-dev qemu-utils openssh-client sshpass iproute2 curl python3 \
            tar gzip dosfstools mtools
    else
        echo "Unsupported package manager. Install the commands listed by --check." >&2
        exit 1
    fi
}

install_rust() {
    local cargo_bin rust_version
    if cargo_bin=$(find_cargo); then
        rust_version=$("$cargo_bin" --version | awk '{print $2}')
        if version_at_least "$rust_version" "$MINIMUM_RUST_VERSION"; then
            return
        fi
    fi

    echo "Installing Rust $MINIMUM_RUST_VERSION with rustup"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        https://sh.rustup.rs | sh -s -- -y --default-toolchain "$MINIMUM_RUST_VERSION"
    export PATH="$HOME/.cargo/bin:$PATH"
}

install_qpl() (
    if [[ -f "$QPL_INCLUDE_DIR/qpl/qpl.h" && -f "$QPL_LIB_DIR/libqpl.a" ]]; then
        return
    fi

    local source_archive source_dir build_dir
    source_archive=$(mktemp --suffix=.tar.gz)
    source_dir=$(mktemp -d)
    build_dir=$(mktemp -d)
    trap 'rm -f "$source_archive"; rm -rf "$source_dir" "$build_dir"' EXIT

    echo "Installing Intel QPL v$QPL_VERSION"
    curl --fail --location --retry 3 \
        --output "$source_archive" \
        "https://github.com/intel/qpl/archive/refs/tags/v$QPL_VERSION.tar.gz"
    tar -xzf "$source_archive" --strip-components=1 -C "$source_dir"
    cmake -S "$source_dir" -B "$build_dir" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DQPL_BUILD_TESTS=OFF \
        -DQPL_BUILD_EXAMPLES=OFF \
        -DQPL_LIBRARY_TYPE=STATIC
    cmake --build "$build_dir" --parallel
    run_privileged cmake --install "$build_dir"
)

case ${1:-} in
    --check)
        check_dependencies
        exit $?
        ;;
    "") ;;
    *)
        echo "Usage: $0 [--check]" >&2
        exit 2
        ;;
esac

echo "Installing benchmark host dependencies"
if host_commands_missing; then
    install_packages
fi
install_rust
if [[ "$WITH_QPL" == 1 ]]; then
    install_qpl
fi

if ! check_dependencies; then
    echo "Dependency setup did not complete successfully." >&2
    exit 1
fi
echo "Benchmark dependencies are ready."
