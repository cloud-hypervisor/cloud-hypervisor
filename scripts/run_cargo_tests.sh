#!/bin/bash
set -e
set -x

source $HOME/.cargo/env
source $(dirname "$0")/test-util.sh

process_common_args "$@"

# Install cargo components
time rustup component add clippy
time rustup component add rustfmt
time which cargo-audit || cargo install cargo-audit

# Run cargo builds and checks
time cargo clippy --all-targets --all-features -- -D warnings
time cargo rustc --bin cloud-hypervisor -- -D warnings
time cargo rustc -p vhost_user_net --bin vhost_user_net -- -D warnings
time cargo test
time cargo audit
time cargo clippy --all-targets --no-default-features --features "acpi,kvm" -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "acpi,kvm"  -- -D warnings
time cargo clippy --all-targets --no-default-features --features "kvm" -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "kvm"  -- -D warnings
time cargo fmt -- --check
time cargo build --all --release
