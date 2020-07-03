#!/bin/bash
set -e
set -x

source $HOME/.cargo/env

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
time cargo clippy --all-targets --no-default-features --features "pci,acpi" -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "pci,acpi"  -- -D warnings
time cargo rustc -p vhost_user_net --bin vhost_user_net --no-default-features --features "pci,acpi"  -- -D warnings
time cargo clippy --all-targets --no-default-features --features "pci" -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "pci"  -- -D warnings
time cargo rustc -p vhost_user_net --bin vhost_user_net --no-default-features --features "pci"  -- -D warnings
time cargo clippy --all-targets --no-default-features --features "mmio" -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "mmio"  -- -D warnings
time cargo rustc -p vhost_user_net --bin vhost_user_net --no-default-features --features "mmio"  -- -D warnings
time cargo fmt -- --check
time cargo build --all --release
