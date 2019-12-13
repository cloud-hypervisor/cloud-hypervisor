#!/bin/bash
set -e
set -x

source $HOME/.cargo/env

# Install cargo components
time rustup component add clippy
time rustup component add rustfmt
time cargo install --force cargo-audit

# Run cargo builds and checks
time cargo rustc --bin cloud-hypervisor -- -D warnings
time cargo rustc --bin vhost_user_net -- -D warnings
time cargo test
time cargo audit
time cargo rustc --bin cloud-hypervisor --no-default-features --features "pci,acpi"  -- -D warnings
time cargo rustc --bin vhost_user_net --no-default-features --features "pci,acpi"  -- -D warnings
time cargo clippy --all-targets --all-features -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "pci"  -- -D warnings
time cargo rustc --bin vhost_user_net --no-default-features --features "pci"  -- -D warnings
time cargo rustc --bin cloud-hypervisor --no-default-features --features "mmio"  -- -D warnings
time cargo rustc --bin vhost_user_net --no-default-features --features "mmio"  -- -D warnings
time sh -c 'find . \( -name "*.rs" ! -wholename "*/out/*.rs" \) | xargs rustfmt --check'
time cargo build --release
