#!/bin/bash
set -e
set -x

source $HOME/.cargo/env

# Install cargo components
rustup component add clippy
rustup component add rustfmt
cargo install --force cargo-audit

# Run cargo builds and checks
cargo rustc --bin cloud-hypervisor -- -D warnings
cargo rustc --bin vhost_user_net -- -D warnings
cargo test
cargo audit
cargo rustc --bin cloud-hypervisor --no-default-features --features "pci,acpi"  -- -D warnings
cargo rustc --bin vhost_user_net --no-default-features --features "pci,acpi"  -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo rustc --bin cloud-hypervisor --no-default-features --features "pci"  -- -D warnings
cargo rustc --bin vhost_user_net --no-default-features --features "pci"  -- -D warnings
cargo rustc --bin cloud-hypervisor --no-default-features --features "mmio"  -- -D warnings
cargo rustc --bin vhost_user_net --no-default-features --features "mmio"  -- -D warnings
find . \( -name "*.rs" ! -wholename "*/out/*.rs" \) | xargs rustfmt --check
cargo build --release
