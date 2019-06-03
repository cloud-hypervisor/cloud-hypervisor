[![Build Status](https://travis-ci.org/rust-vmm/kvm-bindings.svg?branch=master)](https://travis-ci.org/rust-vmm/kvm-bindings)
[![Crates.io](https://img.shields.io/crates/v/kvm-bindings.svg)](https://crates.io/crates/kvm-bindings)
![](https://img.shields.io/crates/l/kvm-bindings.svg)
# kvm-bindings
Rust FFI bindings to KVM generated using
[bindgen](https://crates.io/crates/bindgen). It currently has support for the
following target architectures:
- x86
- x86_64
- arm
- arm64

# Usage
First, add the following to your `Cargo.toml`:
```toml
kvm-bindings = "0.1"
```
Next, add this to your crate root:
```rust
extern crate kvm_bindings;
```
By default `kvm-bindings` will export a wrapper over the latest available kernel
version (4.20), but you can select a different version by specifying it in your
toml:
```toml
kvm-bindings = { version = "0.1", features = ["kvm_v4_20_0"]}
```
In the `kvm-bindings` crate each feature maps to exactly one Linux version
as follows:
- `kvm_v4_14_0` contains the bindings for the Linux kernel version 4.14
- `kvm_v4_20_0` contains the bindings for the Linux kernel version 4.20
