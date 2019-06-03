Remain sorted
=============

[![Build Status](https://api.travis-ci.com/dtolnay/remain.svg?branch=master)](https://travis-ci.com/dtolnay/remain)
[![Latest Version](https://img.shields.io/crates/v/remain.svg)](https://crates.io/crates/remain)
[![Rust Documentation](https://img.shields.io/badge/api-rustdoc-blue.svg)](https://docs.rs/remain)

This crate provides an attribute macro to check at compile time that the
variants of an enum or the arms of a match expression are written in sorted
order.

```toml
[dependencies]
remain = "0.1"
```

## Syntax

Place a `#[remain::sorted]` attribute on enums, structs, match-expressions, or
let-statements whose value is a match-expression.

Alternatively, import as `use remain::sorted;` and use `#[sorted]` as the
attribute.

```rust
#[remain::sorted]
#[derive(Debug)]
pub enum Error {
    BlockSignal(signal::Error),
    CreateCrasClient(libcras::Error),
    CreateEventFd(sys_util::Error),
    CreateSignalFd(sys_util::SignalFdError),
    CreateSocket(io::Error),
    DetectImageType(qcow::Error),
    DeviceJail(io_jail::Error),
    NetDeviceNew(virtio::NetError),
    SpawnVcpu(io::Error),
}

#[remain::sorted]
#[derive(Debug)]
pub enum Registers {
    ax: u16,
    cx: u16,
    di: u16,
    si: u16,
    sp: u16,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[remain::sorted]
        match self {
            BlockSignal(e) => write!(f, "failed to block signal: {}", e),
            CreateCrasClient(e) => write!(f, "failed to create cras client: {}", e),
            CreateEventFd(e) => write!(f, "failed to create eventfd: {}", e),
            CreateSignalFd(e) => write!(f, "failed to create signalfd: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            DetectImageType(e) => write!(f, "failed to detect disk image type: {}", e),
            DeviceJail(e) => write!(f, "failed to jail device: {}", e),
            NetDeviceNew(e) => write!(f, "failed to set up virtio networking: {}", e),
            SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
        }
    }
}
```

If an enum variant, struct field, or match arm is inserted out of order,

```diff
      NetDeviceNew(virtio::NetError),
      SpawnVcpu(io::Error),
+     AaaUhOh(Box<dyn StdError>),
  }
```

then the macro produces a compile error.

```console
error: AaaUhOh should sort before BlockSignal
  --> tests/stable.rs:49:5
   |
49 |     AaaUhOh(Box<dyn StdError>),
   |     ^^^^^^^
```

## Compiler support

The attribute on enums and structs is supported on any rustc version 1.31+.

Rust does not yet have stable support for user-defined attributes within a
function body, so the attribute on match-expressions and let-statements requires
a nightly compiler and the following two features enabled:

```rust
#![feature(proc_macro_hygiene, stmt_expr_attributes)]
```

As a stable alternative, this crate provides a function-level attribute called
`#[remain::check]` which makes match-expression and let-statement attributes
work on any rustc version 1.31+. Place this attribute on any function containing
`#[sorted]` to make them work on a stable compiler.

```rust
impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            /* ... */
        }
    }
}
```

<br>

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
