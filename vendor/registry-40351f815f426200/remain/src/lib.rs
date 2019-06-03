//! This crate provides an attribute macro to check at compile time that the
//! variants of an enum or the arms of a match expression are written in sorted
//! order.
//!
//! # Syntax
//!
//! Place a `#[remain::sorted]` attribute on enums, structs, match-expressions,
//! or let-statements whose value is a match-expression.
//!
//! Alternatively, import as `use remain::sorted;` and use `#[sorted]` as the
//! attribute.
//!
//! ```
//! # use std::error::Error as StdError;
//! # use std::fmt::{self, Display};
//! # use std::io;
//! #
//! #[remain::sorted]
//! #[derive(Debug)]
//! pub enum Error {
//!     BlockSignal(signal::Error),
//!     CreateCrasClient(libcras::Error),
//!     CreateEventFd(sys_util::Error),
//!     CreateSignalFd(sys_util::SignalFdError),
//!     CreateSocket(io::Error),
//!     DetectImageType(qcow::Error),
//!     DeviceJail(io_jail::Error),
//!     NetDeviceNew(virtio::NetError),
//!     SpawnVcpu(io::Error),
//! }
//!
//! impl Display for Error {
//!     # #[remain::check]
//!     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//!         use self::Error::*;
//!
//!         #[remain::sorted]
//!         match self {
//!             BlockSignal(e) => write!(f, "failed to block signal: {}", e),
//!             CreateCrasClient(e) => write!(f, "failed to create cras client: {}", e),
//!             CreateEventFd(e) => write!(f, "failed to create eventfd: {}", e),
//!             CreateSignalFd(e) => write!(f, "failed to create signalfd: {}", e),
//!             CreateSocket(e) => write!(f, "failed to create socket: {}", e),
//!             DetectImageType(e) => write!(f, "failed to detect disk image type: {}", e),
//!             DeviceJail(e) => write!(f, "failed to jail device: {}", e),
//!             NetDeviceNew(e) => write!(f, "failed to set up virtio networking: {}", e),
//!             SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
//!         }
//!     }
//! }
//! #
//! # mod signal {
//! #     pub use std::io::Error;
//! # }
//! #
//! # mod libcras {
//! #     pub use std::io::Error;
//! # }
//! #
//! # mod sys_util {
//! #     pub use std::io::{Error, Error as SignalFdError};
//! # }
//! #
//! # mod qcow {
//! #     pub use std::io::Error;
//! # }
//! #
//! # mod io_jail {
//! #     pub use std::io::Error;
//! # }
//! #
//! # mod virtio {
//! #     pub use std::io::Error as NetError;
//! # }
//! #
//! # fn main() {}
//! ```
//!
//! If an enum variant, struct field, or match arm is inserted out of order,\
//!
//! ```diff
//!       NetDeviceNew(virtio::NetError),
//!       SpawnVcpu(io::Error),
//! +     AaaUhOh(Box<dyn StdError>),
//!   }
//! ```
//!
//! then the macro produces a compile error.
//!
//! ```console
//! error: AaaUhOh should sort before BlockSignal
//!   --> tests/stable.rs:49:5
//!    |
//! 49 |     AaaUhOh(Box<dyn StdError>),
//!    |     ^^^^^^^
//! ```
//!
//! # Compiler support
//!
//! The attribute on enums is supported on any rustc version 1.31+.
//!
//! Rust does not yet have stable support for user-defined attributes within a
//! function body, so the attribute on match-expressions and let-statements
//! requires a nightly compiler and the following two features enabled:
//!
//! ```
//! # const IGNORE: &str = stringify! {
//! #![feature(proc_macro_hygiene, stmt_expr_attributes)]
//! # };
//! ```
//!
//! As a stable alternative, this crate provides a function-level attribute
//! called `#[remain::check]` which makes match-expression and let-statement
//! attributes work on any rustc version 1.31+. Place this attribute on any
//! function containing `#[sorted]` to make them work on a stable compiler.
//!
//! ```
//! # use std::fmt::{self, Display};
//! #
//! # enum Error {}
//! #
//! impl Display for Error {
//!     #[remain::check]
//!     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//!         use self::Error::*;
//!
//!         #[sorted]
//!         match self {
//!             /* ... */
//!             # _ => unimplemented!(),
//!         }
//!     }
//! }
//! #
//! # fn main() {}
//! ```

extern crate proc_macro;

mod check;
mod compare;
mod emit;
mod format;
mod parse;
mod visit;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

use crate::emit::emit;
use crate::parse::{Input, Nothing};

#[proc_macro_attribute]
pub fn sorted(args: TokenStream, input: TokenStream) -> TokenStream {
    let original = input.clone();

    let _ = parse_macro_input!(args as Nothing);
    let input = parse_macro_input!(input as Input);
    let kind = input.kind();

    match check::sorted(input) {
        Ok(()) => original,
        Err(err) => emit(err, kind, original),
    }
}

#[proc_macro_attribute]
pub fn check(args: TokenStream, input: TokenStream) -> TokenStream {
    let _ = parse_macro_input!(args as Nothing);
    let mut input = parse_macro_input!(input as ItemFn);

    visit::check(&mut input);

    TokenStream::from(quote!(#input))
}
