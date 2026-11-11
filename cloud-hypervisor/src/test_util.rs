// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test utilities.

use std::cmp::Ordering;

use clap::Arg;

/// Ensures that all [`Arg`]s are sorted alphabetically.
pub(crate) fn assert_args_sorted<'a>(args: impl Iterator<Item = &'a Arg>) {
    let args: Vec<_> = args.collect();
    for [arg, next] in args.array_windows() {
        assert_ne!(
            arg.get_id().cmp(next.get_id()),
            Ordering::Greater,
            "args not alphabetically sorted: arg={}, next={}",
            arg.get_id(),
            next.get_id()
        );
    }
}
