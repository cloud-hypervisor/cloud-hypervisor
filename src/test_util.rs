// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
pub mod tests {
    use std::cmp::Ordering;

    use clap::Arg;

    pub fn assert_args_sorted<'a, F: Fn() -> R, R: Iterator<Item = &'a Arg>>(get_base_iter: F) {
        let iter = get_base_iter().zip(get_base_iter().skip(1));
        for (arg, next) in iter {
            assert_ne!(
                arg.get_id().cmp(next.get_id()),
                Ordering::Greater,
                "args not alphabetically sorted: arg={}, next={}",
                arg.get_id(),
                next.get_id()
            );
        }
    }
}
