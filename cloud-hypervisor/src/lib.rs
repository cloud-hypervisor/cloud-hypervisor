// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use log::error;

/// Prints a chain of errors to the user in a consistent manner.
/// The user will see a clear chain of errors, followed by debug output
/// for opening issues.
pub fn cli_print_error_chain<'a>(
    top_error: &'a (dyn Error + 'static),
    component: &str,
    // Function optionally returning the display representation of an error.
    display_modifier: impl Fn(
        /* level */ usize,
        /*indention */ usize,
        &'a (dyn Error + 'static),
    ) -> Option<String>,
) {
    // Debug info.
    error!("Fatal error: {top_error:?}");

    eprint!("Error: {component} exited with the following ");
    if top_error.source().is_none() {
        eprintln!("error:");
        eprintln!("  {top_error}");
    } else {
        eprintln!("chain of errors:");
        std::iter::successors(Some(top_error), |sub_error| {
            // Dereference necessary to mitigate rustc compiler bug.
            // See <https://github.com/rust-lang/rust/issues/141673>
            (*sub_error).source()
        })
        .enumerate()
        .for_each(|(level, error)| {
            // Special case: handling of HTTP Server responses in ch-remote
            if let Some(message) = display_modifier(level, 2, error) {
                eprintln!("{message}");
            } else {
                eprintln!("  {level}: {error}");
            }
        });
    }
}
