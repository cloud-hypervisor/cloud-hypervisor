// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

/// Prints a chain of errors to the user in a consistent manner.
/// The user will see a clear chain of errors, followed by debug output
/// for opening issues.
pub fn cli_print_error_chain(top_error: &dyn std::error::Error, component: &str) {
    eprint!("Error: {component} exited with the following ");
    if top_error.source().is_none() {
        eprintln!("error:");
        eprintln!("  {top_error}");
    } else {
        eprintln!("chain of errors:");
        std::iter::successors(Some(top_error), |sub_error| {
            sub_error.source()
        })
        .enumerate()
        .for_each(|(level, error)| {
            eprintln!("  {level}: {error}",);
        });
    }

    eprintln!();
    eprintln!("Debug Info: {top_error:?}");
}
