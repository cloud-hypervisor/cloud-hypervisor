// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::error::Error;

/// Prints a chain of errors to the user in a consistent manner.
pub fn cli_print_error_chain(top_error: &dyn Error, component: &str) {
    eprint!("Error: {component} exited with the following ");
    if top_error.source().is_none() {
        eprintln!("error:");
        eprintln!("  {top_error}");
    } else {
        eprintln!("chain of errors:");
        eprintln!("  0: {top_error}");
        let mut level = 1;
        let mut next_error: &dyn Error = &top_error;
        // Due to lifetime errors' we unfortunately can't simplify this using
        // `std::iter::successors`.
        while let Some(sub_error) = next_error.source() {
            next_error = sub_error;
            eprintln!("  {level}: {next_error}",);
            level += 1;
        }
    }

    eprintln!();
    eprintln!("Debug Info: {top_error:?}");
}