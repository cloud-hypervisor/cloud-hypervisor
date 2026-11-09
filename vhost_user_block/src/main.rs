// Copyright 2019 Red Hat, Inc. All Rights Reserved.
//
// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use clap::Parser;
use vhost_user_block::start_block_backend;

#[derive(Parser)]
#[command(
    version,
    about = "Launch a vhost-user-blk backend",
    arg_required_else_help = true
)]
struct Cli {
    #[arg(long, help = vhost_user_block::SYNTAX)]
    block_backend: String,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    start_block_backend(&cli.block_backend);
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn clap_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_backend_argument() {
        let cli = Cli::try_parse_from(["backend", "--block-backend", "socket=/tmp/backend"])
            .expect("the backend option should parse");
        assert_eq!(cli.block_backend, "socket=/tmp/backend");
        assert!(Cli::try_parse_from(["backend"]).is_err());
    }
}
