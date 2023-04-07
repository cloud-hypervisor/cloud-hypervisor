// Copyright 2019 Red Hat, Inc. All Rights Reserved.
//
// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

extern crate vhost_user_block;

use argh::FromArgs;
use vhost_user_block::start_block_backend;

#[derive(FromArgs)]
/// Launch a vhost-user-blk backend.
struct TopLevel {
    #[argh(option, long = "block-backend")]
    /// vhost-user-block backend parameters
    /// path=<image_path>,socket=<socket_path>,num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,readonly=true|false,direct=true|false,poll_queue=true|false
    backend_command: Option<String>,

    #[argh(switch, short = 'V', long = "version")]
    /// print version information
    version: bool,
}

fn main() {
    env_logger::init();

    let toplevel: TopLevel = argh::from_env();

    if toplevel.version {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("BUILD_VERSION"));
        return;
    }

    if toplevel.backend_command.is_none() {
        println!("Please specify --block-backend");
        std::process::exit(1)
    }

    start_block_backend(&toplevel.backend_command.unwrap());
}
