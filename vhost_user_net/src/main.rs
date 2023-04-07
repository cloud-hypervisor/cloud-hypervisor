// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use argh::FromArgs;
use vhost_user_net::start_net_backend;

#[derive(FromArgs)]
/// Launch a vhost-user-net backend.
struct TopLevel {
    #[argh(option, long = "net-backend")]
    /// vhost-user-net backend parameters
    /// ip=<ip_addr>,mask=<net_mask>,socket=<socket_path>,client=on|off,num_queues=<number_of_queues>,queue_size=<size_of_each_queue>,tap=<if_name>
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
        println!("Please specify --net-backend");
        std::process::exit(1)
    }

    start_net_backend(&toplevel.backend_command.unwrap());
}
