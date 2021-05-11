// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg};
use vhost_user_net::start_net_backend;

fn main() {
    let cmd_arguments = App::new("vhost-user-net backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-net backend.")
        .arg(
            Arg::with_name("net-backend")
                .long("net-backend")
                .help(vhost_user_net::SYNTAX)
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    let backend_command = cmd_arguments.value_of("net-backend").unwrap();
    start_net_backend(backend_command);
}
