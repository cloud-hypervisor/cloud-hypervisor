// Copyright 2019 Red Hat, Inc. All Rights Reserved.
//
// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate log;
extern crate vhost_user_backend;
extern crate vhost_user_block;

use clap::{App, Arg};
use log::*;
use std::process;
use std::sync::{Arc, RwLock};
use vhost_user_backend::VhostUserDaemon;
use vhost_user_block::{VhostUserBlkBackend, VhostUserBlkBackendConfig};

fn main() {
    let cmd_arguments = App::new("vhost-user-blk backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-blk backend.")
        .arg(
            Arg::with_name("block-backend")
                .long("block-backend")
                .help(
                    "vhost-user-block backend parameters \"image=<image_path>,\
                     sock=<socket_path>,readonly=true|false,\
                     direct=true|false\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    let vhost_user_blk_backend = cmd_arguments.value_of("block-backend").unwrap();

    let backend_config = match VhostUserBlkBackendConfig::parse(vhost_user_blk_backend) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let blk_backend = Arc::new(RwLock::new(
        VhostUserBlkBackend::new(
            backend_config.image.to_string(),
            backend_config.readonly,
            backend_config.direct,
        )
        .unwrap(),
    ));

    debug!("blk_backend is created!\n");

    let name = "vhost-user-blk-backend";
    let mut blk_daemon = VhostUserDaemon::new(
        name.to_string(),
        backend_config.sock.to_string(),
        blk_backend.clone(),
    )
    .unwrap();
    debug!("blk_daemon is created!\n");

    let vring_worker = blk_daemon.get_vring_worker();

    blk_backend
        .write()
        .unwrap()
        .set_vring_worker(Some(vring_worker));

    if let Err(e) = blk_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-blk with error: {:?}\n",
            e
        );
        process::exit(1);
    }

    blk_daemon.wait().unwrap();
}
