// Copyright 2019 Intel Corporation. All Rights Reserved.
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
extern crate vhost_user_net;

use clap::{App, Arg};
use epoll;
use std::process;
use std::sync::{Arc, RwLock};
use vhost_user_backend::VhostUserDaemon;
use vhost_user_net::{VhostUserNetBackend, VhostUserNetBackendConfig};

fn main() {
    let cmd_arguments = App::new("vhost-user-net backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-net backend.")
        .arg(
            Arg::with_name("net-backend")
                .long("net-backend")
                .help(
                    "vhost-user-net backend parameters \"ip=<ip_addr>,\
                     mask=<net_mask>,sock=<socket_path>,\
                     num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .get_matches();

    let vhost_user_net_backend = cmd_arguments.value_of("net-backend").unwrap();

    let backend_config = match VhostUserNetBackendConfig::parse(vhost_user_net_backend) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let net_backend = Arc::new(RwLock::new(
        VhostUserNetBackend::new(
            backend_config.ip,
            backend_config.mask,
            backend_config.num_queues,
            backend_config.queue_size,
        )
        .unwrap(),
    ));

    let mut net_daemon = VhostUserDaemon::new(
        "vhost-user-net-backend".to_string(),
        backend_config.sock.to_string(),
        net_backend.clone(),
    )
    .unwrap();

    let (kill_index, kill_evt_fd) = net_backend.read().unwrap().get_kill_event();
    let vring_worker = net_daemon.get_vring_worker();

    if let Err(e) =
        vring_worker.register_listener(kill_evt_fd, epoll::Events::EPOLLIN, u64::from(kill_index))
    {
        println!("failed to register listener for kill event: {:?}", e);
        process::exit(1);
    }

    net_backend
        .write()
        .unwrap()
        .set_vring_worker(Some(vring_worker));

    if let Err(e) = net_daemon.start() {
        println!(
            "failed to start daemon for vhost-user-net with error: {:?}",
            e
        );
        process::exit(1);
    }

    net_daemon.wait().unwrap();
}
