// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::process::{Command, Output};

pub(crate) struct QemuImg {
    command: Command,
}

impl QemuImg {
    pub(crate) fn new() -> Self {
        Self {
            command: Command::new("qemu-img"),
        }
    }

    pub(crate) fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.command.arg(argument);
        self
    }

    pub(crate) fn args(
        &mut self,
        arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> &mut Self {
        self.command.args(arguments);
        self
    }

    pub(crate) fn run(&mut self, context: &str) -> Output {
        let output = self
            .command
            .output()
            .map_err(|error| format!("{:?}\n{error}", self.command))
            .expect(context);
        assert!(
            output.status.success(),
            "{context}\nCommand: {:?}\nStatus: {}\nStderr: {}",
            self.command,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}
