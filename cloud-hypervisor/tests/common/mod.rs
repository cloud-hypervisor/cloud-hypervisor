// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::process::{Command, Output};

pub struct QemuImgCommand {
    command: Command,
}

impl QemuImgCommand {
    pub fn new() -> Self {
        Self {
            command: Command::new("qemu-img"),
        }
    }

    pub fn create(&mut self, format: &str, options: &str) -> &mut Self {
        self.command.args(["create", "-f", format]);
        if !options.is_empty() {
            self.command.args(["-o", options]);
        }
        self
    }

    pub fn convert(
        &mut self,
        source_format: &str,
        destination_format: &str,
        options: &str,
    ) -> &mut Self {
        self.command
            .args(["convert", "-f", source_format, "-O", destination_format]);
        if !options.is_empty() {
            self.command.args(["-o", options]);
        }
        self
    }

    pub fn check(&mut self, path: &str) -> &mut Self {
        self.args(&["check", path])
    }

    pub fn info(&mut self, path: &str) -> &mut Self {
        self.args(&["info", "-U", "--output=json", path])
    }

    pub fn map(&mut self, path: &str) -> &mut Self {
        self.args(&["map", "--output=json", "-U", path])
    }

    pub fn args(&mut self, arguments: &[&str]) -> &mut Self {
        self.command.args(arguments);
        self
    }

    pub fn run(&mut self, context: &str) -> Output {
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

impl Default for QemuImgCommand {
    fn default() -> Self {
        Self::new()
    }
}
