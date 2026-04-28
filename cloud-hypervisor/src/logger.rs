// Copyright © 2026 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Mutex;

pub struct Logger {
    pub output: Mutex<Box<dyn std::io::Write + Send>>,
    pub start: std::time::Instant,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = std::time::Instant::now();
        let duration = now.duration_since(self.start);
        let duration_s = duration.as_secs_f32();

        let location = if let (Some(file), Some(line)) = (record.file(), record.line()) {
            format!("{file}:{line}")
        } else {
            record.target().to_string()
        };

        let mut out = self.output.lock().unwrap();
        write!(
            &mut *out,
            // 10: 6 decimal places + sep => whole seconds in range `0..=999` properly aligned
            "cloud-hypervisor: {:>10.6?}s: <{}> {}:{} -- {}\r\n",
            duration_s,
            std::thread::current().name().unwrap_or("anonymous"),
            record.level(),
            location,
            record.args(),
        )
        .ok();
    }
    fn flush(&self) {}
}
