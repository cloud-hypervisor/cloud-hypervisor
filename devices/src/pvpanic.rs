// Copyright © 2023 Tencent Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

const PVPANIC_PANICKED: u8 = 1 << 0;
const PVPANIC_CRASH_LOADED: u8 = 1 << 1;

/// A device for handling guest panic event
pub struct PvPanicDevice {
    _id: String,
    _events: u8,
}

impl PvPanicDevice {
    pub fn new() -> PvPanicDevice {
        let events = PVPANIC_PANICKED | PVPANIC_CRASH_LOADED;

        PvPanicDevice {
            _id: String::from("_pvpanic"),
            _events: events,
        }
    }
}
