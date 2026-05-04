// Copyright 2020 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs;
use std::path::Path;

#[derive(Copy, Clone)]
pub enum CacheLevel {
    /// L1 data cache
    L1D = 0,
    /// L1 instruction cache
    L1I = 1,
    /// L2 cache
    L2 = 2,
    /// L3 cache
    L3 = 3,
}

/// NOTE: cache size file directory example,
/// "/sys/devices/system/cpu/cpu0/cache/index0/size".
pub fn get_cache_size(cache_level: CacheLevel) -> u32 {
    let mut file_directory: String = "/sys/devices/system/cpu/cpu0/cache".to_string();
    match cache_level {
        CacheLevel::L1D => file_directory += "/index0/size",
        CacheLevel::L1I => file_directory += "/index1/size",
        CacheLevel::L2 => file_directory += "/index2/size",
        CacheLevel::L3 => file_directory += "/index3/size",
    }

    let file_path = Path::new(&file_directory);
    if file_path.exists() {
        let src = fs::read_to_string(file_directory).expect("File not exists or file corrupted.");
        // The content of the file is as simple as a size, like: "32K"
        let src = src.trim();
        let src_digits: u32 = src[0..src.len() - 1].parse().unwrap();
        let src_unit = &src[src.len() - 1..];

        src_digits
            * match src_unit {
                "K" => 1u32 << 10,
                "M" => 1u32 << 20,
                "G" => 1u32 << 30,
                _ => 1,
            }
    } else {
        0
    }
}

/// NOTE: coherency_line_size file directory example,
/// "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size".
pub fn get_cache_coherency_line_size(cache_level: CacheLevel) -> u32 {
    let mut file_directory: String = "/sys/devices/system/cpu/cpu0/cache".to_string();
    match cache_level {
        CacheLevel::L1D => file_directory += "/index0/coherency_line_size",
        CacheLevel::L1I => file_directory += "/index1/coherency_line_size",
        CacheLevel::L2 => file_directory += "/index2/coherency_line_size",
        CacheLevel::L3 => file_directory += "/index3/coherency_line_size",
    }

    let file_path = Path::new(&file_directory);
    if file_path.exists() {
        let src = fs::read_to_string(file_directory).expect("File not exists or file corrupted.");
        src.trim().parse::<u32>().unwrap()
    } else {
        0
    }
}

/// NOTE: number_of_sets file directory example,
/// "/sys/devices/system/cpu/cpu0/cache/index0/number_of_sets".
pub fn get_cache_number_of_sets(cache_level: CacheLevel) -> u32 {
    let mut file_directory: String = "/sys/devices/system/cpu/cpu0/cache".to_string();
    match cache_level {
        CacheLevel::L1D => file_directory += "/index0/number_of_sets",
        CacheLevel::L1I => file_directory += "/index1/number_of_sets",
        CacheLevel::L2 => file_directory += "/index2/number_of_sets",
        CacheLevel::L3 => file_directory += "/index3/number_of_sets",
    }

    let file_path = Path::new(&file_directory);
    if file_path.exists() {
        let src = fs::read_to_string(file_directory).expect("File not exists or file corrupted.");
        src.trim().parse::<u32>().unwrap()
    } else {
        0
    }
}

/// NOTE: shared_cpu_list file directory example,
/// "/sys/devices/system/cpu/cpu0/cache/index0/shared_cpu_list".
pub fn get_cache_shared(cache_level: CacheLevel) -> bool {
    let mut file_directory: String = "/sys/devices/system/cpu/cpu0/cache".to_string();
    let mut result = true;

    match cache_level {
        CacheLevel::L1D | CacheLevel::L1I => result = false,
        CacheLevel::L2 => file_directory += "/index2/shared_cpu_list",
        CacheLevel::L3 => file_directory += "/index3/shared_cpu_list",
    }

    if !result {
        return false;
    }

    let file_path = Path::new(&file_directory);
    if file_path.exists() {
        let src = fs::read_to_string(file_directory).expect("File not exists or file corrupted.");
        let src = src.trim();
        if src.is_empty() {
            result = false;
        } else {
            result = src.contains('-') || src.contains(',');
        }
    } else {
        result = false;
    }

    result
}

#[derive(Default, Copy, Clone, Debug)]
pub struct CacheTopologyInfo {
    pub l1_d_cache_size: u32,
    pub l1_d_cache_line_size: u32,
    pub l1_d_cache_sets: u32,

    pub l1_i_cache_size: u32,
    pub l1_i_cache_line_size: u32,
    pub l1_i_cache_sets: u32,

    pub l2_cache_size: u32,
    pub l2_cache_line_size: u32,
    pub l2_cache_sets: u32,

    pub l3_cache_size: u32,
    pub l3_cache_line_size: u32,
    pub l3_cache_sets: u32,

    pub l2_cache_shared: bool,
    pub l3_cache_shared: bool,
}

/// Reads cache topology information from sysfs for cpu0.
pub fn read_cache_topology() -> Option<CacheTopologyInfo> {
    let cache_path = Path::new("/sys/devices/system/cpu/cpu0/cache");
    if !cache_path.exists() {
        return None;
    }

    let mut info = CacheTopologyInfo {
        l1_d_cache_size: get_cache_size(CacheLevel::L1D),
        l1_d_cache_line_size: get_cache_coherency_line_size(CacheLevel::L1D),
        l1_d_cache_sets: get_cache_number_of_sets(CacheLevel::L1D),

        l1_i_cache_size: get_cache_size(CacheLevel::L1I),
        l1_i_cache_line_size: get_cache_coherency_line_size(CacheLevel::L1I),
        l1_i_cache_sets: get_cache_number_of_sets(CacheLevel::L1I),

        l2_cache_size: get_cache_size(CacheLevel::L2),
        l2_cache_line_size: get_cache_coherency_line_size(CacheLevel::L2),
        l2_cache_sets: get_cache_number_of_sets(CacheLevel::L2),

        l3_cache_size: get_cache_size(CacheLevel::L3),
        l3_cache_line_size: get_cache_coherency_line_size(CacheLevel::L3),
        l3_cache_sets: get_cache_number_of_sets(CacheLevel::L3),

        l2_cache_shared: false,
        l3_cache_shared: false,
    };

    if info.l2_cache_size != 0 {
        info.l2_cache_shared = get_cache_shared(CacheLevel::L2);
    }
    if info.l3_cache_size != 0 {
        info.l3_cache_shared = get_cache_shared(CacheLevel::L3);
    }

    Some(info)
}
