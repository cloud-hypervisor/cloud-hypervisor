// Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
use std::mem;
use std::os::raw;

use vm_memory::ByteValued;

pub const MP_PROCESSOR: raw::c_uint = 0;
pub const MP_BUS: raw::c_uint = 1;
pub const MP_IOAPIC: raw::c_uint = 2;
pub const MP_INTSRC: raw::c_uint = 3;
pub const MP_LINTSRC: raw::c_uint = 4;
pub const CPU_ENABLED: raw::c_uint = 1;
pub const CPU_BOOTPROCESSOR: raw::c_uint = 2;
pub const MPC_APIC_USABLE: raw::c_uint = 1;
pub const MP_IRQDIR_DEFAULT: raw::c_uint = 0;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpf_intel {
    pub signature: [raw::c_uchar; 4usize],
    pub physptr: raw::c_uint,
    pub length: raw::c_uchar,
    pub specification: raw::c_uchar,
    pub checksum: raw::c_uchar,
    pub feature1: raw::c_uchar,
    pub feature2: raw::c_uchar,
    pub feature3: raw::c_uchar,
    pub feature4: raw::c_uchar,
    pub feature5: raw::c_uchar,
}

const _: () = assert!(mem::size_of::<mpf_intel>() == 16);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpf_intel {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_table {
    pub signature: [raw::c_uchar; 4usize],
    pub length: raw::c_ushort,
    pub spec: raw::c_uchar,
    pub checksum: raw::c_uchar,
    pub oem: [raw::c_uchar; 8usize],
    pub productid: [raw::c_uchar; 12usize],
    pub oemptr: raw::c_uint,
    pub oemsize: raw::c_ushort,
    pub oemcount: raw::c_ushort,
    pub lapic: raw::c_uint,
    pub reserved: raw::c_uint,
}

const _: () = {
    assert!(mem::size_of::<mpc_table>() == 4 + 2 + 1 + 1 + 8 + 12 + 4 + 2 + 2 + 4 + 4);
    assert!(mem::size_of::<raw::c_uint>() == 4);
    assert!(mem::size_of::<raw::c_ushort>() == 2);
    assert!(mem::size_of::<raw::c_uchar>() == 1);
};

// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_table {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_cpu {
    pub type_: raw::c_uchar,
    pub apicid: raw::c_uchar,
    pub apicver: raw::c_uchar,
    pub cpuflag: raw::c_uchar,
    pub cpufeature: raw::c_uint,
    pub featureflag: raw::c_uint,
    pub reserved: [raw::c_uint; 2usize],
}

const _: () = assert!(mem::size_of::<mpc_cpu>() == 20);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_cpu {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_bus {
    pub type_: raw::c_uchar,
    pub busid: raw::c_uchar,
    pub bustype: [raw::c_uchar; 6usize],
}

const _: () = assert!(mem::size_of::<mpc_bus>() == 8);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_bus {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_ioapic {
    pub type_: raw::c_uchar,
    pub apicid: raw::c_uchar,
    pub apicver: raw::c_uchar,
    pub flags: raw::c_uchar,
    pub apicaddr: raw::c_uint,
}

const _: () = assert!(mem::size_of::<mpc_ioapic>() == 8);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_ioapic {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_intsrc {
    pub type_: raw::c_uchar,
    pub irqtype: raw::c_uchar,
    pub irqflag: raw::c_ushort,
    pub srcbus: raw::c_uchar,
    pub srcbusirq: raw::c_uchar,
    pub dstapic: raw::c_uchar,
    pub dstirq: raw::c_uchar,
}

const _: () = assert!(mem::size_of::<mpc_intsrc>() == 8);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_intsrc {}

pub const MP_IRQ_SOURCE_TYPES_MP_INT: raw::c_uint = 0;
pub const MP_IRQ_SOURCE_TYPES_MP_NMI: raw::c_uint = 1;
pub const MP_IRQ_SOURCE_TYPES_MP_EXT_INT: raw::c_uint = 3;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_lintsrc {
    pub type_: raw::c_uchar,
    pub irqtype: raw::c_uchar,
    pub irqflag: raw::c_ushort,
    pub srcbusid: raw::c_uchar,
    pub srcbusirq: raw::c_uchar,
    pub destapic: raw::c_uchar,
    pub destapiclint: raw::c_uchar,
}

const _: () = assert!(mem::size_of::<mpc_lintsrc>() == 8);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_lintsrc {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mpc_oemtable {
    pub signature: [raw::c_uchar; 4usize],
    pub length: raw::c_ushort,
    pub rev: raw::c_uchar,
    pub checksum: raw::c_uchar,
    pub mpc: [raw::c_uchar; 8usize],
}

const _: () = assert!(mem::size_of::<mpc_oemtable>() == 16);
// SAFETY: all members of this struct are plain integers
// and the sum of their sizes is the size of the struct, so
// padding and reserved values are not possible as there
// would be nowhere for them to exist.
unsafe impl ByteValued for mpc_oemtable {}
