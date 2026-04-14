// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

// See include/uapi/linux/userfaultfd.h in the kernel code.
pub const UFFDIO_API: u64 = 0xc018_aa3f; // _IOWR(0xAA, 0x3F, struct uffdio_api)
pub const UFFDIO_REGISTER: u64 = 0xc020_aa00; // _IOWR(0xAA, 0x00, struct uffdio_register)
pub const UFFDIO_COPY: u64 = 0xc028_aa03; // _IOWR(0xAA, 0x03, struct uffdio_copy)
pub const UFFDIO_WAKE: u64 = 0x8010_aa02; // _IOR(0xAA, 0x02, struct uffdio_range)

// Seccomp compares these as Dword (u32); ensure they fit.
const _: () = assert!(UFFDIO_API <= u32::MAX as u64);
const _: () = assert!(UFFDIO_REGISTER <= u32::MAX as u64);
const _: () = assert!(UFFDIO_COPY <= u32::MAX as u64);
const _: () = assert!(UFFDIO_WAKE <= u32::MAX as u64);

pub const UFFD_API: u64 = 0xAA;
pub const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
pub const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
pub const UFFD_FEATURE_MISSING_HUGETLBFS: u64 = 1 << 4;
pub const UFFD_FEATURE_MISSING_SHMEM: u64 = 1 << 5;

const _UFFDIO_COPY: u64 = 0x03;
const _UFFDIO_WAKE: u64 = 0x02;
pub const UFFD_API_RANGE_IOCTLS_BASIC: u64 = (1 << _UFFDIO_WAKE) | (1 << _UFFDIO_COPY);
