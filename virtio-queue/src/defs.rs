// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Virtio queue related constant definitions

/// Marks a buffer as continuing via the next field.
pub const VIRTQ_DESC_F_NEXT: u16 = 0x1;

/// Marks a buffer as device write-only.
pub const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// Shows that the buffer contains a list of buffer descriptors.
pub const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

/// Used flags
pub const VIRTQ_USED_F_NO_NOTIFY: u16 = 0x1;

/// This is the size of one element in the used ring, id (le32) + len (le32).
pub(crate) const VIRTQ_USED_ELEMENT_SIZE: u64 = 8;

/// Used ring header: flags (u16) + idx (u16)
pub(crate) const VIRTQ_USED_RING_HEADER_SIZE: u64 = 4;

/// This is the size of the used ring metadata: header + avail_event (le16).
/// The total size of the used ring is:
/// VIRTQ_USED_RING_HMETA_SIZE + VIRTQ_USED_ELEMENT_SIZE * queue_size
pub(crate) const VIRTQ_USED_RING_META_SIZE: u64 = VIRTQ_USED_RING_HEADER_SIZE + 2;

/// This is the size of one element in the available ring (le16).
pub(crate) const VIRTQ_AVAIL_ELEMENT_SIZE: u64 = 2;

/// Avail ring header: flags(u16) + idx(u16)
pub(crate) const VIRTQ_AVAIL_RING_HEADER_SIZE: u64 = 4;

/// This is the size of the available ring metadata: header + used_event (le16).
/// The total size of the available ring is:
/// VIRTQ_AVAIL_RING_META_SIZE + VIRTQ_AVAIL_ELEMENT_SIZE * queue_size
pub(crate) const VIRTQ_AVAIL_RING_META_SIZE: u64 = VIRTQ_AVAIL_RING_HEADER_SIZE + 2;

/// The Virtio Spec 1.0 defines the alignment of VirtIO descriptor is 16 bytes,
/// which fulfills the explicit constraint of GuestMemory::read_obj().
pub(crate) const VIRTQ_DESCRIPTOR_SIZE: usize = 16;

/// Vector value used to disable MSI for a queue.
pub const VIRTQ_MSI_NO_VECTOR: u16 = 0xffff;
