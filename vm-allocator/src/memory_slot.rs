// Copyright © 2024 Rivos Inc
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// Allocator for KVM memory slots
pub struct MemorySlotAllocator {
    next_memory_slot: Arc<AtomicU32>,
    memory_slot_free_list: Arc<Mutex<Vec<u32>>>,
}

impl MemorySlotAllocator {
    /// Next free memory slot
    pub fn next_memory_slot(&self) -> u32 {
        if let Some(slot_id) = self.memory_slot_free_list.lock().unwrap().pop() {
            return slot_id;
        }
        self.next_memory_slot.fetch_add(1, Ordering::SeqCst)
    }

    /// Release memory slot for reuse
    pub fn free_memory_slot(&mut self, slot: u32) {
        self.memory_slot_free_list.lock().unwrap().push(slot)
    }

    /// Instantiate struct
    pub fn new(
        next_memory_slot: Arc<AtomicU32>,
        memory_slot_free_list: Arc<Mutex<Vec<u32>>>,
    ) -> Self {
        Self {
            next_memory_slot,
            memory_slot_free_list,
        }
    }
}
