// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use std::{io, result};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info, warn};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{Queue, QueueT};
use vm_memory::{Bytes, GuestAddressSpace, GuestMemory, GuestMemoryAtomic};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::{AccessPlatform, Translatable};
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1,
    VirtioCommon, VirtioDevice, VirtioDeviceType,
};
use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{GuestMemoryMmap, VirtioInterrupt, VirtioInterruptType};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

#[derive(Error, Debug)]
enum Error {
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
}

struct RngEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    queue: Queue,
    random_file: File,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
    access_platform: Option<Arc<dyn AccessPlatform>>,
}

impl RngEpollHandler {
    fn process_queue(&mut self) -> result::Result<bool, Error> {
        let queue = &mut self.queue;

        let mut used_descs = false;
        while let Some(mut desc_chain) = queue.pop_descriptor_chain(self.mem.memory()) {
            let mut total_len: usize = 0;
            while let Some(desc) = desc_chain.next() {
                if !desc.is_write_only() {
                    warn!("Skipping device-readable descriptor");
                    continue;
                }
                if desc.len() == 0 {
                    continue;
                }
                let addr = match desc
                    .addr()
                    .translate_gva(self.access_platform.as_deref(), desc.len() as usize)
                {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Failed to translate descriptor address: {e}");
                        break;
                    }
                };
                if !desc_chain.memory().check_range(addr, desc.len() as usize) {
                    warn!(
                        "Descriptor range out of guest memory: addr=0x{:x} len={}",
                        addr.0,
                        desc.len()
                    );
                    break;
                }
                match desc_chain.memory().read_volatile_from(
                    addr,
                    &mut self.random_file,
                    desc.len() as usize,
                ) {
                    Ok(written) => total_len += written,
                    Err(e) => {
                        warn!("Failed to read entropy into descriptor: {e}");
                        break;
                    }
                }
            }

            queue
                .add_used(
                    desc_chain.memory(),
                    desc_chain.head_index(),
                    total_len as u32,
                )
                .map_err(Error::QueueAddUsed)?;
            used_descs = true;
        }

        Ok(used_descs)
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(0))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for RngEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;
                let needs_notification = self.process_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to process queue : {e:?}"))
                })?;
                if needs_notification {
                    self.signal_used_queue().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
                    })?;
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Rng {
    common: VirtioCommon,
    id: String,
    random_file: Option<File>,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

#[derive(Deserialize, Serialize)]
pub struct RngState {
    pub avail_features: u64,
    pub acked_features: u64,
}

impl Rng {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(
        id: String,
        path: &str,
        access_platform_enabled: bool,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<RngState>,
    ) -> io::Result<Rng> {
        let random_file = File::open(path)?;

        let (avail_features, acked_features, paused) = if let Some(state) = state {
            info!("Restoring virtio-rng {id}");
            (state.avail_features, state.acked_features, true)
        } else {
            let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

            if access_platform_enabled {
                avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
            }

            (avail_features, 0, false)
        };

        Ok(Rng {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Rng as u32,
                queue_sizes: QUEUE_SIZES.to_vec(),
                paused_sync: Some(Arc::new(Barrier::new(2))),
                avail_features,
                acked_features,
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            random_file: Some(random_file),
            seccomp_action,
            exit_evt,
        })
    }

    fn state(&self) -> RngState {
        RngState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
    }
}

impl VirtioDevice for Rng {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn activate(&mut self, context: crate::device::ActivationContext) -> ActivateResult {
        let crate::device::ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        if let Some(file) = self.random_file.as_ref() {
            let random_file = file.try_clone().map_err(|e| {
                error!("failed cloning rng source: {e}");
                ActivateError::BadActivate
            })?;

            let (_, queue, queue_evt) = queues.remove(0);

            let mut handler = RngEpollHandler {
                mem,
                queue,
                random_file,
                interrupt_cb: interrupt_cb.clone(),
                queue_evt,
                kill_evt,
                pause_evt,
                access_platform: self.common.access_platform(),
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();
            let mut epoll_threads = Vec::new();
            spawn_virtio_thread(
                &self.id,
                &self.seccomp_action,
                Thread::VirtioRng,
                &mut epoll_threads,
                &self.exit_evt,
                device_status.clone(),
                interrupt_cb.clone(),
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;

            self.common.epoll_threads = Some(epoll_threads);

            event!("virtio-device", "activated", "id", &self.id);
            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }

    fn reset(&mut self) {
        self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }
}

impl Pausable for Rng {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Rng {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for Rng {}
impl Migratable for Rng {}

#[cfg(test)]
mod unit_tests {
    use std::sync::Arc;

    use libc::EFD_NONBLOCK;
    use virtio_bindings::virtio_ring::VRING_DESC_F_WRITE;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic};
    use vm_virtio::queue::testing::VirtQueue as GuestQ;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::GuestMemoryMmap;
    use crate::device::{VirtioInterrupt, VirtioInterruptType};

    struct NoopVirtioInterrupt;

    impl VirtioInterrupt for NoopVirtioInterrupt {
        fn trigger(
            &self,
            _int_type: VirtioInterruptType,
        ) -> std::result::Result<(), std::io::Error> {
            Ok(())
        }

        fn set_notifier(
            &self,
            _interrupt: u32,
            _eventfd: Option<EventFd>,
            _vm: &dyn hypervisor::Vm,
        ) -> std::io::Result<()> {
            unimplemented!()
        }
    }

    fn build_handler(
        mem_size: usize,
        desc_addr: u64,
        desc_len: u32,
    ) -> (RngEpollHandler, GuestMemoryMmap) {
        const QSIZE: u16 = 2;

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let guest_vq = GuestQ::new(GuestAddress(0x1_0000), &mem, QSIZE);
        let queue = guest_vq.create_queue();

        guest_vq.dtable[0].set(
            desc_addr,
            desc_len,
            VRING_DESC_F_WRITE.try_into().unwrap(),
            0,
        );
        guest_vq.avail.ring[0].set(0);
        guest_vq.avail.idx.set(1);

        let handler = RngEpollHandler {
            mem: GuestMemoryAtomic::new(mem.clone()),
            queue,
            random_file: File::open("/dev/zero").unwrap(),
            interrupt_cb: Arc::new(NoopVirtioInterrupt),
            queue_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            kill_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            pause_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
            access_platform: None,
        };

        (handler, mem)
    }

    const SENTINEL: u8 = 0xa5;

    #[test]
    fn process_queue_in_bounds_overwrites_buffer() {
        let (mut handler, mem) = build_handler(128 * 1024, 0x4000, 4096);
        mem.write_obj(SENTINEL, GuestAddress(0x4000)).unwrap();
        assert!(handler.process_queue().unwrap());
        let first: u8 = mem.read_obj(GuestAddress(0x4000)).unwrap();
        assert_eq!(first, 0);
    }

    #[test]
    fn process_queue_overflow_preserves_buffer() {
        // 128 KiB of guest RAM, descriptor at 0x4000 claiming 1 GiB.
        // The descriptor overshoots guest memory, so process_queue must
        // skip it and leave the sentinel byte at 0x4000 untouched.
        let (mut handler, mem) = build_handler(128 * 1024, 0x4000, 1 << 30);
        mem.write_obj(SENTINEL, GuestAddress(0x4000))
            .expect("write sentinel into guest memory");
        assert!(
            handler
                .process_queue()
                .expect("process_queue must not fail"),
        );
        let first: u8 = mem
            .read_obj(GuestAddress(0x4000))
            .expect("read back sentinel from guest memory");
        assert_eq!(
            first, SENTINEL,
            "oversize descriptor must not overwrite buffer"
        );
    }
}
