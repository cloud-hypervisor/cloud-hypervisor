// Copyright (c) 2020 Ant Financial
// Copyright (c) 2025 Demi Marie Obenour
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::{self};
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};

use anyhow::anyhow;
use event_monitor::event;
use log::{error, info};
use seccompiler::SeccompAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_queue::{Queue, QueueT};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vmm_sys_util::eventfd::EventFd;

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError, EpollHelperHandler,
    GuestMemoryMmap, VIRTIO_F_VERSION_1, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterrupt, VirtioInterruptType,
};

const QUEUE_SIZE: u16 = 128;
const MIN_NUM_QUEUES: usize = 2;

// Inflate virtio queue event.
const FRONT2BACK_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// Deflate virtio queue event.
const BACK2FRONT_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Guest gave us bad memory addresses.")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Guest gave us a write only descriptor that protocol says to read from")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Guest sent us invalid request")]
    InvalidRequest,
    #[error("Failed to EventFd write.")]
    EventFdWriteFail(#[source] std::io::Error),
    #[error("Invalid queue index: {0}")]
    InvalidQueueIndex(usize),
    #[error("Fail tp signal")]
    FailedSignal(#[source] io::Error),
    #[error("Descriptor chain is too short")]
    DescriptorChainTooShort,
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
}

struct VdbEpollHandler {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    front2back_queue: Queue,
    back2front_queue: Queue,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    front2back_queue_evt: EventFd,
    back2front_queue_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl VdbEpollHandler {
    fn signal(&self, int_type: VirtioInterruptType) -> result::Result<(), Error> {
        self.interrupt_cb.trigger(int_type).map_err(|e| {
            error!("Failed to signal used queue: {e:?}");
            Error::FailedSignal(e)
        })
    }

    #[allow(unused)]
    fn process_front2back_queue(&mut self) -> result::Result<(), Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) = self
            .front2back_queue
            .pop_descriptor_chain(self.mem.memory())
        {
            let desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;
            used_descs = true;
            todo!();
        }

        if used_descs {
            self.signal(VirtioInterruptType::Queue(0))
        } else {
            Ok(())
        }
    }

    #[allow(unused)]
    fn process_back2front_queue(&mut self) -> result::Result<(), Error> {
        let mut used_descs = false;
        while let Some(mut desc_chain) = self
            .back2front_queue
            .pop_descriptor_chain(self.mem.memory())
        {
            let desc = desc_chain.next().ok_or(Error::DescriptorChainTooShort)?;
            used_descs = true;
            todo!();
        }

        if used_descs {
            self.signal(VirtioInterruptType::Queue(1))
        } else {
            Ok(())
        }
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(
            self.front2back_queue_evt.as_raw_fd(),
            FRONT2BACK_QUEUE_EVENT,
        )?;
        helper.add_event(
            self.back2front_queue_evt.as_raw_fd(),
            BACK2FRONT_QUEUE_EVENT,
        )?;
        helper.run(paused, paused_sync, self)?;
        Ok(())
    }
}

impl EpollHelperHandler for VdbEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            FRONT2BACK_QUEUE_EVENT => {
                self.front2back_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get inflate queue event: {e:?}"
                    ))
                })?;
                self.process_front2back_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to signal used inflate queue: {e:?}"
                    ))
                })?;
            }
            BACK2FRONT_QUEUE_EVENT => {
                self.back2front_queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to get back-to-front queue event: {e:?}"
                    ))
                })?;
                self.process_back2front_queue().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!(
                        "Failed to signal used deflate queue: {e:?}"
                    ))
                })?;
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unknown event for virtio-vdb"
                )));
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct VirtioVdbConfig;

#[derive(Serialize, Deserialize)]
pub struct VdbState {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioVdbConfig,
}

// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Vdb {
    common: VirtioCommon,
    id: String,
    config: VirtioVdbConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
}

impl Vdb {
    // Create a new virtio-vdb.
    pub fn new(
        id: String,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        state: Option<VdbState>,
    ) -> io::Result<Self> {
        let queue_sizes = vec![QUEUE_SIZE; MIN_NUM_QUEUES];

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-balloon {id}");
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            let avail_features = 1u64 << VIRTIO_F_VERSION_1;

            let config = VirtioVdbConfig;

            (avail_features, 0, config, false)
        };

        Ok(Vdb {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Balloon as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(2))),
                queue_sizes,
                min_queues: MIN_NUM_QUEUES as u16,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            interrupt_cb: None,
        })
    }

    fn state(&self) -> VdbState {
        VdbState {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl Drop for Vdb {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
        self.common.wait_for_epoll_threads();
    }
}

impl VirtioDevice for Vdb {
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

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        todo!()
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        todo!()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, interrupt_cb.clone())?;
        let (kill_evt, pause_evt) = self.common.dup_eventfds();

        let (_, front2back_queue, front2back_queue_evt) = queues.remove(0);
        let (_, back2front_queue, back2front_queue_evt) = queues.remove(0);

        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut handler = VdbEpollHandler {
            mem,
            back2front_queue,
            front2back_queue,
            interrupt_cb,
            front2back_queue_evt,
            back2front_queue_evt,
            kill_evt,
            pause_evt,
        };

        let paused = self.common.paused.clone();
        let paused_sync = self.common.paused_sync.clone();
        let mut epoll_threads = Vec::new();

        spawn_virtio_thread(
            &self.id,
            &self.seccomp_action,
            Thread::VirtioVdb,
            &mut epoll_threads,
            &self.exit_evt,
            move || handler.run(&paused, paused_sync.as_ref().unwrap()),
        )?;
        self.common.epoll_threads = Some(epoll_threads);

        event!("virtio-device", "activated", "id", &self.id);
        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        let result = self.common.reset();
        event!("virtio-device", "reset", "id", &self.id);
        result
    }
}

impl Pausable for Vdb {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Vdb {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Vdb {}
impl Migratable for Vdb {}
