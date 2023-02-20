// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::Error as DeviceError;
use crate::GuestMemoryMmap;
use crate::VirtioInterruptType;
use crate::{
    ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, VirtioCommon, VirtioDevice,
    VirtioDeviceType, VirtioInterrupt, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_VERSION_1,
};
use anyhow::anyhow;
use seccompiler::SeccompAction;
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use thiserror::Error;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_queue::{Queue, QueueT};
use virtiofsd::{
    descriptor_utils::{Error as VufDescriptorError, Reader, Writer},
    filesystem::FileSystem,
    passthrough::{self, PassthroughFs},
    server::Server,
    Error as VhostUserFsError,
};
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable, VersionMapped,
};
use vmm_sys_util::eventfd::EventFd;

const NUM_QUEUE_OFFSET: usize = 1;
const DEFAULT_QUEUE_NUMBER: usize = 2;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Processing queue failed: {0}")]
    ProcessQueue(VhostUserFsError),
    #[error("Creating a queue reader failed: {0}")]
    QueueReader(VufDescriptorError),
    #[error("Creating a queue writer failed: {0}")]
    QueueWriter(VufDescriptorError),
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Versionize)]
pub struct State {
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioFsConfig,
}

impl VersionMapped for State {}

#[derive(Copy, Clone, Versionize)]
#[repr(C, packed)]
pub struct VirtioFsConfig {
    pub tag: [u8; 36],
    pub num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

struct FsEpollHandler<F: FileSystem + Sync> {
    queue_index: u16,
    queue_evt: EventFd,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    server: Arc<Server<F>>,
}

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

impl<F: FileSystem + Sync> FsEpollHandler<F> {
    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;

        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn return_descriptor(queue: &mut Queue, mem: &GuestMemoryMmap, head_index: u16, len: usize) {
        let used_len: u32 = match len.try_into() {
            Ok(l) => l,
            Err(_) => panic!("Invalid used length, can't return used descritors to the ring"),
        };

        if queue.add_used(mem, head_index, used_len).is_err() {
            warn!("Couldn't return used descriptors to the ring");
        }
    }

    fn process_queue_serial(&mut self) -> Result<bool> {
        let queue = &mut self.queue;

        let mut used_descs = false;

        while let Some(desc_chain) = queue.pop_descriptor_chain(self.mem.memory()) {
            let head_index = desc_chain.head_index();

            let reader = Reader::new(desc_chain.memory(), desc_chain.clone())
                .map_err(Error::QueueReader)
                .unwrap();
            let writer = Writer::new(desc_chain.memory(), desc_chain.clone())
                .map_err(Error::QueueWriter)
                .unwrap();

            let len = self
                .server
                .handle_message(reader, writer)
                .map_err(Error::ProcessQueue)
                .unwrap();

            Self::return_descriptor(queue, desc_chain.memory(), head_index, len);
            used_descs = true;
        }

        Ok(used_descs)
    }

    fn handle_event_impl(&mut self) -> result::Result<(), EpollHelperError> {
        let needs_notification = self.process_queue_serial().map_err(|e| {
            EpollHelperError::HandleEvent(anyhow!("Failed to process queue (submit): {:?}", e))
        })?;

        if needs_notification {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {:?}", e))
            })?
        };

        Ok(())
    }
}

impl<F: FileSystem + Sync> EpollHelperHandler for FsEpollHandler<F> {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;
                self.handle_event_impl()?
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {}",
                    ev_type
                )));
            }
        }
        Ok(())
    }
}

// SAFETY: only a series of integers
unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    common: VirtioCommon,
    id: String,
    config: VirtioFsConfig,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
    iommu: bool,
}

impl Fs {
    /// Create a new virtio-fs device.
    #[allow(clippy::too_many_arguments)]
    #[allow(unused)]
    pub fn new(
        id: String,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        seccomp_action: SeccompAction,
        exit_evt: EventFd,
        iommu: bool,
        state: Option<State>,
    ) -> io::Result<Fs> {
        // Calculate the actual number of queues needed.
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;
        if num_queues > DEFAULT_QUEUE_NUMBER {
            error!(
                "virtio-fs requested too many queues ({}) since the backend only supports {}\n",
                num_queues, DEFAULT_QUEUE_NUMBER
            );
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("requested too many queues"),
            ));
        }

        let (avail_features, acked_features, config, paused) = if let Some(state) = state {
            info!("Restoring virtio-fs {}", id);
            (
                state.avail_features,
                state.acked_features,
                state.config,
                true,
            )
        } else {
            // Filling device and vring features VMM supports.
            let avail_features: u64 = 1 << VIRTIO_F_VERSION_1;

            // Create virtio-fs device configuration.
            let mut config = VirtioFsConfig::default();
            let tag_bytes_vec = tag.to_string().into_bytes();
            config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
            config.num_request_queues = req_num_queues as u32;

            (avail_features, 0, config, false)
        };
        Ok(Fs {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Fs as u32,
                avail_features,
                acked_features,
                queue_sizes: vec![queue_size; num_queues],
                paused_sync: Some(Arc::new(Barrier::new(2))),
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            config,
            seccomp_action,
            exit_evt,
            iommu,
        })
    }

    fn state(&self) -> State {
        State {
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        let mut features = self.common.avail_features;
        if self.iommu {
            features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }
        features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        mut queues: Vec<(usize, Queue, EventFd)>,
    ) -> ActivateResult {
        self.common.activate(&queues, &interrupt_cb)?;
        let server = Arc::new(Server::new(
            PassthroughFs::new(passthrough::Config::default()).unwrap(),
        ));
        let mut epoll_threads = Vec::new();
        for i in 0..queues.len() {
            let (_, queue, queue_evt) = queues.remove(0);
            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let mut handler = FsEpollHandler {
                queue_index: i as u16,
                queue_evt,
                queue,
                mem: mem.clone(),
                interrupt_cb: interrupt_cb.clone(),
                kill_evt,
                pause_evt,
                server: server.clone(),
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioFs,
                &mut epoll_threads,
                &self.exit_evt,
                move || handler.run(paused, paused_sync.unwrap()),
            )?;
        }

        self.common.epoll_threads = Some(epoll_threads);
        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn VirtioInterrupt>> {
        // We first must resume the virtio thread if it was paused.
        if self.common.pause_evt.take().is_some() {
            self.common.resume().ok()?;
        }

        if let Some(kill_evt) = self.common.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        event!("virtio-device", "reset", "id", &self.id);

        // Return the interrupt
        Some(self.common.interrupt_cb.take().unwrap())
    }
}

impl Pausable for Fs {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        self.common.pause()
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.common.resume()
    }
}

impl Snapshottable for Fs {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_versioned_state(&self.state())
    }
}
impl Transportable for Fs {}
impl Migratable for Fs {}
