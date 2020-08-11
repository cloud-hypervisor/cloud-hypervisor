// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollHelper, EpollHelperError, EpollHelperHandler, Queue,
    VirtioDevice, VirtioDeviceType, VirtioInterruptType, EPOLL_HELPER_EVENT_LAST,
    VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::VirtioInterrupt;
use anyhow::anyhow;
use libc::EFD_NONBLOCK;
use seccomp::{SeccompAction, SeccompFilter};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::ops::DerefMut;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use vm_memory::{ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotDataSection, Snapshottable,
    Transportable,
};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// New descriptors are pending on the virtio queue.
const INPUT_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
const OUTPUT_QUEUE_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// Some input from the VMM is ready to be injected into the VM.
const INPUT_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;
// Console configuration change event is triggered.
const CONFIG_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 4;

//Console size feature bit
const VIRTIO_CONSOLE_F_SIZE: u64 = 0;

#[derive(Copy, Clone, Debug, Default, Deserialize)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// We must explicitly implement Serialize since the structure is packed and
// it's unsafe to borrow from a packed structure. And by default, if we derive
// Serialize from serde, it will borrow the values from the structure.
// That's why this implementation copies each field separately before it
// serializes the entire structure field by field.
impl Serialize for VirtioConsoleConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let cols = self.cols;
        let rows = self.rows;
        let max_nr_ports = self.max_nr_ports;
        let emerg_wr = self.emerg_wr;

        let mut virtio_console_config = serializer.serialize_struct("VirtioConsoleConfig", 12)?;
        virtio_console_config.serialize_field("cols", &cols)?;
        virtio_console_config.serialize_field("rows", &rows)?;
        virtio_console_config.serialize_field("max_nr_ports", &max_nr_ports)?;
        virtio_console_config.serialize_field("emerg_wr", &emerg_wr)?;
        virtio_console_config.end()
    }
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioConsoleConfig {}

struct ConsoleEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    in_buffer: Arc<Mutex<VecDeque<u8>>>,
    out: Arc<Mutex<Box<dyn io::Write + Send + Sync + 'static>>>,
    input_queue_evt: EventFd,
    output_queue_evt: EventFd,
    input_evt: EventFd,
    config_evt: EventFd,
    kill_evt: EventFd,
    pause_evt: EventFd,
}

impl ConsoleEpollHandler {
    /*
     * Each port of virtio console device has one receive
     * queue. One or more empty buffers are placed by the
     * dirver in the receive queue for incoming data. Here,
     * we place the input data to these empty buffers.
     */
    fn process_input_queue(&mut self) -> bool {
        let mut in_buffer = self.in_buffer.lock().unwrap();
        let recv_queue = &mut self.queues[0]; //receiveq
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;

        if in_buffer.is_empty() {
            return false;
        }

        let mem = self.mem.memory();
        for avail_desc in recv_queue.iter(&mem) {
            let len = cmp::min(avail_desc.len as u32, in_buffer.len() as u32);
            let source_slice = in_buffer.drain(..len as usize).collect::<Vec<u8>>();
            if let Err(e) = mem.write_slice(&source_slice[..], avail_desc.addr) {
                error!("Failed to write slice: {:?}", e);
                recv_queue.go_to_previous_position();
                break;
            }

            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;

            if in_buffer.is_empty() {
                break;
            }
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            recv_queue.add_used(&mem, desc_index, len);
        }

        used_count > 0
    }

    /*
     * Each port of virtio console device has one transmit
     * queue. For outgoing data, characters are placed in
     * the transmit queue by the driver. Therefore, here
     * we read data from the transmit queue and flush them
     * to the referenced address.
     */
    fn process_output_queue(&mut self) -> bool {
        let trans_queue = &mut self.queues[1]; //transmitq
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;

        let mem = self.mem.memory();
        for avail_desc in trans_queue.iter(&mem) {
            let len;
            let mut out = self.out.lock().unwrap();
            let _ = mem.write_to(
                avail_desc.addr,
                &mut out.deref_mut(),
                avail_desc.len as usize,
            );
            let _ = out.flush();

            len = avail_desc.len;
            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }

        for &(desc_index, len) in &used_desc_heads[..used_count] {
            trans_queue.add_used(&mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(&VirtioInterruptType::Queue, Some(&self.queues[0]))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn run(&mut self, paused: Arc<AtomicBool>) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.input_queue_evt.as_raw_fd(), INPUT_QUEUE_EVENT)?;
        helper.add_event(self.output_queue_evt.as_raw_fd(), OUTPUT_QUEUE_EVENT)?;
        helper.add_event(self.input_evt.as_raw_fd(), INPUT_EVENT)?;
        helper.add_event(self.config_evt.as_raw_fd(), CONFIG_EVENT)?;
        helper.run(paused, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for ConsoleEpollHandler {
    fn handle_event(&mut self, _helper: &mut EpollHelper, event: u16) -> bool {
        match event {
            INPUT_QUEUE_EVENT => {
                if let Err(e) = self.input_queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else if self.process_input_queue() {
                    if let Err(e) = self.signal_used_queue() {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            OUTPUT_QUEUE_EVENT => {
                if let Err(e) = self.output_queue_evt.read() {
                    error!("Failed to get queue event: {:?}", e);
                    return true;
                } else {
                    self.process_output_queue();
                }
            }
            INPUT_EVENT => {
                if let Err(e) = self.input_evt.read() {
                    error!("Failed to get input event: {:?}", e);
                    return true;
                } else if self.process_input_queue() {
                    if let Err(e) = self.signal_used_queue() {
                        error!("Failed to signal used queue: {:?}", e);
                        return true;
                    }
                }
            }
            CONFIG_EVENT => {
                if let Err(e) = self.config_evt.read() {
                    error!("Failed to get config event: {:?}", e);
                    return true;
                } else if let Err(e) = self
                    .interrupt_cb
                    .trigger(&VirtioInterruptType::Config, None)
                {
                    error!("Failed to signal console driver: {:?}", e);
                    return true;
                }
            }
            _ => {
                error!("Unknown event for virtio-console");
                return true;
            }
        }
        false
    }
}

/// Input device.
pub struct ConsoleInput {
    input_evt: EventFd,
    config_evt: EventFd,
    in_buffer: Arc<Mutex<VecDeque<u8>>>,
    config: Arc<Mutex<VirtioConsoleConfig>>,
    acked_features: AtomicU64,
}

impl ConsoleInput {
    pub fn queue_input_bytes(&self, input: &[u8]) {
        let mut in_buffer = self.in_buffer.lock().unwrap();
        in_buffer.extend(input);
        let _ = self.input_evt.write(1);
    }

    pub fn update_console_size(&self, cols: u16, rows: u16) {
        if self
            .acked_features
            .fetch_and(1u64 << VIRTIO_CONSOLE_F_SIZE, Ordering::SeqCst)
            != 0
        {
            self.config.lock().unwrap().update_console_size(cols, rows);
            //Send the interrupt to the driver
            let _ = self.config_evt.write(1);
        }
    }
}

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports: 1u32,
            emerg_wr: 0u32,
        }
    }

    pub fn update_console_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }
}

/// Virtio device for exposing console to the guest OS through virtio.
pub struct Console {
    id: String,
    kill_evt: Option<EventFd>,
    pause_evt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
    config: Arc<Mutex<VirtioConsoleConfig>>,
    input: Arc<ConsoleInput>,
    out: Arc<Mutex<Box<dyn io::Write + Send + Sync + 'static>>>,
    queue_evts: Option<Vec<EventFd>>,
    interrupt_cb: Option<Arc<dyn VirtioInterrupt>>,
    epoll_threads: Option<Vec<thread::JoinHandle<()>>>,
    paused: Arc<AtomicBool>,
    seccomp_action: SeccompAction,
}

#[derive(Serialize, Deserialize)]
pub struct ConsoleState {
    avail_features: u64,
    acked_features: u64,
    config: VirtioConsoleConfig,
    in_buffer: VecDeque<u8>,
}

impl Console {
    /// Create a new virtio console device that gets random data from /dev/urandom.
    pub fn new(
        id: String,
        out: Box<dyn io::Write + Send + Sync + 'static>,
        cols: u16,
        rows: u16,
        iommu: bool,
        seccomp_action: SeccompAction,
    ) -> io::Result<(Console, Arc<ConsoleInput>)> {
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1 | 1u64 << VIRTIO_CONSOLE_F_SIZE;

        if iommu {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        let input_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let config_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let console_config = Arc::new(Mutex::new(VirtioConsoleConfig::new(cols, rows)));
        let console_input = Arc::new(ConsoleInput {
            input_evt,
            config_evt,
            in_buffer: Arc::new(Mutex::new(VecDeque::new())),
            config: console_config.clone(),
            acked_features: AtomicU64::new(0),
        });

        Ok((
            Console {
                id,
                kill_evt: None,
                pause_evt: None,
                avail_features,
                acked_features: 0u64,
                config: console_config,
                input: console_input.clone(),
                out: Arc::new(Mutex::new(out)),
                queue_evts: None,
                interrupt_cb: None,
                epoll_threads: None,
                paused: Arc::new(AtomicBool::new(false)),
                seccomp_action,
            },
            console_input,
        ))
    }

    fn state(&self) -> ConsoleState {
        ConsoleState {
            avail_features: self.avail_features,
            acked_features: self.acked_features,
            config: *(self.config.lock().unwrap()),
            in_buffer: self.input.in_buffer.lock().unwrap().clone(),
        }
    }

    fn set_state(&mut self, state: &ConsoleState) -> io::Result<()> {
        self.avail_features = state.avail_features;
        self.acked_features = state.acked_features;
        *(self.config.lock().unwrap()) = state.config;
        *(self.input.in_buffer.lock().unwrap()) = state.in_buffer.clone();

        Ok(())
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Console {
    fn device_type(&self) -> u32 {
        VirtioDeviceType::TYPE_CONSOLE as u32
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.lock().unwrap().as_slice(), offset, data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_cb: Arc<dyn VirtioInterrupt>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let (self_kill_evt, kill_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating kill EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;

        self.kill_evt = Some(self_kill_evt);

        let (self_pause_evt, pause_evt) = EventFd::new(EFD_NONBLOCK)
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(|e| {
                error!("failed creating pause EventFd pair: {}", e);
                ActivateError::BadActivate
            })?;
        self.pause_evt = Some(self_pause_evt);

        // Save the interrupt EventFD as we need to return it on reset
        // but clone it to pass into the thread.
        self.interrupt_cb = Some(interrupt_cb.clone());

        let mut tmp_queue_evts: Vec<EventFd> = Vec::new();
        for queue_evt in queue_evts.iter() {
            // Save the queue EventFD as we need to return it on reset
            // but clone it to pass into the thread.
            tmp_queue_evts.push(queue_evt.try_clone().map_err(|e| {
                error!("failed to clone queue EventFd: {}", e);
                ActivateError::BadActivate
            })?);
        }
        self.queue_evts = Some(tmp_queue_evts);

        self.input
            .acked_features
            .store(self.acked_features, Ordering::Relaxed);

        if (self.acked_features & (1u64 << VIRTIO_CONSOLE_F_SIZE)) != 0 {
            if let Err(e) = interrupt_cb.trigger(&VirtioInterruptType::Config, None) {
                error!("Failed to signal console driver: {:?}", e);
            }
        }

        let mut handler = ConsoleEpollHandler {
            queues,
            mem,
            interrupt_cb,
            in_buffer: self.input.in_buffer.clone(),
            out: self.out.clone(),
            input_queue_evt: queue_evts.remove(0),
            output_queue_evt: queue_evts.remove(0),
            input_evt: self.input.input_evt.try_clone().unwrap(),
            config_evt: self.input.config_evt.try_clone().unwrap(),
            kill_evt,
            pause_evt,
        };

        let paused = self.paused.clone();
        let mut epoll_threads = Vec::new();
        // Retrieve seccomp filter for virtio_console thread
        let virtio_console_seccomp_filter =
            get_seccomp_filter(&self.seccomp_action, Thread::VirtioConsole)
                .map_err(ActivateError::CreateSeccompFilter)?;
        thread::Builder::new()
            .name("virtio_console".to_string())
            .spawn(move || {
                if let Err(e) = SeccompFilter::apply(virtio_console_seccomp_filter) {
                    error!("Error applying seccomp filter: {:?}", e);
                } else if let Err(e) = handler.run(paused) {
                    error!("Error running worker: {:?}", e);
                }
            })
            .map(|thread| epoll_threads.push(thread))
            .map_err(|e| {
                error!("failed to clone the virtio-console epoll thread: {}", e);
                ActivateError::BadActivate
            })?;

        self.epoll_threads = Some(epoll_threads);

        Ok(())
    }

    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        // We first must resume the virtio thread if it was paused.
        if self.pause_evt.take().is_some() {
            self.resume().ok()?;
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        // Return the interrupt and queue EventFDs
        Some((
            self.interrupt_cb.take().unwrap(),
            self.queue_evts.take().unwrap(),
        ))
    }
}

virtio_pausable!(Console);
impl Snapshottable for Console {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&self) -> std::result::Result<Snapshot, MigratableError> {
        let snapshot =
            serde_json::to_vec(&self.state()).map_err(|e| MigratableError::Snapshot(e.into()))?;

        let mut console_snapshot = Snapshot::new(self.id.as_str());
        console_snapshot.add_data_section(SnapshotDataSection {
            id: format!("{}-section", self.id),
            snapshot,
        });

        Ok(console_snapshot)
    }

    fn restore(&mut self, snapshot: Snapshot) -> std::result::Result<(), MigratableError> {
        if let Some(console_section) = snapshot.snapshot_data.get(&format!("{}-section", self.id)) {
            let console_state = match serde_json::from_slice(&console_section.snapshot) {
                Ok(state) => state,
                Err(error) => {
                    return Err(MigratableError::Restore(anyhow!(
                        "Could not deserialize CONSOLE {}",
                        error
                    )))
                }
            };

            return self.set_state(&console_state).map_err(|e| {
                MigratableError::Restore(anyhow!("Could not restore CONSOLE state {:?}", e))
            });
        }

        Err(MigratableError::Restore(anyhow!(
            "Could not find CONSOLE snapshot section"
        )))
    }
}
impl Transportable for Console {}
impl Migratable for Console {}
