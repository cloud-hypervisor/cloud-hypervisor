// Copyright © 2024 Google LLC
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::{io, result};

use num_enum::TryFromPrimitive;
use pci::{
    BarReprogrammingParams, PciBarConfiguration, PciBarPrefetchable, PciBarRegionType,
    PciClassCode, PciConfiguration, PciDevice, PciDeviceError, PciHeaderType, PciSubclass,
};
use thiserror::Error;
use vm_allocator::page_size::get_page_size;
use vm_allocator::{AddressAllocator, SystemAllocator};
use vm_device::{BusDeviceSync, Resource};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryError, GuestMemoryMmap, Le32, Le64,
};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

const PVMEMCONTROL_VENDOR_ID: u16 = 0x1ae0;
const PVMEMCONTROL_DEVICE_ID: u16 = 0x0087;

const PVMEMCONTROL_SUBSYSTEM_VENDOR_ID: u16 = 0x1ae0;
const PVMEMCONTROL_SUBSYSTEM_ID: u16 = 0x011F;

const MAJOR_VERSION: u64 = 1;
const MINOR_VERSION: u64 = 0;

#[derive(Error, Debug)]
pub enum Error {
    // device errors
    #[error("Guest gave us bad memory addresses")]
    GuestMemory(#[source] GuestMemoryError),
    #[error("Guest sent us invalid request")]
    InvalidRequest,

    #[error("Guest sent us invalid command: {0}")]
    InvalidCommand(u32),
    #[error("Guest sent us invalid connection: {0}")]
    InvalidConnection(u32),

    // pvmemcontrol errors
    #[error("Request contains invalid arguments: {0}")]
    InvalidArgument(u64),
    #[error("Unknown function code: {0}")]
    UnknownFunctionCode(u64),
    #[error("Libc call fail")]
    LibcFail(#[source] std::io::Error),
}

#[derive(Copy, Clone)]
enum PvmemcontrolSubclass {
    Other = 0x80,
}

impl PciSubclass for PvmemcontrolSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// commands have 0 as the most significant byte
#[repr(u32)]
#[derive(PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
enum PvmemcontrolTransportCommand {
    Reset = 0x060f_e6d2,
    Register = 0x0e35_9539,
    Ready = 0x0ca8_d227,
    Disconnect = 0x030f_5da0,
    Ack = 0x03cf_5196,
    Error = 0x01fb_a249,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PvmemcontrolTransportRegister {
    buf_phys_addr: Le64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PvmemcontrolTransportRegisterResponse {
    command: Le32,
    _padding: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
union PvmemcontrolTransportUnion {
    register: PvmemcontrolTransportRegister,
    register_response: PvmemcontrolTransportRegisterResponse,
    unit: (),
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PvmemcontrolTransport {
    payload: PvmemcontrolTransportUnion,
    command: PvmemcontrolTransportCommand,
}

const PVMEMCONTROL_DEVICE_MMIO_SIZE: u64 = std::mem::size_of::<PvmemcontrolTransport>() as u64;
const PVMEMCONTROL_DEVICE_MMIO_ALIGN: u64 = std::mem::align_of::<PvmemcontrolTransport>() as u64;

impl PvmemcontrolTransport {
    fn ack() -> Self {
        PvmemcontrolTransport {
            payload: PvmemcontrolTransportUnion { unit: () },
            command: PvmemcontrolTransportCommand::Ack,
        }
    }

    fn error() -> Self {
        PvmemcontrolTransport {
            payload: PvmemcontrolTransportUnion { unit: () },
            command: PvmemcontrolTransportCommand::Error,
        }
    }

    fn register_response(command: u32) -> Self {
        PvmemcontrolTransport {
            payload: PvmemcontrolTransportUnion {
                register_response: PvmemcontrolTransportRegisterResponse {
                    command: command.into(),
                    _padding: 0,
                },
            },
            command: PvmemcontrolTransportCommand::Ack,
        }
    }

    unsafe fn as_register(self) -> PvmemcontrolTransportRegister {
        // SAFETY: We access initialized data.
        unsafe { self.payload.register }
    }
}

// SAFETY: Contains no references and does not have compiler-inserted padding
unsafe impl ByteValued for PvmemcontrolTransportUnion {}
// SAFETY: Contains no references and does not have compiler-inserted padding
unsafe impl ByteValued for PvmemcontrolTransport {}

#[repr(u64)]
#[derive(Copy, Clone, TryFromPrimitive, Debug)]
enum FunctionCode {
    Info = 0,
    Dontneed = 1,
    Remove = 2,
    Free = 3,
    Pageout = 4,
    Dontdump = 5,
    SetVMAAnonName = 6,
    Mlock = 7,
    Munlock = 8,
    MprotectNone = 9,
    MprotectR = 10,
    MprotectW = 11,
    MprotectRW = 12,
    Mergeable = 13,
    Unmergeable = 14,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct PvmemcontrolReq {
    func_code: Le64,
    addr: Le64,
    length: Le64,
    arg: Le64,
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for PvmemcontrolReq {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct PvmemcontrolResp {
    ret_errno: Le32,
    ret_code: Le32,
    ret_value: Le64,
    arg0: Le64,
    arg1: Le64,
}

impl std::fmt::Debug for PvmemcontrolResp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PvmemcontrolResp {
            ret_errno,
            ret_code,
            ..
        } = self;
        write!(
            f,
            "PvmemcontrolResp {{ ret_errno: {}, ret_code: {}, .. }}",
            ret_errno.to_native(),
            ret_code.to_native()
        )
    }
}

// SAFETY: it only has data and has no implicit padding.
unsafe impl ByteValued for PvmemcontrolResp {}

/// The guest connections start at 0x8000_0000, which has a leading 1 in
/// the most significant byte, this ensures it does not conflict with
/// any of the transport commands
#[derive(Hash, Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuestConnection {
    command: u32,
}

impl Default for GuestConnection {
    fn default() -> Self {
        GuestConnection::new(0x8000_0000)
    }
}

impl GuestConnection {
    fn new(command: u32) -> Self {
        Self { command }
    }

    fn next(&self) -> Self {
        let GuestConnection { command } = *self;

        if command == u32::MAX {
            GuestConnection::default()
        } else {
            GuestConnection::new(command + 1)
        }
    }
}

impl TryFrom<u32> for GuestConnection {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (value & 0x8000_0000) != 0 {
            Ok(GuestConnection::new(value))
        } else {
            Err(Error::InvalidConnection(value))
        }
    }
}

struct PercpuInitState {
    port_buf_map: HashMap<GuestConnection, GuestAddress>,
    next_conn: GuestConnection,
}

impl PercpuInitState {
    fn new() -> Self {
        PercpuInitState {
            port_buf_map: HashMap::new(),
            next_conn: GuestConnection::default(),
        }
    }
}

enum PvmemcontrolState {
    PercpuInit(PercpuInitState),
    Ready(HashMap<GuestConnection, GuestAddress>),
    Broken,
}

pub struct PvmemcontrolDevice {
    transport: PvmemcontrolTransport,
    state: PvmemcontrolState,
}

impl PvmemcontrolDevice {
    fn new(transport: PvmemcontrolTransport, state: PvmemcontrolState) -> Self {
        PvmemcontrolDevice { transport, state }
    }
}

impl PvmemcontrolDevice {
    fn register_percpu_buf(
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
        mut state: PercpuInitState,
        PvmemcontrolTransportRegister { buf_phys_addr }: PvmemcontrolTransportRegister,
    ) -> Self {
        // access to this address is checked
        let buf_phys_addr = GuestAddress(buf_phys_addr.into());
        if !guest_memory.memory().check_range(
            buf_phys_addr,
            std::mem::size_of::<PvmemcontrolResp>().max(std::mem::size_of::<PvmemcontrolReq>()),
        ) {
            warn!("guest sent invalid phys addr {:#x}", buf_phys_addr.0);
            return PvmemcontrolDevice::new(
                PvmemcontrolTransport::error(),
                PvmemcontrolState::Broken,
            );
        }

        let conn = {
            // find an available port+byte combination, and fail if full
            let mut next_conn = state.next_conn;
            while state.port_buf_map.contains_key(&next_conn) {
                next_conn = next_conn.next();
                if next_conn == state.next_conn {
                    warn!("connections exhausted");
                    return PvmemcontrolDevice::new(
                        PvmemcontrolTransport::error(),
                        PvmemcontrolState::Broken,
                    );
                }
            }
            next_conn
        };
        state.next_conn = conn.next();
        state.port_buf_map.insert(conn, buf_phys_addr);

        // inform guest of the connection
        let response = PvmemcontrolTransport::register_response(conn.command);

        PvmemcontrolDevice::new(response, PvmemcontrolState::PercpuInit(state))
    }

    fn reset() -> Self {
        PvmemcontrolDevice::new(
            PvmemcontrolTransport::ack(),
            PvmemcontrolState::PercpuInit(PercpuInitState::new()),
        )
    }

    fn error() -> Self {
        PvmemcontrolDevice::new(PvmemcontrolTransport::error(), PvmemcontrolState::Broken)
    }

    fn ready(PercpuInitState { port_buf_map, .. }: PercpuInitState) -> Self {
        PvmemcontrolDevice::new(
            PvmemcontrolTransport::ack(),
            PvmemcontrolState::Ready(port_buf_map),
        )
    }

    fn run_command(
        &mut self,
        guest_memory: &GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
        command: PvmemcontrolTransportCommand,
    ) {
        let state = std::mem::replace(&mut self.state, PvmemcontrolState::Broken);

        *self = match command {
            PvmemcontrolTransportCommand::Reset => Self::reset(),
            PvmemcontrolTransportCommand::Register => {
                if let PvmemcontrolState::PercpuInit(state) = state {
                    // SAFETY: By device protocol. If driver is wrong the device
                    // can enter a Broken state, but the behavior is still sound.
                    Self::register_percpu_buf(guest_memory, state, unsafe {
                        self.transport.as_register()
                    })
                } else {
                    debug!("received register without reset");
                    Self::error()
                }
            }
            PvmemcontrolTransportCommand::Ready => {
                if let PvmemcontrolState::PercpuInit(state) = state {
                    Self::ready(state)
                } else {
                    debug!("received ready without reset");
                    Self::error()
                }
            }
            PvmemcontrolTransportCommand::Disconnect => Self::error(),
            PvmemcontrolTransportCommand::Ack => {
                debug!("received ack as command");
                Self::error()
            }
            PvmemcontrolTransportCommand::Error => {
                debug!("received error as command");
                Self::error()
            }
        }
    }

    /// read from the transport
    fn read_transport(&self, offset: u64, data: &mut [u8]) {
        self.transport
            .as_slice()
            .iter()
            .skip(offset as usize)
            .zip(data.iter_mut())
            .for_each(|(src, dest)| *dest = *src)
    }

    /// can only write to transport payload
    /// command is a special register that needs separate dispatching
    fn write_transport(&mut self, offset: u64, data: &[u8]) {
        self.transport
            .payload
            .as_mut_slice()
            .iter_mut()
            .skip(offset as usize)
            .zip(data.iter())
            .for_each(|(dest, src)| *dest = *src)
    }

    fn find_connection(&self, conn: GuestConnection) -> Option<GuestAddress> {
        match &self.state {
            PvmemcontrolState::Ready(map) => map.get(&conn).copied(),
            _ => None,
        }
    }
}

pub struct PvmemcontrolBusDevice {
    mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    dev: RwLock<PvmemcontrolDevice>,
}

pub struct PvmemcontrolPciDevice {
    id: String,
    configuration: PciConfiguration,
    bar_regions: Vec<PciBarConfiguration>,
}

impl PvmemcontrolBusDevice {
    /// f is called with the host address of `range_base` and only when
    /// [`range_base`, `range_base` + `range_len`) is present in the guest
    fn operate_on_memory_range<F>(&self, addr: u64, length: u64, f: F) -> result::Result<(), Error>
    where
        F: FnOnce(*mut libc::c_void, libc::size_t) -> libc::c_int,
    {
        let memory = self.mem.memory();
        let range_base = GuestAddress(addr);
        let range_len = usize::try_from(length).map_err(|_| Error::InvalidRequest)?;

        // assume guest memory is not interleaved with vmm memory on the host.
        if !memory.check_range(range_base, range_len) {
            return Err(Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(
                range_base,
            )));
        }
        let hva = memory
            .get_host_address(range_base)
            .map_err(Error::GuestMemory)?;
        let res = f(hva as *mut libc::c_void, range_len as libc::size_t);
        if res != 0 {
            return Err(Error::LibcFail(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn madvise(&self, addr: u64, length: u64, advice: libc::c_int) -> result::Result<(), Error> {
        // SAFETY: [`base`, `base` + `len`) is guest memory
        self.operate_on_memory_range(addr, length, |base, len| unsafe {
            libc::madvise(base, len, advice)
        })
    }

    fn mlock(&self, addr: u64, length: u64, on_default: bool) -> result::Result<(), Error> {
        // SAFETY: [`base`, `base` + `len`) is guest memory
        self.operate_on_memory_range(addr, length, |base, len| unsafe {
            libc::mlock2(base, len, if on_default { libc::MLOCK_ONFAULT } else { 0 })
        })
    }

    fn munlock(&self, addr: u64, length: u64) -> result::Result<(), Error> {
        // SAFETY: [`base`, `base` + `len`) is guest memory
        self.operate_on_memory_range(addr, length, |base, len| unsafe {
            libc::munlock(base, len)
        })
    }

    fn mprotect(
        &self,
        addr: u64,
        length: u64,
        protection: libc::c_int,
    ) -> result::Result<(), Error> {
        // SAFETY: [`base`, `base` + `len`) is guest memory
        self.operate_on_memory_range(addr, length, |base, len| unsafe {
            libc::mprotect(base, len, protection)
        })
    }

    fn set_vma_anon_name(&self, addr: u64, length: u64, name: u64) -> result::Result<(), Error> {
        let name = (name != 0).then(|| CString::new(format!("pvmemcontrol-{name}")).unwrap());
        let name_ptr = if let Some(name) = &name {
            name.as_ptr()
        } else {
            std::ptr::null()
        };
        debug!("addr {:X} length {} name {:?}", addr, length, name);

        // SAFETY: [`base`, `base` + `len`) is guest memory
        self.operate_on_memory_range(addr, length, |base, len| unsafe {
            libc::prctl(
                libc::PR_SET_VMA,
                libc::PR_SET_VMA_ANON_NAME,
                base,
                len,
                name_ptr,
            )
        })
    }

    fn process_request(
        &self,
        func_code: FunctionCode,
        addr: u64,
        length: u64,
        arg: u64,
    ) -> Result<PvmemcontrolResp, Error> {
        let result = match func_code {
            FunctionCode::Info => {
                return Ok(PvmemcontrolResp {
                    ret_errno: 0.into(),
                    ret_code: 0.into(),
                    ret_value: get_page_size().into(),
                    arg0: MAJOR_VERSION.into(),
                    arg1: MINOR_VERSION.into(),
                });
            }
            FunctionCode::Dontneed => self.madvise(addr, length, libc::MADV_DONTNEED),
            FunctionCode::Remove => self.madvise(addr, length, libc::MADV_REMOVE),
            FunctionCode::Free => self.madvise(addr, length, libc::MADV_FREE),
            FunctionCode::Pageout => self.madvise(addr, length, libc::MADV_PAGEOUT),
            FunctionCode::Dontdump => self.madvise(addr, length, libc::MADV_DONTDUMP),
            FunctionCode::SetVMAAnonName => self.set_vma_anon_name(addr, length, arg),
            FunctionCode::Mlock => self.mlock(addr, length, false),
            FunctionCode::Munlock => self.munlock(addr, length),
            FunctionCode::MprotectNone => self.mprotect(addr, length, libc::PROT_NONE),
            FunctionCode::MprotectR => self.mprotect(addr, length, libc::PROT_READ),
            FunctionCode::MprotectW => self.mprotect(addr, length, libc::PROT_WRITE),
            FunctionCode::MprotectRW => {
                self.mprotect(addr, length, libc::PROT_READ | libc::PROT_WRITE)
            }
            FunctionCode::Mergeable => self.madvise(addr, length, libc::MADV_MERGEABLE),
            FunctionCode::Unmergeable => self.madvise(addr, length, libc::MADV_UNMERGEABLE),
        };
        result.map(|_| PvmemcontrolResp::default())
    }

    fn handle_request(
        &self,
        PvmemcontrolReq {
            func_code,
            addr,
            length,
            arg,
        }: PvmemcontrolReq,
    ) -> Result<PvmemcontrolResp, Error> {
        let (func_code, addr, length, arg) = (
            func_code.to_native(),
            addr.to_native(),
            length.to_native(),
            arg.to_native(),
        );

        let resp_or_err = FunctionCode::try_from(func_code)
            .map_err(|_| Error::UnknownFunctionCode(func_code))
            .and_then(|func_code| self.process_request(func_code, addr, length, arg));

        let resp = match resp_or_err {
            Ok(resp) => resp,
            Err(e) => match e {
                Error::InvalidArgument(arg) => PvmemcontrolResp {
                    ret_errno: (libc::EINVAL as u32).into(),
                    ret_code: (arg as u32).into(),
                    ..Default::default()
                },
                Error::LibcFail(err) => PvmemcontrolResp {
                    ret_errno: (err.raw_os_error().unwrap_or(libc::EFAULT) as u32).into(),
                    ret_code: 0u32.into(),
                    ..Default::default()
                },
                Error::UnknownFunctionCode(func_code) => PvmemcontrolResp {
                    ret_errno: (libc::EOPNOTSUPP as u32).into(),
                    ret_code: (func_code as u32).into(),
                    ..Default::default()
                },
                Error::GuestMemory(err) => {
                    warn!("{}", err);
                    PvmemcontrolResp {
                        ret_errno: (libc::EINVAL as u32).into(),
                        ret_code: (func_code as u32).into(),
                        ..Default::default()
                    }
                }
                // device error, stop responding
                other => return Err(other),
            },
        };
        Ok(resp)
    }

    fn handle_pvmemcontrol_request(&self, guest_addr: GuestAddress) {
        let request: PvmemcontrolReq = if let Ok(x) = self.mem.memory().read_obj(guest_addr) {
            x
        } else {
            warn!("cannot read from guest address {:#x}", guest_addr.0);
            return;
        };

        let response: PvmemcontrolResp = match self.handle_request(request) {
            Ok(x) => x,
            Err(e) => {
                warn!("cannot process request {:?} with error {}", request, e);
                return;
            }
        };

        if self.mem.memory().write_obj(response, guest_addr).is_err() {
            warn!("cannot write to guest address {:#x}", guest_addr.0);
        }
    }

    fn handle_guest_write(&self, offset: u64, data: &[u8]) {
        if offset as usize != std::mem::offset_of!(PvmemcontrolTransport, command) {
            if data.len() != 4 && data.len() != 8 {
                warn!("guest write is not 4 or 8 bytes long");
                return;
            }
            self.dev.write().unwrap().write_transport(offset, data);
            return;
        }
        let data = if data.len() == 4 {
            let mut d = [0u8; 4];
            d.iter_mut()
                .zip(data.iter())
                .for_each(|(d, data)| *d = *data);
            d
        } else {
            warn!("guest write with non u32 at command register");
            return;
        };
        let data_cmd = u32::from_le_bytes(data);
        let command = PvmemcontrolTransportCommand::try_from(data_cmd);

        match command {
            Ok(command) => self.dev.write().unwrap().run_command(&self.mem, command),
            Err(_) => {
                GuestConnection::try_from(data_cmd)
                    .and_then(|conn| {
                        self.dev
                            .read()
                            .unwrap()
                            .find_connection(conn)
                            .ok_or(Error::InvalidConnection(conn.command))
                    })
                    .map(|gpa| self.handle_pvmemcontrol_request(gpa))
                    .unwrap_or_else(|err| warn!("{:?}", err));
            }
        }
    }

    fn handle_guest_read(&self, offset: u64, data: &mut [u8]) {
        self.dev.read().unwrap().read_transport(offset, data)
    }
}

impl PvmemcontrolDevice {
    pub fn make_device(
        id: String,
        mem: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    ) -> (PvmemcontrolPciDevice, PvmemcontrolBusDevice) {
        let dev = RwLock::new(PvmemcontrolDevice::error());
        let mut configuration = PciConfiguration::new(
            PVMEMCONTROL_VENDOR_ID,
            PVMEMCONTROL_DEVICE_ID,
            0x1,
            PciClassCode::BaseSystemPeripheral,
            &PvmemcontrolSubclass::Other,
            None,
            PciHeaderType::Device,
            PVMEMCONTROL_SUBSYSTEM_VENDOR_ID,
            PVMEMCONTROL_SUBSYSTEM_ID,
            None,
            None,
        );
        let command: [u8; 2] = [0x03, 0x01]; // memory, io, SERR#

        configuration.write_config_register(1, 0, &command);
        (
            PvmemcontrolPciDevice {
                id,
                configuration,
                bar_regions: Vec::new(),
            },
            PvmemcontrolBusDevice { mem, dev },
        )
    }
}

impl PciDevice for PvmemcontrolPciDevice {
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> (Vec<BarReprogrammingParams>, Option<Arc<Barrier>>) {
        (
            self.configuration
                .write_config_register(reg_idx, offset, data),
            None,
        )
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.configuration.read_config_register(reg_idx)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }

    fn allocate_bars(
        &mut self,
        _allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>, PciDeviceError> {
        let mut bars = Vec::new();
        let region_type = PciBarRegionType::Memory32BitRegion;
        let bar_id = 0;
        let region_size = PVMEMCONTROL_DEVICE_MMIO_SIZE;
        let restoring = resources.is_some();
        let bar_addr = mmio32_allocator
            .allocate(None, region_size, Some(PVMEMCONTROL_DEVICE_MMIO_ALIGN))
            .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;

        let bar = PciBarConfiguration::default()
            .set_index(bar_id as usize)
            .set_address(bar_addr.raw_value())
            .set_size(region_size)
            .set_region_type(region_type)
            .set_prefetchable(PciBarPrefetchable::NotPrefetchable);

        if !restoring {
            self.configuration
                .add_pci_bar(&bar)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
        }

        bars.push(bar);
        self.bar_regions.clone_from(&bars);
        Ok(bars)
    }

    fn free_bars(
        &mut self,
        _allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
    ) -> Result<(), PciDeviceError> {
        for bar in self.bar_regions.drain(..) {
            mmio32_allocator.free(GuestAddress(bar.addr()), bar.size())
        }
        Ok(())
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> result::Result<(), io::Error> {
        for bar in self.bar_regions.iter_mut() {
            if bar.addr() == old_base {
                *bar = bar.set_address(new_base);
            }
        }
        Ok(())
    }
}

impl Pausable for PvmemcontrolPciDevice {
    fn pause(&mut self) -> std::result::Result<(), MigratableError> {
        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), MigratableError> {
        Ok(())
    }
}

impl Snapshottable for PvmemcontrolPciDevice {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        let mut snapshot = Snapshot::new_from_state(&())?;

        // Snapshot PciConfiguration
        snapshot.add_snapshot(self.configuration.id(), self.configuration.snapshot()?);

        Ok(snapshot)
    }
}

impl Transportable for PvmemcontrolPciDevice {}
impl Migratable for PvmemcontrolPciDevice {}

impl BusDeviceSync for PvmemcontrolBusDevice {
    fn read(&self, _base: u64, offset: u64, data: &mut [u8]) {
        self.handle_guest_read(offset, data)
    }

    fn write(&self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.handle_guest_write(offset, data);
        None
    }
}
