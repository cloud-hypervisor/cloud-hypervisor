//! Snapshot format: the on-disk representation of a paused VM.
//!
//! This is the heart of the "rehydration" dream. The layout is intentionally
//! backend-neutral:
//!   - architectural vCPU state (GPRs, PC, CPSR, curated EL1 sysregs)
//!   - device state (UART tx counter)
//!   - the full guest RAM image
//!
//! A real cloud snapshot would carry CPU state as KVM ONE_REG values; the
//! restore path would translate those into this neutral form (see INTEGRATION.md).

use std::fs::File;
use std::io::{self, Read, Write};

use crate::hvf::VcpuState;

const MAGIC: u32 = 0x4856_4d31; // "HVM1"
const VERSION: u32 = 1;

pub struct Snapshot {
    pub ram_base: u64,
    pub vcpu: VcpuState,
    pub uart_tx: u64,
    pub ram: Vec<u8>,
}

struct W {
    buf: Vec<u8>,
}
impl W {
    fn new() -> Self {
        W { buf: Vec::new() }
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
}

struct R<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        R { b, o: 0 }
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.b[self.o..self.o + 4].try_into().unwrap());
        self.o += 4;
        v
    }
    fn u64(&mut self) -> u64 {
        let v = u64::from_le_bytes(self.b[self.o..self.o + 8].try_into().unwrap());
        self.o += 8;
        v
    }
    fn rest(self) -> &'a [u8] {
        &self.b[self.o..]
    }
}

impl Snapshot {
    pub fn save(&self, path: &str) -> io::Result<()> {
        let mut w = W::new();
        w.u32(MAGIC);
        w.u32(VERSION);
        w.u64(self.ram_base);
        w.u64(self.ram.len() as u64);
        w.u64(self.uart_tx);

        // vCPU: 31 GPRs, PC, CPSR
        for g in &self.vcpu.gpr {
            w.u64(*g);
        }
        w.u64(self.vcpu.pc);
        w.u64(self.vcpu.cpsr);

        // sysregs: count then (id, value) pairs
        w.u32(self.vcpu.sysregs.len() as u32);
        for &(id, val) in &self.vcpu.sysregs {
            w.u32(id as u32);
            w.u64(val);
        }

        // RAM image
        w.bytes(&self.ram);

        let mut f = File::create(path)?;
        f.write_all(&w.buf)?;
        Ok(())
    }

    pub fn load(path: &str) -> io::Result<Snapshot> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        let mut r = R::new(&bytes);

        let magic = r.u32();
        let version = r.u32();
        assert_eq!(magic, MAGIC, "bad snapshot magic");
        assert_eq!(version, VERSION, "unsupported snapshot version");

        let ram_base = r.u64();
        let ram_size = r.u64() as usize;
        let uart_tx = r.u64();

        let mut gpr = [0u64; 31];
        for g in gpr.iter_mut() {
            *g = r.u64();
        }
        let pc = r.u64();
        let cpsr = r.u64();

        let n = r.u32() as usize;
        let mut sysregs = Vec::with_capacity(n);
        for _ in 0..n {
            let id = r.u32() as u16;
            let val = r.u64();
            sysregs.push((id, val));
        }

        let ram = r.rest().to_vec();
        assert_eq!(ram.len(), ram_size, "snapshot RAM size mismatch");

        Ok(Snapshot {
            ram_base,
            vcpu: VcpuState {
                gpr,
                pc,
                cpsr,
                sysregs,
            },
            uart_tx,
            ram,
        })
    }
}
