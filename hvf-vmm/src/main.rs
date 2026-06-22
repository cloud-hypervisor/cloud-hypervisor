//! hvf-vmm: an arm64 VMM engine on Apple Hypervisor.framework.
//!
//! Demonstrates the portable core of Phases 2-4 of the Cloud Hypervisor ->
//! macOS port: a real HVF backend run-loop, an MMIO serial console, and full
//! snapshot save + rehydration into a freshly-created VM.
//!
//! Subcommands:
//!   demo [path]      cold boot -> snapshot at checkpoint -> rehydrate in a new
//!                    VM -> resume (all in one process). Default path /tmp/hvf-snap.bin
//!   boot <path>      cold boot; write snapshot at the guest checkpoint, then exit
//!   restore <path>   create a fresh VM and resume from a snapshot

mod eventfd;
mod hvf;
mod snapshot;
mod uart;

use hvf::*;
use snapshot::Snapshot;
use uart::Uart;

const RAM_BASE: u64 = 0x4000_0000;
const RAM_SIZE: usize = 0x10_0000; // 1 MiB

/// Flat guest blob produced by build.rs from guest.s.
static GUEST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guest.bin"));

macro_rules! hostlog {
    ($($a:tt)*) => {{ eprintln!("\x1b[36m[hvf]\x1b[0m {}", format!($($a)*)); }};
}

#[derive(Debug, PartialEq)]
enum Stop {
    Checkpoint,
    Poweroff,
}

struct Machine {
    // Field order matters: vCPU must be destroyed before the VM, and the VM
    // before the RAM mapping is torn down.
    vcpu: Vcpu,
    // Held to keep the VM (and its guest-memory mapping) alive; dropped after
    // the vCPU via field ordering.
    #[allow(dead_code)]
    vm: Vm,
    ram: GuestRam,
    uart: Uart,
}

impl Machine {
    fn new() -> Result<Machine, Box<dyn std::error::Error>> {
        let ram = GuestRam::new(RAM_BASE, RAM_SIZE)?;
        let vm = Vm::create()?;
        vm.map_ram(&ram, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)?;
        let vcpu = Vcpu::create()?;
        Ok(Machine {
            vcpu,
            vm,
            ram,
            uart: Uart::new(),
        })
    }

    /// Load the cold-boot guest image and set the initial vCPU state.
    fn load_cold(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.ram.as_mut_slice()[..GUEST.len()].copy_from_slice(GUEST);
        // EL1h, DAIF masked.
        self.vcpu.set_reg(HV_REG_CPSR, 0x3c5)?;
        self.vcpu.set_reg(HV_REG_PC, RAM_BASE)?;
        Ok(())
    }

    /// Rehydrate guest RAM + device + vCPU state from a snapshot.
    fn load_snapshot(&mut self, snap: &Snapshot) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(snap.ram_base, RAM_BASE, "snapshot RAM base mismatch");
        self.ram.as_mut_slice()[..snap.ram.len()].copy_from_slice(&snap.ram);
        self.uart.tx_count = snap.uart_tx;
        self.vcpu.restore_state(&snap.vcpu)?;
        Ok(())
    }

    fn capture(&self) -> Result<Snapshot, Box<dyn std::error::Error>> {
        Ok(Snapshot {
            ram_base: RAM_BASE,
            vcpu: self.vcpu.capture_state()?,
            uart_tx: self.uart.tx_count,
            ram: self.ram.as_slice().to_vec(),
        })
    }

    /// Run the vCPU until it requests a checkpoint or power-off.
    fn run(&mut self) -> Result<Stop, Box<dyn std::error::Error>> {
        loop {
            // Copy the exit fields out so the borrow of `self.vcpu` ends before
            // we call other vCPU methods below.
            let (reason, esr, pa, far) = {
                let exit = self.vcpu.run()?;
                (
                    exit.reason,
                    exit.exception.syndrome,
                    exit.exception.physical_address,
                    exit.exception.virtual_address,
                )
            };
            match reason {
                HV_EXIT_REASON_EXCEPTION => {
                    let ec = (esr >> 26) & 0x3f;
                    match ec {
                        // Data Abort (lower / same EL): an MMIO access.
                        0x24 | 0x25 => {
                            self.handle_mmio(esr, pa)?;
                            let pc = self.vcpu.get_reg(HV_REG_PC)?;
                            self.vcpu.set_reg(HV_REG_PC, pc + 4)?; // skip the faulting insn
                        }
                        // HVC from AArch64: our hypercall ABI (x0 selects action).
                        0x16 => {
                            let x0 = self.vcpu.get_gpr(0)?;
                            match x0 {
                                1 => return Ok(Stop::Checkpoint),
                                0 => return Ok(Stop::Poweroff),
                                other => hostlog!("ignoring unknown hypercall x0={other}"),
                            }
                        }
                        _ => {
                            return Err(format!(
                                "unhandled guest exception EC={ec:#04x} ESR={esr:#018x} \
                                 FAR={far:#x} IPA={pa:#x} PC={:#x}",
                                self.vcpu.get_reg(HV_REG_PC)?
                            )
                            .into());
                        }
                    }
                }
                HV_EXIT_REASON_CANCELED => { /* async cancel: just re-enter */ }
                HV_EXIT_REASON_VTIMER_ACTIVATED => { /* no GIC wired in this demo */ }
                other => return Err(format!("unexpected exit reason {other}").into()),
            }
        }
    }

    /// Decode an MMIO data abort from the ESR ISS and dispatch to a device.
    fn handle_mmio(&mut self, esr: u64, pa: u64) -> Result<(), Box<dyn std::error::Error>> {
        let isv = (esr >> 24) & 1;
        let sas = (esr >> 22) & 3; // 0=B,1=H,2=W,3=D
        let srt = ((esr >> 16) & 0x1f) as u32;
        let wnr = (esr >> 6) & 1;

        if !Uart::contains(pa) {
            return Err(format!("MMIO to unhandled device @ {pa:#x}").into());
        }
        let offset = pa - uart::UART_BASE;

        if wnr == 1 {
            // Store. Our guest uses the W-register convention; if ISV is clear we
            // default to x0 (matches guest.s `strb w0, [x20]`).
            let reg = if isv == 1 { srt } else { 0 };
            let val = if reg == 31 { 0 } else { self.vcpu.get_gpr(reg)? };
            self.uart.write(offset, val);
        } else {
            // Load: return the device value into the destination register.
            let v = self.uart.read(offset);
            if isv == 1 && srt != 31 {
                let mask = match sas {
                    0 => 0xff,
                    1 => 0xffff,
                    2 => 0xffff_ffff,
                    _ => u64::MAX,
                };
                self.vcpu.set_reg(srt, v & mask)?;
            }
        }
        Ok(())
    }
}

fn boot_phase(snap_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    hostlog!("cold boot: creating VM, mapping {} KiB RAM @ {:#x}", RAM_SIZE / 1024, RAM_BASE);
    let mut m = Machine::new()?;
    m.load_cold()?;
    hostlog!("running guest (serial console below)\n");
    match m.run()? {
        Stop::Checkpoint => {
            let snap = m.capture()?;
            let pc = snap.vcpu.pc;
            let counter = snap.vcpu.gpr[19];
            snap.save(snap_path)?;
            hostlog!(
                "\n>>> CHECKPOINT: guest paused at PC={pc:#x}, counter(x19)={counter}, \
                 uart_tx={} bytes",
                snap.uart_tx
            );
            hostlog!(">>> snapshot written to {snap_path}");
        }
        Stop::Poweroff => hostlog!("guest powered off before checkpoint"),
    }
    Ok(())
}

fn restore_phase(snap_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let snap = Snapshot::load(snap_path)?;
    hostlog!(
        "rehydrating from {snap_path}: PC={:#x}, counter(x19)={}, uart_tx={}",
        snap.vcpu.pc,
        snap.vcpu.gpr[19],
        snap.uart_tx
    );
    let mut m = Machine::new()?;
    m.load_snapshot(&snap)?;
    hostlog!("resuming guest (serial console below)\n");
    match m.run()? {
        Stop::Poweroff => hostlog!("\n>>> guest powered off cleanly after rehydration"),
        Stop::Checkpoint => hostlog!("guest requested another checkpoint"),
    }
    Ok(())
}

fn demo(snap_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    hostlog!("=== PHASE A: cold boot until checkpoint ===");
    {
        let mut m = Machine::new()?;
        m.load_cold()?;
        hostlog!("running guest (serial console below)\n");
        let stop = m.run()?;
        assert_eq!(stop, Stop::Checkpoint, "expected a checkpoint");
        let snap = m.capture()?;
        hostlog!(
            "\n>>> CHECKPOINT: counter(x19)={}, PC={:#x}, uart_tx={} bytes",
            snap.vcpu.gpr[19],
            snap.vcpu.pc,
            snap.uart_tx
        );
        snap.save(snap_path)?;
        hostlog!(">>> snapshot ({} bytes RAM) written to {snap_path}", snap.ram.len());
        // m drops here: vCPU destroyed, VM destroyed, RAM unmapped.
    }
    hostlog!("=== the entire VM has been torn down (hv_vm_destroy) ===");

    hostlog!("=== PHASE B: rehydrate into a BRAND-NEW VM ===");
    {
        let snap = Snapshot::load(snap_path)?;
        let mut m = Machine::new()?;
        m.load_snapshot(&snap)?;
        hostlog!("resuming guest from restored state (serial console below)\n");
        let stop = m.run()?;
        assert_eq!(stop, Stop::Poweroff, "expected power-off");
        hostlog!("\n>>> guest powered off cleanly. Rehydration proven. 🎉");
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("demo");
    let default_path = "/tmp/hvf-snap.bin".to_string();
    let path = args.get(2).unwrap_or(&default_path);

    let res = match cmd {
        "demo" => demo(path),
        "boot" => boot_phase(path),
        "restore" => restore_phase(path),
        _ => {
            eprintln!("usage: hvf-vmm [demo|boot|restore] [snapshot-path]");
            std::process::exit(2);
        }
    };

    if let Err(e) = res {
        hostlog!("ERROR: {e}");
        std::process::exit(1);
    }
}
