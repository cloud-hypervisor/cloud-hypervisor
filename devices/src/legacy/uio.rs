// ???
// 
//

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::sync::{Arc, Barrier};
use std::{io, result};
use std::path::{Path, PathBuf};
//use std::string::*;
use vm_device::interrupt::InterruptSourceGroup;
use vm_device::BusDevice;

#[derive(Debug)]
pub enum Error {
    Unknown,
}
pub type Result<T> = result::Result<T, Error>;

pub struct UioDeviceInfo {
    pub name: String,
    pub dev_path: PathBuf,
    pub dev_num: u32,
    pub is_ram: bool,
    pub interrupts: Vec<u32>,
    pub mappings: Vec<(u64, u64, u64)>, // start, size, offset
}

fn open_and_parse_hex(path: String) -> u64 {
    let mut file = File::open(path).unwrap();
    let mut num = String::new();
    file.read_to_string(&mut num).unwrap();
    let just_num = num.trim().trim_start_matches("0x");
    u64::from_str_radix(just_num, 16).unwrap()
}

pub fn get_uio_devices_info() -> Result<Vec<UioDeviceInfo>>{
    let mut ret = vec![];
    let mut dev_num: u32 = 0;
    info!("UIO devices:");
    'uio_devices: loop {
        let dev_path = format!("/dev/uio{}", dev_num);
        /* use OpenOptions to ensure device is readable and writeable */
        match OpenOptions::new().read(true).write(true).open(&dev_path) {
            Ok(_) => (), /* but we don't actually need the file here */
            Err(error) => match error.kind() {
                std::io::ErrorKind::NotFound => break 'uio_devices,
                _ => continue 'uio_devices,
            },
        };
        /* The device exists, now populate it */
        let mut dev_info = UioDeviceInfo{
            name: String::new(),
            dev_path: PathBuf::from(dev_path),
            dev_num,
            is_ram: false,
            interrupts: vec![],
            mappings: vec![],
        };
        let sys_path = format!("/sys/class/uio/uio{}", dev_num);
        dev_info.name = std::fs::read_to_string(format!("{}/name", sys_path)).unwrap();
        dev_info.name.truncate(dev_info.name.trim_end().len());
        info!(" {}", dev_info.name);
        if dev_info.name.eq("ram") {
            dev_info.is_ram = true;
        }
        info!("  is_ram: {:?}", dev_info.is_ram);

        info!("  mappings:");
        let mut map_num = 0;
        loop {
            let map_path = format!("{}/maps/map{}", sys_path, map_num);
            if !Path::new(&map_path).exists() {
                break;
            }
            let addr = open_and_parse_hex(format!("{}/addr", map_path));
            let size = open_and_parse_hex(format!("{}/size", map_path));
            let offset = open_and_parse_hex(format!("{}/offset", map_path));
            info!("   ({:#x}, {:#x}, {:#x})", addr, size, offset);
            dev_info.mappings.push((addr,size,offset));

            map_num += 1;
        }

        /*
         * Interrupts are packed into this file as bytes,
         * Each interrupt is 3 32 bit numbers (assumes #interrupt_cells == 3)
         */
        info!("  interrupts:");
        let interrupts_path = format!("{}/device/of_node/interrupts", sys_path);
        if Path::new(&interrupts_path).exists() {
            let bytes: Vec<u8> = std::fs::read(&interrupts_path).unwrap();
            if bytes.len() % (4*3) == 0 {
                let num_interrupts: usize = bytes.len() / (4*3);
                for n in 0..num_interrupts {
                    /* we only care about the middle number of the 3; that's the interrupt */
                    let i = (n * 3 + 1) * 4;
                    let slice = [
                        bytes[i + 0],
                        bytes[i + 1],
                        bytes[i + 2],
                        bytes[i + 3]];
                        let interrupt: u32 = u32::from_be_bytes(slice);
                        info!("   {:#x}", interrupt);
                        dev_info.interrupts.push(interrupt);
                }
            } else {
                info!("   invalid number of bytes {} in {}", bytes.len(), interrupts_path);
            }
        }
        ret.push(dev_info);
        dev_num += 1;
    }
    return Ok(ret);
}

pub struct Uio {
}

impl Uio {
    pub fn new() -> Self {
        Self { }
    }
}

impl BusDevice for Uio {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
    }
    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}
