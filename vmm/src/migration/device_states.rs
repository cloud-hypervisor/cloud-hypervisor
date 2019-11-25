use std::result;
use std::collections::VecDeque;
use std::io::{self};

use serde::{Serialize, Deserialize};
use vmm_sys_util::eventfd::EventFd;

use devices::Interrupt;

struct EmpInterrupt {
    event_fd: EventFd,
}

impl Interrupt for EmpInterrupt {
    fn deliver(&self) -> result::Result<(), std::io::Error> {
        self.event_fd.write(1)
    }
}

impl EmpInterrupt {
    fn new(event_fd: EventFd) -> Self {
        EmpInterrupt { event_fd }
    }
}

pub fn empty_irq() -> Box<dyn Interrupt> {
    Box::new(EmpInterrupt::new(EventFd::new(0).unwrap()))
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "devices::legacy::Serial")]
pub struct SerialState {
    pub interrupt_enable: u8,
    pub interrupt_identification: u8,
    #[serde(skip, default="empty_irq")]
    pub interrupt: Box<dyn Interrupt>,
    pub line_control: u8,
    pub line_status: u8,
    pub modem_control: u8,
    pub modem_status: u8,
    pub scratch: u8,
    pub baud_divisor: u16,
    pub in_buffer: VecDeque<u8>,
    #[serde(skip)]
    pub out: Option<Box<dyn io::Write + Send>>,
}

#[derive(Serialize, Deserialize)]
pub struct WrapSerialStates {
    #[serde(with = "SerialState")]
    pub serial: devices::legacy::Serial,
}

pub fn serde_serial(serial: &devices::legacy::Serial) -> String {
    let serial_state = devices::legacy::Serial {
        interrupt_enable: serial.interrupt_enable,
        interrupt_identification: serial.interrupt_identification,
        interrupt: empty_irq(),
        line_control: serial.line_control,
        line_status: serial.line_status,
        modem_control: serial.modem_control,
        modem_status: serial.modem_status,
        scratch: serial.scratch,
        baud_divisor: serial.baud_divisor,
        in_buffer: serial.in_buffer.clone(),
        out: None,
    };
    let serial_wrap = WrapSerialStates { serial: serial_state };
    serde_json::to_string(&serial_wrap).unwrap()
}
