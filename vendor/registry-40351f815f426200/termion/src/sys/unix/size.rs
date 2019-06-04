use std::{io, mem};

use super::cvt;
use super::libc::{c_ushort, ioctl, STDOUT_FILENO, TIOCGWINSZ};

#[repr(C)]
struct TermSize {
    row: c_ushort,
    col: c_ushort,
    _x: c_ushort,
    _y: c_ushort,
}
/// Get the size of the terminal.
pub fn terminal_size() -> io::Result<(u16, u16)> {
    unsafe {
        let mut size: TermSize = mem::zeroed();
        cvt(ioctl(STDOUT_FILENO, TIOCGWINSZ.into(), &mut size as *mut _))?;
        Ok((size.col as u16, size.row as u16))
    }
}
