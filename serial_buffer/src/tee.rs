// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Write};

/// Writes to `out` and copies everything that `out` accepted to `copy`.
pub struct Tee<O, C> {
    out: O,
    copy: C,
}

impl<O: Write, C: Write> Tee<O, C> {
    pub fn new(out: O, copy: C) -> Self {
        Self { out, copy }
    }
}

impl<O: Write, C: Write> Write for Tee<O, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = self.out.write(buf)?;
        self.copy.write_all(&buf[..count])?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()?;
        self.copy.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::Tee;

    #[test]
    fn copies_only_what_out_accepted() {
        let mut out = [0u8; 6];
        let mut copy = Vec::new();
        let mut tee = Tee::new(out.as_mut_slice(), &mut copy);

        assert_eq!(tee.write(b"hello world").unwrap(), 6);
        assert_eq!(&out, b"hello ");
        assert_eq!(copy, b"hello ");
    }
}
