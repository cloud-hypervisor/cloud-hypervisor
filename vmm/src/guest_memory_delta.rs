// Copyright © 2026 Contributors to the Cloud Hypervisor project
//
// SPDX-License-Identifier: Apache-2.0
//

//! Header of a memory delta file: the guest ranges a snapshot carries on top
//! of its base memory file.

use std::io::{self, BufReader, Read};

use thiserror::Error;
use vm_migration::protocol::{MemoryRange, MemoryRangeTable};

const MAGIC: [u8; 8] = *b"CHDELTA1";
// Magic and entry count
const PREFIX_LEN: u64 = 16;
// Guest address and length of one entry
const ENTRY_LEN: u64 = 16;

#[derive(Debug, Error)]
pub enum DeltaError {
    #[error("Error reading the memory delta header")]
    Read(#[source] io::Error),
    #[error("Not a memory delta file")]
    BadMagic,
    #[error("Delta entry table of {0} entries does not fit in the file")]
    TableTooLarge(u64),
    #[error("Empty delta entry at {0:#x}")]
    EmptyEntry(u64),
    #[error("Delta entry {gpa:#x}+{length:#x} is outside the memory layout")]
    OutsideLayout { gpa: u64, length: u64 },
    #[error("Delta data size does not match its entry table")]
    SizeMismatch,
}

fn read_u64(reader: &mut impl Read) -> Result<u64, DeltaError> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).map_err(DeltaError::Read)?;
    Ok(u64::from_le_bytes(buf))
}

/// Header of a memory delta file. It lists the guest ranges whose contents
/// follow it in the file, in the same order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GuestMemoryDeltaHeader {
    entries: Vec<MemoryRange>,
}

impl GuestMemoryDeltaHeader {
    pub(crate) fn new(entries: Vec<MemoryRange>) -> Self {
        Self { entries }
    }

    /// Reads and checks the header of a memory delta file that is `file_len`
    /// bytes long. Every entry must lie inside `layout`.
    pub(crate) fn read(
        reader: &mut impl Read,
        file_len: u64,
        layout: &MemoryRangeTable,
    ) -> Result<Self, DeltaError> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic).map_err(DeltaError::Read)?;
        if magic != MAGIC {
            return Err(DeltaError::BadMagic);
        }
        let count = read_u64(reader)?;

        let header_len = count
            .checked_mul(ENTRY_LEN)
            .and_then(|n| n.checked_add(PREFIX_LEN))
            .filter(|&n| n <= file_len)
            .ok_or(DeltaError::TableTooLarge(count))?;

        // Buffer the table reads, without reading past the table
        let mut table = BufReader::new(reader.by_ref().take(header_len - PREFIX_LEN));
        let mut entries = Vec::new();
        let mut data_len: u64 = 0;
        for _ in 0..count {
            let gpa = read_u64(&mut table)?;
            let length = read_u64(&mut table)?;
            if length == 0 {
                return Err(DeltaError::EmptyEntry(gpa));
            }
            let inside = gpa.checked_add(length).is_some_and(|end| {
                layout
                    .ranges()
                    .iter()
                    .any(|r| gpa >= r.gpa && end <= r.gpa + r.length)
            });
            if !inside {
                return Err(DeltaError::OutsideLayout { gpa, length });
            }
            data_len = data_len
                .checked_add(length)
                .ok_or(DeltaError::SizeMismatch)?;
            entries.push(MemoryRange { gpa, length });
        }

        if header_len.checked_add(data_len) != Some(file_len) {
            return Err(DeltaError::SizeMismatch);
        }

        Ok(Self { entries })
    }

    /// Returns the guest ranges that the file carries.
    pub(crate) fn entries(&self) -> &[MemoryRange] {
        &self.entries
    }

    /// Returns the header as the file stores it: the magic, the entry count
    /// and one (gpa, length) pair per entry, all little-endian.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(PREFIX_LEN as usize + ENTRY_LEN as usize * self.entries.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());

        for entry in &self.entries {
            out.extend_from_slice(&entry.gpa.to_le_bytes());
            out.extend_from_slice(&entry.length.to_le_bytes());
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_header(entries: &[MemoryRange]) -> Vec<u8> {
        GuestMemoryDeltaHeader::new(entries.to_vec()).to_bytes()
    }

    fn read_header(
        reader: &mut impl Read,
        file_len: u64,
        layout: &MemoryRangeTable,
    ) -> Result<Vec<MemoryRange>, DeltaError> {
        GuestMemoryDeltaHeader::read(reader, file_len, layout).map(|h| h.entries().to_vec())
    }

    // Two 1 MiB ranges with a 1 MiB gap between them
    fn layout() -> MemoryRangeTable {
        let mut layout = MemoryRangeTable::default();
        layout.push(MemoryRange {
            gpa: 0,
            length: 0x100000,
        });
        layout.push(MemoryRange {
            gpa: 0x200000,
            length: 0x100000,
        });
        layout
    }

    #[test]
    fn header_round_trip() {
        let entries = vec![
            MemoryRange {
                gpa: 0,
                length: 4096,
            },
            MemoryRange {
                gpa: 0x10000,
                length: 8192,
            },
        ];
        let mut layout = MemoryRangeTable::default();
        layout.push(MemoryRange {
            gpa: 0,
            length: 0x100000,
        });

        let header = encode_header(&entries);
        let file_len = header.len() as u64 + 4096 + 8192;
        let decoded = read_header(&mut header.as_slice(), file_len, &layout).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn header_stops_at_data() {
        let entries = vec![MemoryRange {
            gpa: 0,
            length: 4096,
        }];
        let mut file = encode_header(&entries);
        file.extend_from_slice(&[0xab; 4096]);
        let mut reader = file.as_slice();
        read_header(&mut reader, file.len() as u64, &layout()).unwrap();
        assert_eq!(reader, &[0xab; 4096][..]);
    }

    #[test]
    fn header_layout() {
        let header = encode_header(&[MemoryRange {
            gpa: 0x1000,
            length: 0x2000,
        }]);
        assert_eq!(header.len(), 32);
        assert_eq!(&header[0..8], b"CHDELTA1");
        assert_eq!(&header[8..16], &1u64.to_le_bytes()); // count = 1
        assert_eq!(&header[16..24], &0x1000u64.to_le_bytes());
        assert_eq!(&header[24..32], &0x2000u64.to_le_bytes());
    }

    #[test]
    fn bad_magic() {
        let mut header = encode_header(&[]);
        header[0] = b'X';
        let mut layout = MemoryRangeTable::default();
        layout.push(MemoryRange {
            gpa: 0,
            length: 0x100000,
        });
        assert!(matches!(
            read_header(&mut header.as_slice(), 16, &layout),
            Err(DeltaError::BadMagic)
        ));
    }

    #[test]
    fn short_header() {
        let header = encode_header(&[]);
        let short = &header[..10];
        let layout = MemoryRangeTable::default();
        assert!(matches!(
            read_header(&mut &short[..], 10, &layout),
            Err(DeltaError::Read(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn empty_header() {
        let header = encode_header(&[]);
        let entries = read_header(&mut header.as_slice(), PREFIX_LEN, &layout()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn table_too_large() {
        let mut header = encode_header(&[]);
        header[8..16].copy_from_slice(&5u64.to_le_bytes());
        assert!(matches!(
            read_header(&mut header.as_slice(), PREFIX_LEN, &layout()),
            Err(DeltaError::TableTooLarge(5))
        ));
    }

    #[test]
    fn table_size_overflow() {
        let mut header = encode_header(&[]);
        header[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            read_header(&mut header.as_slice(), PREFIX_LEN, &layout()),
            Err(DeltaError::TableTooLarge(u64::MAX))
        ));
    }

    #[test]
    fn empty_entry() {
        let header = encode_header(&[MemoryRange {
            gpa: 0x1000,
            length: 0,
        }]);
        assert!(matches!(
            read_header(&mut header.as_slice(), header.len() as u64, &layout()),
            Err(DeltaError::EmptyEntry(0x1000))
        ));
    }

    #[test]
    fn entry_outside_layout() {
        let header = encode_header(&[MemoryRange {
            gpa: 0x150000,
            length: 0x1000,
        }]);
        let file_len = header.len() as u64 + 0x1000;
        assert!(matches!(
            read_header(&mut header.as_slice(), file_len, &layout()),
            Err(DeltaError::OutsideLayout {
                gpa: 0x150000,
                length: 0x1000
            })
        ));
    }

    #[test]
    fn entry_straddles_ranges() {
        let header = encode_header(&[MemoryRange {
            gpa: 0xff000,
            length: 0x2000,
        }]);
        let file_len = header.len() as u64 + 0x2000;
        assert!(matches!(
            read_header(&mut header.as_slice(), file_len, &layout()),
            Err(DeltaError::OutsideLayout { .. })
        ));
    }

    #[test]
    fn entry_end_overflow() {
        let header = encode_header(&[MemoryRange {
            gpa: u64::MAX,
            length: 2,
        }]);
        let file_len = header.len() as u64 + 2;
        assert!(matches!(
            read_header(&mut header.as_slice(), file_len, &layout()),
            Err(DeltaError::OutsideLayout { .. })
        ));
    }

    #[test]
    fn data_size_mismatch() {
        let header = encode_header(&[MemoryRange {
            gpa: 0,
            length: 0x1000,
        }]);
        let file_len = header.len() as u64 + 0x1000;
        for len in [file_len - 1, file_len + 1] {
            assert!(matches!(
                read_header(&mut header.as_slice(), len, &layout()),
                Err(DeltaError::SizeMismatch)
            ));
        }
    }
}
