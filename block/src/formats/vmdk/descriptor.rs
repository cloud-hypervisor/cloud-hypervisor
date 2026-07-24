// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Parser for the flat VMDK text descriptor.
//!
//! A flat VMDK stores its layout in a small text descriptor: a header, a list
//! of `FLAT` extent lines, and a disk database (DDB). Only the `monolithicFlat`
//! and `twoGbMaxExtentFlat` create types are recognized.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::str::Lines;

use crate::AlignedFile;

const VMDK_DESCRIPTOR_HEADER: &str = "# Disk DescriptorFile";
const VMDK_DESCRIPTOR_EXTENTS: &str = "# Extent description";
const VMDK_DESCRIPTOR_DDB: &str = "# The Disk Data Base";
const VMDK_DESCRIPTOR_DDB_2: &str = "#DDB";

/// Flat VMDK create types.
#[derive(Debug, Default)]
pub enum VMDKDiskType {
    #[default]
    CreateTypeUnsupported,
    MonolithicFlat,
    TwoGbMaxExtentFlat,
}

/// Flat VMDK extent line fields.
/// Format of each extent line:
/// `<access> <sectors> <type> "<file>" [offset]`.
#[derive(Debug, Default)]
pub struct VmdkExtentHeader {
    pub access: String,
    pub size_in_sectors: u64,
    pub extent_type: String,
    pub filename: String,
    pub offset_in_sectors: u64,
}

/// Descriptor header fields.
#[derive(Debug, Default)]
pub struct VmdkDescriptorHeader {
    pub create_type: VMDKDiskType,
}

/// Ordered list of extents.
#[derive(Debug, Default)]
pub struct VmdkDescriptorExtents {
    pub extents: Vec<VmdkExtentHeader>,
}

/// Parsed flat VMDK descriptor
///
/// extents_list: ordered extent list
/// base_path: descriptor file's parent directory
#[derive(Debug, Default)]
pub struct VmdkDescriptor {
    pub base_path: String,
    pub extents_list: VmdkDescriptorExtents,
}

impl VmdkDescriptor {
    pub fn new(file: &File, path: &Path) -> io::Result<Self> {
        // The descriptor's directory anchors the relative extent filenames.
        let base_path = path
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot retrieve parent directory of the file",
                )
            })?
            .to_string_lossy()
            .to_string();

        // A valid descriptor is at least a few bytes of text.
        if file.metadata()?.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid VMDK descriptor file: file is empty or too small",
            ));
        }

        let content = read_descriptor(file)?;
        let mut lines = content.lines();
        let (_header, last_line) = parse_header(&mut lines)?;
        let extents_list = parse_extents(&mut lines, last_line)?;

        Ok(Self {
            base_path,
            extents_list,
        })
    }
}

// Read the whole descriptor into memory through an `AlignedFile` and return it
// as a `String`.
fn read_descriptor(file: &File) -> io::Result<String> {
    let aligned = AlignedFile::new(file.try_clone()?, true);
    let len = file.metadata()?.len() as usize;
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < buf.len() {
        match aligned.read_at(&mut buf[filled..], filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    // A descriptor is ASCII text, so invalid UTF-8 means "not a descriptor".
    String::from_utf8(buf).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "VMDK descriptor is not valid UTF-8",
        )
    })
}

pub(crate) fn parse_header<'a>(
    lines: &mut Lines<'a>,
) -> io::Result<(VmdkDescriptorHeader, &'a str)> {
    let header_line = lines.next().unwrap_or_default();

    // Reject actual disk data (or an embedded descriptor, which is
    // unsupported): a flat descriptor must start with the header line.
    if header_line.trim_end() != VMDK_DESCRIPTOR_HEADER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Not a VMDK descriptor file: missing header: {header_line}"),
        ));
    }

    let mut header = VmdkDescriptorHeader::default();
    let mut last_comment_line = "";

    for line in lines.by_ref() {
        if line.starts_with('#') {
            // End of the header section.
            last_comment_line = line;
            break;
        }
        let parts: Vec<&str> = line.split('=').map(|s| s.trim()).collect();
        if parts.len() == 2 && parts[0] == "createType" {
            // Tools such as qemu-img quote the value, strip quotes for comparison.
            header.create_type = match parts[1].trim_matches('"') {
                "monolithicFlat" => VMDKDiskType::MonolithicFlat,
                "twoGbMaxExtentFlat" => VMDKDiskType::TwoGbMaxExtentFlat,
                _ => VMDKDiskType::CreateTypeUnsupported,
            };
        }
    }

    Ok((header, last_comment_line))
}

pub(crate) fn parse_extents(
    lines: &mut Lines<'_>,
    last_comment_line: &str,
) -> io::Result<VmdkDescriptorExtents> {
    let mut extents = VmdkDescriptorExtents::default();

    if last_comment_line != VMDK_DESCRIPTOR_EXTENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected the extents section comment line",
        ));
    }

    for line in lines.by_ref() {
        // Tools such as qemu-img separate sections with blank lines, skip them.
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if line == VMDK_DESCRIPTOR_DDB || line == VMDK_DESCRIPTOR_DDB_2 {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected the DDB section comment line",
            ));
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 4 || parts.len() == 5 {
            let size_in_sectors = parts[1].parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "VMDK extent size '{}' is not a valid sector count",
                        parts[1]
                    ),
                )
            })?;
            let offset_in_sectors = match parts.get(4) {
                Some(offset) => offset.parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("VMDK extent offset '{offset}' is not a valid sector count"),
                    )
                })?,
                None => 0,
            };
            extents.extents.push(VmdkExtentHeader {
                access: parts[0].to_string(),
                size_in_sectors,
                extent_type: parts[2].to_string(),
                filename: parts[3].trim_matches('"').to_string(),
                offset_in_sectors,
            });
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Malformed VMDK extent line",
            ));
        }
    }

    Ok(extents)
}

/// Returns true when `prefix` begins with the `# Disk DescriptorFile` header.
pub fn has_descriptor_header(prefix: &[u8]) -> bool {
    prefix.starts_with(VMDK_DESCRIPTOR_HEADER.as_bytes())
}

/// Returns true for a supported flat VMDK: create type `monolithicFlat` or
/// `twoGbMaxExtentFlat` with only `FLAT` extents.
pub fn is_flat_vmdk(f: &mut File) -> io::Result<bool> {
    let content = match read_descriptor(f) {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut lines = content.lines();

    let (header, last_line) = match parse_header(&mut lines) {
        Ok(parsed) => parsed,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(false),
        Err(e) => return Err(e),
    };

    match header.create_type {
        VMDKDiskType::MonolithicFlat | VMDKDiskType::TwoGbMaxExtentFlat => {}
        _ => return Ok(false),
    }

    let extents = match parse_extents(&mut lines, last_line) {
        Ok(extents) => extents,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(false),
        Err(e) => return Err(e),
    };

    for extent in &extents.extents {
        if extent.extent_type != "FLAT" {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_hdr(input: &str) -> io::Result<(VmdkDescriptorHeader, String)> {
        let mut lines = input.lines();
        let (header, last) = parse_header(&mut lines)?;
        Ok((header, last.to_string()))
    }

    fn parse_body(last_comment: &str, body: &str) -> io::Result<VmdkDescriptorExtents> {
        let mut lines = body.lines();
        parse_extents(&mut lines, last_comment)
    }

    // Two-stage parse, as `VmdkDescriptor::new` chains it.
    fn parse_full(input: &str) -> io::Result<(VmdkDescriptorHeader, VmdkDescriptorExtents)> {
        let mut lines = input.lines();
        let (header, last) = parse_header(&mut lines)?;
        let extents = parse_extents(&mut lines, last)?;
        Ok((header, extents))
    }

    #[test]
    fn new_is_unaffected_by_shared_file_offset() {
        use std::io::{Read, Seek, SeekFrom, Write};

        use vmm_sys_util::tempfile::TempFile;

        // A minimal but complete monolithicFlat descriptor.
        let descriptor_text = "# Disk DescriptorFile\n\
                               version=1\n\
                               createType=monolithicFlat\n\
                               # Extent description\n\
                               RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                               # The Disk Data Base\n\
                               ddb.adapterType = \"ide\"\n";

        let tmp = TempFile::new().unwrap();
        let mut file: &File = tmp.as_file();
        file.write_all(descriptor_text.as_bytes()).unwrap();

        // Advance the shared OS file offset off zero, mimicking an earlier
        // image-type probe. `&File` is `Copy`, so this moves the same fd's
        // offset that `VmdkDescriptor::new` will see.
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut scratch = [0u8; 8];
        file.read_exact(&mut scratch).unwrap();
        assert_ne!(file.stream_position().unwrap(), 0);

        // `read_descriptor` reads positionally (anchored at offset 0), so the
        // advanced offset must not affect the parse.
        let descriptor = VmdkDescriptor::new(file, tmp.as_path()).unwrap();
        assert_eq!(descriptor.extents_list.extents.len(), 1);
        assert_eq!(
            descriptor.extents_list.extents[0].filename,
            "disk-flat.vmdk"
        );
    }

    #[test]
    fn single_flat_extent_with_ddb() {
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                          # The Disk Data Base\n\
                          ddb.adapterType = \"ide\"\n\
                          ddb.geometry.sectors = \"63\"\n";

        let extents = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 1);
        let e = &extents.extents[0];
        assert_eq!(e.access, "RW");
        assert_eq!(e.size_in_sectors, 2_097_152);
        assert_eq!(e.extent_type, "FLAT");
        assert_eq!(e.filename, "disk-flat.vmdk");
    }

    #[test]
    fn multiple_extents_two_gb_max() {
        let body: &str = "RW 4192256 FLAT \"disk-s001.vmdk\"\n\
                          RW 4192256 FLAT \"disk-s002.vmdk\"\n\
                          RW 2097152 FLAT \"disk-s003.vmdk\"\n\
                          # The Disk Data Base\n\
                          ddb.adapterType = \"lsilogic\"\n";

        let extents = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 3);
        assert_eq!(extents.extents[0].filename, "disk-s001.vmdk");
        assert_eq!(extents.extents[2].filename, "disk-s003.vmdk");
        assert!(extents.extents.iter().all(|e| e.extent_type == "FLAT"));
    }

    #[test]
    fn extent_line_with_optional_offset_field() {
        // 5-field form: <access> <sectors> <type> <file> <offset>
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\" 0\n";

        let extents = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].filename, "disk-flat.vmdk");
    }

    #[test]
    fn extent_access_modes_are_preserved() {
        let body: &str = "RDONLY 2097152 FLAT \"ro.vmdk\"\n\
                          NOACCESS 1048576 FLAT \"noaccess.vmdk\"\n";

        let extents = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 2);
        assert_eq!(extents.extents[0].access, "RDONLY");
        assert_eq!(extents.extents[1].access, "NOACCESS");
    }

    #[test]
    fn rejects_wrong_leading_comment() {
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\"\n";
        // Must be told we are at "# Extent description"; anything else errors.
        parse_body("# The Disk Data Base", body).unwrap_err();
    }

    #[test]
    fn rejects_malformed_extent_line() {
        // Only three fields -> malformed.
        let body: &str = "RW 2097152 FLAT\n";
        parse_body("# Extent description", body).unwrap_err();
    }

    #[test]
    fn rejects_non_numeric_extent_size() {
        // A non-numeric sector count must be rejected, not coerced to 0.
        let body: &str = "RW notanumber FLAT \"disk-flat.vmdk\"\n";
        parse_body("# Extent description", body).unwrap_err();
    }

    #[test]
    fn rejects_non_numeric_extent_offset() {
        // A non-numeric trailing offset must be rejected too.
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\" xyz\n";
        parse_body("# Extent description", body).unwrap_err();
    }

    #[test]
    fn rejects_unexpected_comment_in_body() {
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                          # Some other comment\n";
        parse_body("# Extent description", body).unwrap_err();
    }

    #[test]
    fn skips_blank_line_inside_extent_section() {
        // qemu-img emits a blank line between the last extent and the
        // "# The Disk Data Base" marker, it must be skipped, not rejected.
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                          \n\
                          # The Disk Data Base\n";
        let extents = parse_body("# Extent description", body).unwrap();
        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].filename, "disk-flat.vmdk");
    }

    #[test]
    fn rejects_missing_descriptor_header() {
        let input: &str = "NOT_A_DESCRIPTOR\nversion=1\n";
        parse_hdr(input).unwrap_err();
    }

    #[test]
    fn parses_header_fields() {
        let input: &str = "# Disk DescriptorFile\n\
                           version=1\n\
                           CID=fffffffe\n\
                           parentCID=ffffffff\n\
                           createType=monolithicFlat\n\
                           # Extent description\n";

        let (header, last) = parse_hdr(input).unwrap();

        assert!(matches!(header.create_type, VMDKDiskType::MonolithicFlat));
        assert_eq!(last, "# Extent description");
    }

    #[test]
    fn parses_quoted_create_type() {
        // qemu-img quotes the createType value; the parser must strip quotes.
        let input: &str = "# Disk DescriptorFile\n\
                           version=1\n\
                           createType=\"twoGbMaxExtentFlat\"\n\
                           # Extent description\n";

        let (header, _last) = parse_hdr(input).unwrap();
        assert!(matches!(
            header.create_type,
            VMDKDiskType::TwoGbMaxExtentFlat
        ));
    }

    #[test]
    fn full_monolithic_flat_descriptor() {
        let input: &str = "# Disk DescriptorFile\n\
                           version=1\n\
                           createType=monolithicFlat\n\
                           # Extent description\n\
                           RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                           # The Disk Data Base\n\
                           ddb.adapterType = \"ide\"\n";

        let (header, extents) = parse_full(input).unwrap();

        assert!(matches!(header.create_type, VMDKDiskType::MonolithicFlat));
        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].access, "RW");
    }

    #[test]
    fn full_two_gb_max_extent_flat_descriptor() {
        let input: &str = "# Disk DescriptorFile\n\
                           version=1\n\
                           createType=twoGbMaxExtentFlat\n\
                           # Extent description\n\
                           RW 4192256 FLAT \"disk-s001.vmdk\"\n\
                           RW 4192256 FLAT \"disk-s002.vmdk\"\n\
                           # The Disk Data Base\n";

        let (header, extents) = parse_full(input).unwrap();

        assert!(matches!(
            header.create_type,
            VMDKDiskType::TwoGbMaxExtentFlat
        ));
        assert_eq!(extents.extents.len(), 2);
    }

    #[test]
    fn full_qemu_style_descriptor() {
        // Mirrors a real qemu-img monolithicFlat descriptor: quoted createType,
        // blank lines between sections, 5-field extent line with a trailing
        // offset, and the "#DDB" marker form.
        let input: &str = "# Disk DescriptorFile\n\
                           version=1\n\
                           CID=eb2295a4\n\
                           parentCID=ffffffff\n\
                           createType=\"monolithicFlat\"\n\
                           \n\
                           # Extent description\n\
                           RW 6291456 FLAT \"t-flat.vmdk\" 0\n\
                           \n\
                           # The Disk Data Base\n\
                           #DDB\n\
                           \n\
                           ddb.virtualHWVersion = \"4\"\n\
                           ddb.adapterType = \"ide\"\n";

        let (header, extents) = parse_full(input).unwrap();

        assert!(matches!(header.create_type, VMDKDiskType::MonolithicFlat));
        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].access, "RW");
        assert_eq!(extents.extents[0].size_in_sectors, 6_291_456);
        assert_eq!(extents.extents[0].extent_type, "FLAT");
        assert_eq!(extents.extents[0].filename, "t-flat.vmdk");
    }
}
