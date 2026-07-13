// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! Parser for the flat VMDK text descriptor.
//!
//! A flat VMDK stores its layout in a small text descriptor: a header, a list
//! of `FLAT` extent lines, and a disk database (DDB). Only the `monolithicFlat`
//! and `twoGbMaxExtentFlat` create types are recognized.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
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
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct VmdkExtentHeader {
    pub access: String,
    pub size_in_sectors: u64,
    pub extent_type: String,
    pub filename: String,
    pub offset_in_sectors: u64,
}

/// Descriptor header fields.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct VmdkDescriptorHeader {
    pub version: u32,
    pub cid: u32,
    pub parent_cid: u32,
    pub create_type: VMDKDiskType,
    pub parent_filename_hint: String,
}

/// Ordered list of extents.
#[derive(Debug, Default)]
pub struct VmdkDescriptorExtents {
    pub extents: Vec<VmdkExtentHeader>,
}
/// Disk database.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct VmdkDescriptorDdb {
    pub entries: HashMap<String, String>,
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
        if parts.len() == 2 {
            match parts[0] {
                "version" => header.version = parts[1].parse().unwrap_or(0),
                "CID" => header.cid = u32::from_str_radix(parts[1], 16).unwrap_or(0),
                "parentCID" => header.parent_cid = u32::from_str_radix(parts[1], 16).unwrap_or(0),
                "createType" => {
                    // Tools such as qemu-img quote the value, e.g.
                    // createType="monolithicFlat"; strip the quotes.
                    header.create_type = match parts[1].trim_matches('"') {
                        "monolithicFlat" => VMDKDiskType::MonolithicFlat,
                        "twoGbMaxExtentFlat" => VMDKDiskType::TwoGbMaxExtentFlat,
                        _ => VMDKDiskType::CreateTypeUnsupported,
                    }
                }
                "parentFileNameHint" => header.parent_filename_hint = parts[1].to_string(),
                _ => {}
            }
        }
    }

    Ok((header, last_comment_line))
}

pub(crate) fn parse_extents_and_ddb(
    lines: &mut Lines<'_>,
    last_comment_line: &str,
) -> io::Result<(VmdkDescriptorExtents, VmdkDescriptorDdb)> {
    let mut extents = VmdkDescriptorExtents::default();
    let mut ddb = VmdkDescriptorDdb::default();

    if last_comment_line != VMDK_DESCRIPTOR_EXTENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected the extents section comment line",
        ));
    }

    let mut in_extents_section = true;
    for line in lines.by_ref() {
        // Tools such as qemu-img separate sections with blank lines; skip them.
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if line == VMDK_DESCRIPTOR_DDB || line == VMDK_DESCRIPTOR_DDB_2 {
                in_extents_section = false;
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected the DDB section comment line",
            ));
        }
        if in_extents_section {
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
                let extent = VmdkExtentHeader {
                    access: parts[0].to_string(),
                    size_in_sectors,
                    extent_type: parts[2].to_string(),
                    filename: parts[3].trim_matches('"').to_string(),
                    offset_in_sectors,
                };
                extents.extents.push(extent);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Malformed VMDK extent line",
                ));
            }
        } else {
            let parts: Vec<&str> = line.split('=').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                ddb.entries
                    .insert(parts[0].to_string(), parts[1].to_string());
            }
        }
    }

    Ok((extents, ddb))
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

    let extents = match parse_extents_and_ddb(&mut lines, last_line) {
        Ok((extents, _ddb)) => extents,
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

    fn parse_body(
        last_comment: &str,
        body: &str,
    ) -> io::Result<(VmdkDescriptorExtents, VmdkDescriptorDdb)> {
        let mut lines = body.lines();
        parse_extents_and_ddb(&mut lines, last_comment)
    }

    // Two-stage parse, as `VmdkDescriptor::new` chains it.
    fn parse_full(
        input: &str,
    ) -> io::Result<(
        VmdkDescriptorHeader,
        VmdkDescriptorExtents,
        VmdkDescriptorDdb,
    )> {
        let mut lines = input.lines();
        let (header, last) = parse_header(&mut lines)?;
        let (extents, ddb) = parse_extents_and_ddb(&mut lines, last)?;
        Ok((header, extents, ddb))
    }

    #[test]
    fn single_flat_extent_with_ddb() {
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                          # The Disk Data Base\n\
                          ddb.adapterType = \"ide\"\n\
                          ddb.geometry.sectors = \"63\"\n";

        let (extents, ddb) = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 1);
        let e = &extents.extents[0];
        assert_eq!(e.access, "RW");
        assert_eq!(e.size_in_sectors, 2_097_152);
        assert_eq!(e.extent_type, "FLAT");
        assert_eq!(e.filename, "disk-flat.vmdk");

        assert_eq!(
            ddb.entries.get("ddb.adapterType").map(String::as_str),
            Some("\"ide\"")
        );
        assert_eq!(
            ddb.entries.get("ddb.geometry.sectors").map(String::as_str),
            Some("\"63\"")
        );
    }

    #[test]
    fn multiple_extents_two_gb_max() {
        let body: &str = "RW 4192256 FLAT \"disk-s001.vmdk\"\n\
                          RW 4192256 FLAT \"disk-s002.vmdk\"\n\
                          RW 2097152 FLAT \"disk-s003.vmdk\"\n\
                          # The Disk Data Base\n\
                          ddb.adapterType = \"lsilogic\"\n";

        let (extents, _ddb) = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 3);
        assert_eq!(extents.extents[0].filename, "disk-s001.vmdk");
        assert_eq!(extents.extents[2].filename, "disk-s003.vmdk");
        assert!(extents.extents.iter().all(|e| e.extent_type == "FLAT"));
    }

    #[test]
    fn extent_line_with_optional_offset_field() {
        // 5-field form: <access> <sectors> <type> <file> <offset>
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\" 0\n";

        let (extents, _ddb) = parse_body("# Extent description", body).unwrap();

        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].filename, "disk-flat.vmdk");
    }

    #[test]
    fn extent_access_modes_are_preserved() {
        let body: &str = "RDONLY 2097152 FLAT \"ro.vmdk\"\n\
                          NOACCESS 1048576 FLAT \"noaccess.vmdk\"\n";

        let (extents, _ddb) = parse_body("# Extent description", body).unwrap();

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
        // "# The Disk Data Base" marker; it must be skipped, not rejected.
        let body: &str = "RW 2097152 FLAT \"disk-flat.vmdk\"\n\
                          \n\
                          # The Disk Data Base\n";
        let (extents, _ddb) = parse_body("# Extent description", body).unwrap();
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

        assert_eq!(header.version, 1);
        assert_eq!(header.cid, 0xffff_fffe);
        assert_eq!(header.parent_cid, 0xffff_ffff);
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

        let (header, extents, ddb) = parse_full(input).unwrap();

        assert!(matches!(header.create_type, VMDKDiskType::MonolithicFlat));
        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].access, "RW");
        assert_eq!(
            ddb.entries.get("ddb.adapterType").map(String::as_str),
            Some("\"ide\"")
        );
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

        let (header, extents, _ddb) = parse_full(input).unwrap();

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

        let (header, extents, ddb) = parse_full(input).unwrap();

        assert!(matches!(header.create_type, VMDKDiskType::MonolithicFlat));
        assert_eq!(extents.extents.len(), 1);
        assert_eq!(extents.extents[0].access, "RW");
        assert_eq!(extents.extents[0].size_in_sectors, 6_291_456);
        assert_eq!(extents.extents[0].extent_type, "FLAT");
        assert_eq!(extents.extents[0].filename, "t-flat.vmdk");
        assert_eq!(
            ddb.entries.get("ddb.adapterType").map(String::as_str),
            Some("\"ide\"")
        );
    }
}
