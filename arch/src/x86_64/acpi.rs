// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use acpi_tables::{rsdp::RSDP, sdt::SDT};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use vm_memory::{Address, ByteValued, Bytes};

pub fn create_acpi_tables(guest_mem: &GuestMemoryMmap) -> GuestAddress {
    // RSDP is at the EBDA
    let rsdp_offset = super::EBDA_START;
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let mut dsdt = SDT::new(*b"DSDT", 36, 6, *b"CLOUDH", *b"CHDSDT  ", 1);
    dsdt.update_checksum();
    let dsdt_offset = rsdp_offset.checked_add(RSDP::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = SDT::new(*b"FACP", 276, 6, *b"CLOUDH", *b"CHFACP  ", 1);

    let fadt_flags: u32 = 1 << 20; // HW_REDUCED_ACPI
    facp.write(112, fadt_flags);

    // TODO: RESET_REG/RESET_VALUE @ offset 116/128

    facp.write(131, 3u8); // FADT minor version
    facp.write(140, dsdt_offset.0); // X_DSDT

    // TODO: SLEEP_CONTROL_REG/SLEEP_STATUS_REG @ offset 244/256

    facp.write(268, b"CLOUDHYP"); // Hypervisor Vendor Identity

    facp.update_checksum();
    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_slice(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

    // XSDT
    let mut xsdt = SDT::new(
        *b"XSDT",
        36 + 8 * tables.len() as u32,
        1,
        *b"CLOUDH",
        *b"CHXSDT  ",
        1,
    );
    xsdt.write(36, tables[0]);
    xsdt.update_checksum();

    let xsdt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = RSDP::new(*b"CLOUDH", xsdt_offset.0);
    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
