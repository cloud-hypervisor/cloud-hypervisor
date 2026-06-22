//! Build script: assemble the bare-metal arm64 guest with the host clang and
//! extract its flat `.text` blob (no objcopy/lld needed — we parse the ELF).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Minimal ELF64 reader: return the bytes of the named section.
fn elf_section<'a>(elf: &'a [u8], want: &str) -> Option<&'a [u8]> {
    assert_eq!(&elf[0..4], b"\x7fELF", "not an ELF file");
    let e_shoff = rd_u64(elf, 0x28) as usize;
    let e_shentsize = rd_u16(elf, 0x3a) as usize;
    let e_shnum = rd_u16(elf, 0x3c) as usize;
    let e_shstrndx = rd_u16(elf, 0x3e) as usize;

    let strtab_hdr = e_shoff + e_shstrndx * e_shentsize;
    let strtab_off = rd_u64(elf, strtab_hdr + 0x18) as usize;

    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        let name_idx = rd_u32(elf, sh) as usize;
        // Read the NUL-terminated section name from the section-header strtab.
        let mut end = strtab_off + name_idx;
        while elf[end] != 0 {
            end += 1;
        }
        let name = std::str::from_utf8(&elf[strtab_off + name_idx..end]).unwrap_or("");
        if name == want {
            let off = rd_u64(elf, sh + 0x18) as usize;
            let size = rd_u64(elf, sh + 0x20) as usize;
            return Some(&elf[off..off + size]);
        }
    }
    None
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let guest_src = manifest.join("guest.s");
    let obj = out.join("guest.o");
    let bin = out.join("guest.bin");

    println!("cargo:rerun-if-changed={}", guest_src.display());
    println!("cargo:rerun-if-changed=build.rs");

    let status = Command::new("xcrun")
        .args([
            "clang",
            "--target=aarch64-none-elf",
            "-c",
            guest_src.to_str().unwrap(),
            "-o",
            obj.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run xcrun clang — is the Xcode command line toolchain installed?");
    assert!(status.success(), "guest assembly failed");

    let elf = fs::read(&obj).expect("read guest.o");
    let text = elf_section(&elf, ".text").expect("no .text section in guest.o");
    fs::write(&bin, text).expect("write guest.bin");
    println!("cargo:warning=guest blob: {} bytes", text.len());
}
