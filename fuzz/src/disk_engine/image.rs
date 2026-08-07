// Copyright © 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Backing storage for fuzzed disk images.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Creates an empty anonymous file.
fn memfd(name: &str) -> io::Result<File> {
    let name = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: FFI call with a valid NUL terminated name and no flags.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: memfd_create returned a fresh descriptor owned by nobody else.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

/// Materializes `bytes` as an anonymous file.
///
/// A memfd keeps the image in tmpfs so a fuzz iteration never touches the
/// filesystem, and the descriptor is closed when the returned `File` drops.
///
/// The whole buffer is written. `bytes` here is fuzzer input, which is dense,
/// and looking for the zero pages in it would cost as much as writing them:
/// measured on a loaded 96 way host, scanning 8 MiB took 6.1 ms and writing
/// it took 5.9 ms. Only a *fixed* image can skip the scan, which is what
/// [`template_memfd`] does.
pub fn image_memfd(name: &str, bytes: &[u8]) -> io::Result<File> {
    let mut file = memfd(name)?;
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Page granularity at which a template's zero regions are skipped.
///
/// One page is the smallest unit tmpfs allocates, so a page of zeroes that is
/// never written costs neither memory nor a copy.
const SPARSE_PAGE: usize = 4096;

/// Returns the indices of the pages of `bytes` that are not entirely zero,
/// computing them once per template buffer.
///
/// A template is the same buffer on every iteration, so its layout is a
/// constant and finding it again each time is pure overhead - and it is the
/// dominant overhead. Measured for the VHDX template, 8 MiB of file holding
/// 333 non-zero bytes: scanning it took 6.1 ms of a 7.7 ms iteration and
/// capped the target at 17 executions a second. Writing it densely instead
/// costs the same 5.9 ms, so skipping the zero pages only pays once the scan
/// is not repeated. Cached, materialization is a `set_len` and six page
/// writes, about 5 us.
///
/// The cache is keyed by the identity of the buffer - its address and its
/// length - and not by the format name. A format has as many templates as
/// [`crate::disk_engine::format::DiskFormat::template_variant`] hands out,
/// and qcow2 has two of different sizes, so a name is not the name of one
/// buffer: keying by it returned the first materialized variant's page map
/// for the other one, and indexing a 1 MiB image's map into the 2560 byte
/// file of the small cluster image panicked. Length alone is no better,
/// because two variants may coincidentally match.
///
/// A template lives in a `OnceLock` static for the life of the process,
/// which is what `&'static [u8]` here demands: an address that is never
/// freed and so never reused, and two distinct live slices cannot share
/// both an address and a length. Empty slices may share the dangling
/// address every allocator hands out for a zero sized read, but their page
/// map is empty either way.
fn template_pages(bytes: &'static [u8]) -> Arc<Vec<usize>> {
    /// Cached page maps, one per template buffer, keyed by address and
    /// length.
    type PageMaps = HashMap<(usize, usize), Arc<Vec<usize>>>;

    static CACHE: Mutex<Option<PageMaps>> = Mutex::new(None);

    let key = (bytes.as_ptr() as usize, bytes.len());
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(PageMaps::new);
    Arc::clone(cache.entry(key).or_insert_with(|| {
        Arc::new(
            bytes
                .chunks(SPARSE_PAGE)
                .enumerate()
                .filter(|(_, page)| page.iter().any(|byte| *byte != 0))
                .map(|(index, _)| index)
                .collect(),
        )
    }))
}

/// Writes the pages of `bytes` named by `pages` into an emptied `file`.
///
/// The file is first sized to the whole length, so the pages that are skipped
/// stay holes and read back as zeroes. `file` must be empty or freshly
/// truncated.
fn write_template(file: &File, bytes: &[u8], pages: &[usize]) -> io::Result<()> {
    file.set_len(bytes.len() as u64)?;
    for index in pages {
        let start = index * SPARSE_PAGE;
        let end = (start + SPARSE_PAGE).min(bytes.len());
        file.write_all_at(&bytes[start..end], start as u64)?;
    }
    Ok(())
}

/// Materializes a fixed template image as an anonymous file.
///
/// Unlike [`image_memfd`] this writes only the pages that carry data, using
/// the page map cached by [`template_pages`].
pub fn template_memfd(name: &str, bytes: &'static [u8]) -> io::Result<File> {
    let pages = template_pages(bytes);
    let mut file = memfd(name)?;
    write_template(&file, bytes, &pages)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Returns the per process scratch directory for path backed images.
///
/// Formats that resolve sibling files relative to the image need a real
/// directory. One is created per process and reused, so an iteration only
/// rewrites the image itself.
pub fn scratch_dir(name: &str) -> io::Result<&'static Path> {
    static DIR: OnceLock<PathBuf> = OnceLock::new();

    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ch-fuzz-{name}-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    });
    Ok(dir.as_path())
}

/// Opens the scratch image for `name`, emptied.
fn scratch_image(name: &str) -> io::Result<(File, PathBuf)> {
    let path = scratch_dir(name)?.join(format!("image.{name}"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    Ok((file, path))
}

/// Materializes `bytes` as a real file inside the scratch directory.
///
/// The path is stable across iterations so that a format resolving siblings
/// relative to it sees the same directory every time.
pub fn image_file(name: &str, bytes: &[u8]) -> io::Result<(File, PathBuf)> {
    let (mut file, path) = scratch_image(name)?;
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, path))
}

/// Materializes a fixed template image inside the scratch directory.
///
/// The path backed counterpart of [`template_memfd`].
pub fn template_file(name: &str, bytes: &'static [u8]) -> io::Result<(File, PathBuf)> {
    let pages = template_pages(bytes);
    let (mut file, path) = scratch_image(name)?;
    // `truncate(true)` freed every block, so the skipped pages read as zeroes.
    write_template(&file, bytes, &pages)?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, path))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    // A sparsely written template has to be byte identical to the buffer it
    // was built from: the framework, and the shadow model in particular,
    // assumes the engine sees exactly the bytes the harness handed it.
    #[test]
    fn template_materialization_reproduces_the_buffer() {
        let mut bytes = vec![0u8; 3 * SPARSE_PAGE + 17];
        bytes[0] = 0xff;
        bytes[SPARSE_PAGE - 1] = 0x01;
        // The second page stays all zero, so it is never written.
        bytes[2 * SPARSE_PAGE + 5] = 0xaa;
        bytes[3 * SPARSE_PAGE + 16] = 0x5a;
        // A template is `'static` in the harness because it lives in a
        // `OnceLock`; leaking gives the test the same lifetime.
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());

        // Twice, because the second round runs off the cached page map.
        for round in 0..2 {
            let mut file = template_memfd("sparse-test", bytes).expect("memfd");
            let mut read_back = Vec::new();
            file.read_to_end(&mut read_back).expect("read back");
            assert_eq!(read_back, bytes, "round {round}");
        }
        assert_eq!(*template_pages(bytes), vec![0, 2, 3]);

        // An empty buffer and a wholly zero buffer are degenerate cases of
        // the same loop, and each needs its own cache key.
        for len in [0usize, 1, SPARSE_PAGE, SPARSE_PAGE + 1] {
            let zeroes: &'static [u8] = Box::leak(vec![0u8; len].into_boxed_slice());
            let mut file = template_memfd("zero-test", zeroes).expect("memfd");
            let mut read_back = Vec::new();
            file.read_to_end(&mut read_back).expect("read back");
            assert_eq!(read_back, zeroes, "{len} zero bytes");
        }
    }

    // Two templates of the same format, materialized in one process, must
    // each get their own page map.
    //
    // The cache used to be keyed by format name, on the assumption that a
    // format had one template. `DiskFormat::template_variant` broke that:
    // qcow2 has a 1 MiB default image and a 4 MiB small cluster one whose
    // file is only a couple of kilobytes. Whichever was materialized first
    // owned the entry, and applying its page map to the other panicked with
    // an out of range slice index the moment a fuzz target replayed a
    // corpus that reached both. The shapes here are the same: a long buffer
    // whose pages are spread out, and a short one that a page index of the
    // long map runs past.
    #[test]
    fn two_templates_of_one_format_do_not_share_a_page_map() {
        let mut large = vec![0u8; 32 * SPARSE_PAGE];
        large[0] = 0x1;
        large[31 * SPARSE_PAGE] = 0x2;
        let large: &'static [u8] = Box::leak(large.into_boxed_slice());

        let mut small = vec![0u8; 2560];
        small[7] = 0x3;
        let small: &'static [u8] = Box::leak(small.into_boxed_slice());

        // Both orders, and twice each, so that neither the first nor the
        // cached path can be the one that is right by accident.
        for round in 0..2 {
            for (which, bytes) in [("large", large), ("small", small)] {
                let mut file = template_memfd("variant-test", bytes).expect("memfd");
                let mut read_back = Vec::new();
                file.read_to_end(&mut read_back).expect("read back");
                assert_eq!(read_back.len(), bytes.len(), "{which}, round {round}");
                assert_eq!(read_back, bytes, "{which}, round {round}");
            }
        }

        // And the maps themselves are the two different maps, not one -
        // and each is still cached, which is the whole point of keying
        // them at all: a second call hands back the same allocation
        // rather than scanning the buffer again.
        assert_eq!(*template_pages(large), vec![0, 31]);
        assert_eq!(*template_pages(small), vec![0]);
        assert!(Arc::ptr_eq(&template_pages(large), &template_pages(large)));
        assert!(Arc::ptr_eq(&template_pages(small), &template_pages(small)));
        assert!(!Arc::ptr_eq(&template_pages(large), &template_pages(small)));
    }

    // A path backed template is rewritten in place every iteration, so a
    // shorter image must not leave the tail of a longer one behind.
    #[test]
    fn a_rewritten_scratch_image_keeps_no_tail() {
        let long = vec![0xa5u8; 2 * SPARSE_PAGE];
        let (_file, path) = image_file("sparse-file-test", &long).expect("scratch image");
        assert_eq!(
            fs::metadata(&path).expect("metadata").len(),
            long.len() as u64
        );

        let short = vec![0u8; 8];
        let (_file, path) = image_file("sparse-file-test", &short).expect("scratch image");
        assert_eq!(fs::read(&path).expect("read back"), short);
    }
}
