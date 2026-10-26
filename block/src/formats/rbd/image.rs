// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! librados/librbd handle management for a single RBD image.
//!
//! All virtqueue workers share one [`RbdImageHandle`]. The handle keeps an
//! in-flight counter so that the underlying librbd image is only closed
//! after every asynchronous completion has fired; closing an image with
//! outstanding AIO would be a use-after-free inside librbd. Completion
//! callbacks only hold the counter (never the image handle), which
//! guarantees the close never happens on a librbd callback thread.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use std::{io, mem, ptr};

use log::{debug, error, info};

use super::sys::*;
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::factory::RbdOpenOptions;
use crate::formats::rbd_uri::RbdUri;

/// Maximum time to wait for in-flight I/O while closing an image.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Tracks asynchronous operations submitted against one image handle.
pub(crate) struct InFlight {
    count: AtomicUsize,
    mutex: Mutex<()>,
    condvar: Condvar,
}

impl InFlight {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            mutex: Mutex::new(()),
            condvar: Condvar::new(),
        }
    }

    /// Registers one operation before it is submitted to librbd.
    pub(crate) fn increment(&self) {
        self.count.fetch_add(1, Ordering::AcqRel);
    }

    /// Marks one operation as completed.
    pub(crate) fn decrement(&self) {
        let previous = self.count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "RBD in-flight counter underflow");
        if previous == 1 {
            // Take the mutex before notifying to avoid a lost wakeup in
            // `wait_for_idle()`.
            let _guard = self.mutex.lock().unwrap();
            self.condvar.notify_all();
        }
    }

    /// Waits until all submitted operations have completed.
    ///
    /// Returns `false` if `timeout` elapses first.
    fn wait_for_idle(&self, timeout: Duration) -> bool {
        let mut guard = self.mutex.lock().unwrap();
        let deadline = Instant::now() + timeout;

        while self.count.load(Ordering::Acquire) != 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, _) = self.condvar.wait_timeout(guard, deadline - now).unwrap();
            guard = next;
        }

        true
    }
}

/// Owns a librados cluster handle.
struct RadosCluster {
    ptr: rados_t,
}

impl Drop for RadosCluster {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by rados_create() and is not used
        // after this point; rados_shutdown() releases the cluster handle.
        unsafe { rados_shutdown(self.ptr) };
    }
}

/// Owns a librados I/O context.
struct RadosIoctx {
    ptr: rados_ioctx_t,
}

impl Drop for RadosIoctx {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by rados_ioctx_create() and is not
        // used after this point.
        unsafe { rados_ioctx_destroy(self.ptr) };
    }
}

/// Owns an open librbd image.
struct OpenedImage {
    ptr: rbd_image_t,
}

impl Drop for OpenedImage {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by rbd_open()/rbd_open_read_only()
        // and all in-flight I/O has completed before this drop runs.
        unsafe { rbd_close(self.ptr) };
    }
}

/// A shared librbd image handle and its connection state.
pub(crate) struct RbdImageHandle {
    image: Option<OpenedImage>,
    ioctx: Option<RadosIoctx>,
    cluster: Option<RadosCluster>,
    in_flight: Arc<InFlight>,
}

// SAFETY: The librados/librbd client handles are designed to be used from
// multiple threads and internally synchronize their state. All calls into
// the C API go through this handle, and the underlying image is only closed
// after the in-flight counter reaches zero.
unsafe impl Send for RbdImageHandle {}
// SAFETY: See the `Send` implementation above.
unsafe impl Sync for RbdImageHandle {}

fn cstring(value: &str, what: &str) -> BlockResult<CString> {
    CString::new(value).map_err(|_| {
        BlockError::new(
            BlockErrorKind::InvalidFormat,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("RBD {what} must not contain NUL bytes"),
            ),
        )
    })
}

impl RbdImageHandle {
    /// Connects to the cluster and opens the image (or snapshot).
    pub(crate) fn open(
        uri: &RbdUri,
        readonly: bool,
        options: RbdOpenOptions<'_>,
    ) -> BlockResult<Arc<Self>> {
        if uri.snapshot.is_some() && !readonly {
            return Err(BlockError::new(
                BlockErrorKind::InvalidFormat,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "RBD snapshots require readonly=on",
                ),
            ));
        }

        let pool = cstring(&uri.pool, "pool")?;
        let name = cstring(&uri.image, "image")?;
        let snapshot = uri
            .snapshot
            .as_deref()
            .map(|snapshot| cstring(snapshot, "snapshot"))
            .transpose()?;
        let user = options.user.map(|user| cstring(user, "user")).transpose()?;
        let namespace = options
            .namespace
            .map(|namespace| cstring(namespace, "namespace"))
            .transpose()?;
        let conf = options
            .conf
            .map(|path| CString::new(path.as_os_str().as_bytes()))
            .transpose()
            .map_err(|_| {
                BlockError::new(
                    BlockErrorKind::InvalidFormat,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "RBD configuration path must not contain NUL bytes",
                    ),
                )
            })?;

        let mut cluster_ptr: rados_t = ptr::null_mut();
        // SAFETY: `cluster_ptr` is a valid out-pointer and `user` is either
        // NULL or a NUL-terminated string.
        let ret = unsafe {
            rados_create(
                &mut cluster_ptr,
                user.as_ref().map_or(ptr::null(), |user| user.as_ptr()),
            )
        };
        block_check(ret, "rados_create")?;
        let cluster = RadosCluster { ptr: cluster_ptr };

        // SAFETY: `cluster.ptr` is a valid handle and `conf` is either NULL
        // or a NUL-terminated path.
        let ret = unsafe {
            rados_conf_read_file(
                cluster.ptr,
                conf.as_ref().map_or(ptr::null(), |conf| conf.as_ptr()),
            )
        };
        // With no explicit configuration file librados searches the default
        // locations; a missing file there is not fatal.
        if conf.is_some() {
            block_check(ret, "rados_conf_read_file")?;
        } else if ret < 0 {
            debug!(
                "librados could not read a default configuration file: {}",
                errno_error(ret, "rados_conf_read_file")
            );
        }

        // SAFETY: `cluster.ptr` is a valid, connected-less cluster handle.
        block_check(unsafe { rados_connect(cluster.ptr) }, "rados_connect")?;

        let mut ioctx_ptr: rados_ioctx_t = ptr::null_mut();
        // SAFETY: `cluster.ptr` is connected and `pool` is a NUL-terminated
        // pool name; `ioctx_ptr` is a valid out-pointer.
        let ret = unsafe { rados_ioctx_create(cluster.ptr, pool.as_ptr(), &mut ioctx_ptr) };
        block_check(ret, "rados_ioctx_create")?;
        let ioctx = RadosIoctx { ptr: ioctx_ptr };

        if let Some(namespace) = namespace.as_ref() {
            // SAFETY: `ioctx.ptr` is a valid I/O context and `namespace` is
            // a NUL-terminated string.
            unsafe { rados_ioctx_set_namespace(ioctx.ptr, namespace.as_ptr()) };
        }

        let mut image_ptr: rbd_image_t = ptr::null_mut();
        let snap_name = snapshot
            .as_ref()
            .map_or(ptr::null(), |snapshot| snapshot.as_ptr());
        // SAFETY: `ioctx.ptr` and `name` are valid; `image_ptr` is a valid
        // out-pointer; `snap_name` is NULL or a NUL-terminated snapshot name.
        let ret = unsafe {
            if readonly {
                rbd_open_read_only(ioctx.ptr, name.as_ptr(), &mut image_ptr, snap_name)
            } else {
                rbd_open(ioctx.ptr, name.as_ptr(), &mut image_ptr, ptr::null())
            }
        };
        block_check(ret, "rbd_open")?;
        let image = OpenedImage { ptr: image_ptr };

        // Warm up librbd's worker threads while we are still on the VMM
        // thread, which has a broader seccomp filter than the virtqueue
        // workers. Read-only images have nothing to flush.
        if !readonly {
            // SAFETY: `image.ptr` is a valid open image handle.
            let ret = unsafe { rbd_flush(image.ptr) };
            block_check(ret, "rbd_flush")?;
        }

        let mut size = 0u64;
        // SAFETY: `image.ptr` is valid and `size` is a valid out-pointer.
        let ret = unsafe { rbd_get_size(image.ptr, &mut size) };
        block_check(ret, "rbd_get_size")?;

        info!(
            "Opened RBD image {}/{} (snapshot: {:?}, readonly: {readonly}, size: {size} bytes)",
            uri.pool, uri.image, uri.snapshot
        );

        Ok(Arc::new(Self {
            image: Some(image),
            ioctx: Some(ioctx),
            cluster: Some(cluster),
            in_flight: Arc::new(InFlight::new()),
        }))
    }

    /// Returns the raw librbd image handle used for I/O submission.
    pub(crate) fn raw_image(&self) -> rbd_image_t {
        self.image
            .as_ref()
            .expect("RBD image stays open until RbdImageHandle is dropped")
            .ptr
    }

    /// Returns the in-flight operation tracker used by completion callbacks.
    pub(crate) fn in_flight(&self) -> Arc<InFlight> {
        Arc::clone(&self.in_flight)
    }

    /// Returns the logical image size in bytes.
    pub(crate) fn size(&self) -> BlockResult<u64> {
        let mut size = 0u64;
        // SAFETY: `self.raw_image()` is a valid handle and `size` is a valid
        // out-pointer.
        let ret = unsafe { rbd_get_size(self.raw_image(), &mut size) };
        block_check(ret, "rbd_get_size")?;
        Ok(size)
    }

    /// Flushes librbd's caches to the OSDs.
    pub(crate) fn flush(&self) -> BlockResult<()> {
        // SAFETY: `self.raw_image()` is a valid open image handle.
        block_check(unsafe { rbd_flush(self.raw_image()) }, "rbd_flush")
    }

    /// Resizes the image to `size` bytes.
    pub(crate) fn resize(&self, size: u64) -> BlockResult<()> {
        // SAFETY: `self.raw_image()` is a valid open image handle.
        block_check(unsafe { rbd_resize(self.raw_image(), size) }, "rbd_resize")
    }
}

impl Drop for RbdImageHandle {
    fn drop(&mut self) {
        if !self.in_flight.wait_for_idle(CLOSE_TIMEOUT) {
            error!(
                "Timed out waiting for in-flight RBD I/O; leaking image handles to avoid \
                 closing librbd state from under a completion"
            );
            if let Some(image) = self.image.take() {
                mem::forget(image);
            }
            if let Some(ioctx) = self.ioctx.take() {
                mem::forget(ioctx);
            }
            if let Some(cluster) = self.cluster.take() {
                mem::forget(cluster);
            }
            return;
        }

        // Drop the guards in dependency order: image, ioctx, cluster.
        drop(self.image.take());
        drop(self.ioctx.take());
        drop(self.cluster.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_waits_until_drained() {
        let in_flight = InFlight::new();
        in_flight.increment();
        in_flight.increment();

        assert!(!in_flight.wait_for_idle(Duration::from_millis(1)));

        in_flight.decrement();
        assert!(!in_flight.wait_for_idle(Duration::from_millis(1)));

        in_flight.decrement();
        assert!(in_flight.wait_for_idle(Duration::from_millis(100)));
    }
}
