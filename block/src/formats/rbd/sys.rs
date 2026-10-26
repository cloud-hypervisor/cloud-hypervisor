// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Re-exports and helpers for the librbd and librados FFI crates.

use std::ffi::c_int;
use std::io;

pub(crate) use rados_sys::{
    rados_conf_read_file, rados_connect, rados_create, rados_ioctx_create, rados_ioctx_destroy,
    rados_ioctx_set_namespace, rados_ioctx_t, rados_shutdown, rados_t,
};
pub(crate) use rbd_sys::{
    RBD_WRITE_ZEROES_FLAG_THICK_PROVISION, iovec, rbd_aio_create_completion, rbd_aio_discard,
    rbd_aio_flush, rbd_aio_get_return_value, rbd_aio_readv, rbd_aio_release, rbd_aio_write_zeroes,
    rbd_aio_writev, rbd_close, rbd_completion_t, rbd_flush, rbd_get_size, rbd_image_t, rbd_open,
    rbd_open_read_only, rbd_resize,
};

use crate::error::{BlockError, BlockErrorKind};

/// Converts a negative Ceph return value into an `io::Error`.
///
/// Ceph returns `-errno` on failure; the `what` context is preserved in
/// the message because the block layer logs the source chain.
pub(crate) fn errno_error(ret: c_int, what: &str) -> io::Error {
    let err = io::Error::from_raw_os_error(-ret);
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

/// Checks a Ceph return value, returning an `io::Error` on failure.
pub(crate) fn check(ret: c_int, what: &str) -> io::Result<()> {
    if ret < 0 {
        Err(errno_error(ret, what))
    } else {
        Ok(())
    }
}

/// Checks a Ceph return value, returning a [`BlockError`] on failure.
pub(crate) fn block_check(ret: c_int, what: &str) -> Result<(), BlockError> {
    check(ret, what).map_err(|e| BlockError::new(BlockErrorKind::Io, e))
}
