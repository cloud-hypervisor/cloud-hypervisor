// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 Demi Marie Obenour <demiobenour@gmail.com>

use super::{IoUring, SubmissionQueue, Submitter};
pub(super) struct DestructorClear<'a>(&'a mut Option<IoUring>);
/// A struct that drops the contained [`IoUring`] instance
/// on [`Drop`].  It crashes the program if the destructor
/// for the [`IoUring`] panics.  It can be disarmed by
/// setting the contained `&mut Option<IoUring>` to a
/// reference to a `None`.
impl<'a> Drop for DestructorClear<'a> {
    fn drop(&mut self) {
        struct ConvertPanicToAbort;
        impl Drop for ConvertPanicToAbort {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    // double panic always aborts
                    panic!("Cannot handle panic while closing io_uring instance")
                }
            }
        }
        if self.0.is_some() {
            // Ensure that any panic in this destructor becomes a double panic.
            let _convert_panic_into_abort = ConvertPanicToAbort;
            // Cancel all outstanding requests to prevent
            // use-after-scope of iovecs.
            // TODO: this isn't safe in the presence
            // of concurrent forks, but Cloud Hypervisor doesn't fork
            // while this code is running.
            *self.0 = None;
        }
    }
}

impl<'a> DestructorClear<'a> {
    pub(super) fn new(io_uring: &'a mut Option<IoUring>) -> Self {
        Self(io_uring)
    }

    pub(super) fn split_ring(&mut self) -> std::io::Result<(Submitter<'_>, SubmissionQueue<'_>)> {
        let Some(io_uring) = self.0.as_mut() else {
            return Err(std::io::Error::other("io_uring instance already deleted"));
        };
        let (submitter, sq, _) = io_uring.split();
        Ok((submitter, sq))
    }

    pub(super) fn disarm(&mut self) {
        *self.0 = None;
    }
}
