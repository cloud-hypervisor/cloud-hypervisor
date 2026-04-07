// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

// General safety argument:
//
// - IoBuf guarantees that its iovec will stay valid until
//   it is dropped.
// - The IoBuf is stored in a HashMap, and is only removed if an
//   I/O with the same user data completes or no request was actually
//   queued.
// - If there was already an I/O with the same user data in the map,
//   insert_request() panics without inserting the old entry.
// - Therefore, when a user data value is reaped from the completion
//   queue, looking it up will return the request submitted with that value.
// - This means that the memory the iovec refers to will stay valid for at
//   least until the I/O completes, and that once the I/O does complete,
//   it is safe to free it.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::ErrorKind;
use std::mem::ManuallyDrop;
use std::os::fd::AsRawFd as _;

use log::warn;
use vmm_sys_util::eventfd::EventFd;

use super::Completion;
use crate::async_io::{AsyncIoError, AsyncIoResult, BorrowedDiskFd};
use crate::{BatchRequest, IoBuf};

pub struct Tracker<T: super::AsyncIoEngine> {
    engine: T,
    // TODO: this is a hack. It duplicates bookkeeping done by the
    // Request struct. However, there is no way to make the public
    // API of the block crate sound without this.
    //
    // This must use ManuallyDrop to ensure it is not dropped until all requests
    // are complete. If a request cannot be completed, the backing storage should
    // be leaked (deadlocking future modifications of guest memory), rather than
    // being freed while potentially still in use.
    requests: ManuallyDrop<HashMap<u64, Option<IoBuf>>>,
}

impl<T: super::AsyncIoEngine> std::fmt::Debug for Tracker<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: do better
        f.debug_struct("Tracker").finish()
    }
}

impl<T: super::AsyncIoEngine> Tracker<T> {
    pub fn new(engine: T) -> Self {
        Self {
            engine,
            requests: ManuallyDrop::new(Default::default()),
        }
    }
}

macro_rules! unsafe_no_buf_requests {
    ($(
        pub fn $name: ident(&mut self, err = $e: expr $(,$arg: ident: $t: ty)*) -> AsyncIoResult<()>;
    )*) => {
        $(
            pub fn $name(&mut self $(,$arg: $t)*, user_data: u64) -> AsyncIoResult<()> {
                insert_request(&mut self.requests, None, user_data).map_err($e)?;
                // SAFETY: user_data is guaranteed unique
                unsafe { self.engine.$name($($arg,)* user_data) }.map_err(
                    |(queued, e)| {
                        if !queued {
                            assert!(self.requests.remove(&user_data).expect("Added above").is_none())
                        }
                        e
                    },
                )
            }
        )*
    };
}

pub(super) fn insert_request(
    requests: &mut HashMap<u64, Option<IoBuf>>,
    request: Option<IoBuf>,
    user_data: u64,
) -> std::io::Result<&mut Option<IoBuf>> {
    match requests.entry(user_data) {
        Entry::Occupied(_) => Err(std::io::Error::from(ErrorKind::InvalidInput)),
        Entry::Vacant(vacant) => Ok(vacant.insert(request)),
    }
}

impl<T: super::AsyncIoEngine> Drop for Tracker<T> {
    fn drop(&mut self) {
        // TODO: cancel outbound requests
        while !self.requests.is_empty() {
            while self.next_completed_request().is_none() {
                let notifier = self.notifier();
                wait_eventfd(notifier);
            }
        }
        // SAFETY: we just emptied all requests, so we are not keeping
        // any more guest memory alive. Therefore, it is safe to drop the
        // map. This is `Drop`, so afterwards the requests will not be
        // exposed to safe code.
        unsafe { ManuallyDrop::drop(&mut self.requests) }
    }
}

pub(crate) fn wait_eventfd(notifier: &EventFd) {
    while let Err(e) = notifier.read() {
        match e.kind() {
            ErrorKind::Interrupted => {}
            ErrorKind::WouldBlock => {
                let mut p = [libc::pollfd {
                    fd: notifier.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                }];
                // SAFETY: FFI call, valid parameters
                if unsafe { libc::poll(p.as_mut_ptr(), 1, 1000) } == 0 {
                    warn!(
                        "Device is taking over 1 second to complete an I/O request during shutdown!"
                    );
                }
            }
            _ => panic!("reading from an eventfd should not fail"),
        }
    }
}

impl<T: super::AsyncIoEngine> Tracker<T> {
    pub fn notifier(&self) -> &EventFd {
        self.engine.notifier()
    }

    pub fn batch_requests_enabled(&self) -> bool {
        self.engine.batch_requests_enabled()
    }

    pub fn write_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        offset: libc::off_t,
        request: IoBuf,
        user_data: u64,
    ) -> Result<(), AsyncIoError> {
        let iovecs = insert_request(&mut self.requests, Some(request), user_data)
            .map_err(AsyncIoError::WriteVectored)?;

        // SAFETY: See top-level comment.
        unsafe {
            self.engine.write_vectored(
                fd,
                iovecs.as_mut().expect("inserted a Some").iovecs(),
                offset as _,
                user_data,
            )
        }
        .map_err(|(queued, e)| {
            if !queued {
                let _: Option<IoBuf> = self.requests.remove(&user_data).expect("Added above");
            }
            e
        })
    }

    pub fn read_vectored(
        &mut self,
        fd: BorrowedDiskFd,
        offset: libc::off_t,
        request: IoBuf,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let iovecs = insert_request(&mut self.requests, Some(request), user_data)
            .map_err(AsyncIoError::WriteVectored)?;

        // SAFETY: See top-level comment.
        unsafe {
            self.engine.read_vectored(
                fd,
                iovecs.as_mut().expect("inserted a Some").iovecs(),
                offset as _,
                user_data,
            )
        }
        .map_err(|(queued, e)| {
            if !queued {
                let _: Option<IoBuf> = self.requests.remove(&user_data).expect("Added above");
            }
            e
        })
    }

    pub fn submit_batch_requests(
        &mut self,
        fd: BorrowedDiskFd,
        batch_requests: Vec<BatchRequest>,
    ) -> Result<(), AsyncIoError> {
        let Tracker { engine, requests } = self;
        engine.submit_batch_requests(fd, batch_requests, requests)
    }

    pub fn next_completed_request(&mut self) -> Option<Completion> {
        let Tracker { engine, requests } = self;
        engine
            .next_completed_request()
            .map(|super::InnerCompletion { user_data, result }| {
                // Now that the request has completed, it is safe to return the reference to it.
                let buffer: Option<IoBuf> = requests
                    .remove(&user_data)
                    .expect("Did not push a request onto the submission queue");
                Completion {
                    user_data,
                    result,
                    iobuf: buffer,
                }
            })
    }
    unsafe_no_buf_requests! {
        pub fn punch_hole(&mut self, err = AsyncIoError::PunchHole, fd: BorrowedDiskFd, offset: u64, length: u64) -> AsyncIoResult<()>;
        pub fn write_zeroes(&mut self, err = AsyncIoError::WriteZeroes, fd: BorrowedDiskFd, offset: u64, length: u64) -> AsyncIoResult<()>;
        pub fn fsync(&mut self, err = AsyncIoError::Fsync, fd: BorrowedDiskFd) -> AsyncIoResult<()>;
    }
}
