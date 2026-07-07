// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult};
use crate::formats::vhdx::Vhdx;

pub(super) struct VhdxSync {
    vhdx_file: Arc<Mutex<Vhdx>>,
    eventfd: EventFd,
    completion_list: VecDeque<AsyncIoCompletion>,
    size: u64,
}

impl VhdxSync {
    pub(super) fn new(vhdx_file: Arc<Mutex<Vhdx>>, size: u64) -> Self {
        VhdxSync {
            vhdx_file,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for VhdxSync"),
            completion_list: VecDeque::new(),
            size,
        }
    }

    fn read_operation(&mut self, op: &mut AsyncIoOperation) -> AsyncIoResult<usize> {
        let offset = op.offset();
        let mut buf = vec![0u8; op.total_len()];
        let mut vhdx = self.vhdx_file.lock().unwrap();
        vhdx.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::ReadVectored)?;
        let result = vhdx.read(&mut buf).map_err(AsyncIoError::ReadVectored)?;
        drop(vhdx);

        op.write_bytes_at(0, &buf[..result])
            .map_err(AsyncIoError::ReadVectored)?;
        Ok(result)
    }

    fn write_operation(&mut self, op: &AsyncIoOperation) -> AsyncIoResult<usize> {
        let offset = op.offset();
        let mut buf = vec![0u8; op.total_len()];
        op.read_bytes_at(0, &mut buf)
            .map_err(AsyncIoError::WriteVectored)?;

        let mut vhdx = self.vhdx_file.lock().unwrap();
        vhdx.seek(SeekFrom::Start(offset as u64))
            .map_err(AsyncIoError::WriteVectored)?;
        let result = vhdx.write(&buf).map_err(AsyncIoError::WriteVectored)?;
        Ok(result)
    }
}

impl AsyncIo for VhdxSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        op.validate_bounds(self.size)?;
        let is_read = op.is_read();
        let mut op = op;
        let result = if is_read {
            self.read_operation(&mut op)?
        } else {
            self.write_operation(&op)?
        };

        self.completion_list
            .push_back(AsyncIoCompletion::from_operation(op, result as i32));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        self.vhdx_file
            .lock()
            .unwrap()
            .flush()
            .map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.completion_list
                .push_back(AsyncIoCompletion::new(user_data, 0, None));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completion_list.pop_front()
    }

    fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::PunchHole(io::Error::other(
            "punch_hole not supported for VHDX",
        )))
    }

    fn write_zeroes(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteZeroes(io::Error::other(
            "write_zeroes not supported for VHDX",
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Mutex};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::async_io::{AsyncIo, AsyncIoError, AsyncIoOperation, OwnedIoBuffer};
    use crate::formats::vhdx::Vhdx;
    use crate::formats::vhdx::test_util::create_dynamic_vhdx;

    fn make_vhdx_sync(tf: &TempFile) -> (VhdxSync, u64) {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tf.as_path())
            .unwrap();
        let vhdx = Vhdx::new(file, false).unwrap();
        let size = vhdx.virtual_disk_size();
        let sync = VhdxSync::new(Arc::new(Mutex::new(vhdx)), size);
        (sync, size)
    }

    /// Builds a `VhdxSync` from a fresh 1 MiB dynamic VHDX, or `None`
    /// if `qemu-img` is unavailable to generate one.
    fn setup() -> Option<(VhdxSync, u64)> {
        let tf = create_dynamic_vhdx(1)?;
        Some(make_vhdx_sync(&tf))
    }

    #[test]
    fn sync_rejects_read_straddling_logical_size() {
        let Some((mut sync, size)) = setup() else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        let op = AsyncIoOperation::read_to_vec(
            (size - 512) as i64,
            OwnedIoBuffer::from_vec(vec![0u8; 1024]),
            1,
        );
        assert!(matches!(
            sync.submit_data_operation(op),
            Err(AsyncIoError::ReadVectored(_))
        ));
    }

    #[test]
    fn sync_rejects_write_straddling_logical_size() {
        let Some((mut sync, size)) = setup() else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        let op = AsyncIoOperation::write_from_vec(
            (size - 512) as i64,
            OwnedIoBuffer::from_vec(vec![0u8; 1024]),
            1,
        );
        assert!(matches!(
            sync.submit_data_operation(op),
            Err(AsyncIoError::WriteVectored(_))
        ));
    }

    #[test]
    fn sync_accepts_operation_exactly_filling_logical_size() {
        let Some((mut sync, size)) = setup() else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        let op =
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0u8; size as usize]), 1);
        sync.submit_data_operation(op).unwrap();
    }

    #[test]
    fn sync_accepts_operation_at_last_sector() {
        let Some((mut sync, size)) = setup() else {
            eprintln!("skipping: qemu-img unavailable");
            return;
        };

        // VHDX operates in 512-byte sectors; read exactly the last sector.
        let op = AsyncIoOperation::read_to_vec(
            (size - 512) as i64,
            OwnedIoBuffer::from_vec(vec![0u8; 512]),
            1,
        );
        sync.submit_data_operation(op).unwrap();
    }
}
