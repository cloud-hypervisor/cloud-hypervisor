// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;

use libc;
use vm_memory::ByteValued;

use super::fs_cache_req_handler::FsCacheReqHandler;
use crate::descriptor_utils::{Reader, Writer};
use crate::filesystem::{
    Context, DirEntry, Entry, FileSystem, GetxattrReply, ListxattrReply, ZeroCopyReader,
    ZeroCopyWriter,
};
use crate::fuse::*;
use crate::{Error, Result};

const MAX_BUFFER_SIZE: u32 = 1 << 20;
const DIRENT_PADDING: [u8; 8] = [0; 8];

struct ZCReader<'a>(Reader<'a>);

impl<'a> ZeroCopyReader for ZCReader<'a> {
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        self.0.read_to_at(f, count, off)
    }
}

impl<'a> io::Read for ZCReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

struct ZCWriter<'a>(Writer<'a>);

impl<'a> ZeroCopyWriter for ZCWriter<'a> {
    fn write_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        self.0.write_from_at(f, count, off)
    }
}

impl<'a> io::Write for ZCWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub struct Server<F: FileSystem + Sync> {
    fs: F,
}

impl<F: FileSystem + Sync> Server<F> {
    pub fn new(fs: F) -> Server<F> {
        Server { fs }
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn handle_message<T: FsCacheReqHandler>(
        &self,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
    ) -> Result<usize> {
        let in_header: InHeader = r.read_obj().map_err(Error::DecodeMessage)?;

        if in_header.len > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }
        match in_header.opcode {
            x if x == Opcode::Lookup as u32 => self.lookup(in_header, r, w),
            x if x == Opcode::Forget as u32 => self.forget(in_header, r), // No reply.
            x if x == Opcode::Getattr as u32 => self.getattr(in_header, r, w),
            x if x == Opcode::Setattr as u32 => self.setattr(in_header, r, w),
            x if x == Opcode::Readlink as u32 => self.readlink(in_header, w),
            x if x == Opcode::Symlink as u32 => self.symlink(in_header, r, w),
            x if x == Opcode::Mknod as u32 => self.mknod(in_header, r, w),
            x if x == Opcode::Mkdir as u32 => self.mkdir(in_header, r, w),
            x if x == Opcode::Unlink as u32 => self.unlink(in_header, r, w),
            x if x == Opcode::Rmdir as u32 => self.rmdir(in_header, r, w),
            x if x == Opcode::Rename as u32 => self.rename(in_header, r, w),
            x if x == Opcode::Link as u32 => self.link(in_header, r, w),
            x if x == Opcode::Open as u32 => self.open(in_header, r, w),
            x if x == Opcode::Read as u32 => self.read(in_header, r, w),
            x if x == Opcode::Write as u32 => self.write(in_header, r, w),
            x if x == Opcode::Statfs as u32 => self.statfs(in_header, w),
            x if x == Opcode::Release as u32 => self.release(in_header, r, w),
            x if x == Opcode::Fsync as u32 => self.fsync(in_header, r, w),
            x if x == Opcode::Setxattr as u32 => self.setxattr(in_header, r, w),
            x if x == Opcode::Getxattr as u32 => self.getxattr(in_header, r, w),
            x if x == Opcode::Listxattr as u32 => self.listxattr(in_header, r, w),
            x if x == Opcode::Removexattr as u32 => self.removexattr(in_header, r, w),
            x if x == Opcode::Flush as u32 => self.flush(in_header, r, w),
            x if x == Opcode::Init as u32 => self.init(in_header, r, w),
            x if x == Opcode::Opendir as u32 => self.opendir(in_header, r, w),
            x if x == Opcode::Readdir as u32 => self.readdir(in_header, r, w),
            x if x == Opcode::Releasedir as u32 => self.releasedir(in_header, r, w),
            x if x == Opcode::Fsyncdir as u32 => self.fsyncdir(in_header, r, w),
            x if x == Opcode::Getlk as u32 => self.getlk(in_header, r, w),
            x if x == Opcode::Setlk as u32 => self.setlk(in_header, r, w),
            x if x == Opcode::Setlkw as u32 => self.setlkw(in_header, r, w),
            x if x == Opcode::Access as u32 => self.access(in_header, r, w),
            x if x == Opcode::Create as u32 => self.create(in_header, r, w),
            x if x == Opcode::Interrupt as u32 => self.interrupt(in_header),
            x if x == Opcode::Bmap as u32 => self.bmap(in_header, r, w),
            x if x == Opcode::Destroy as u32 => self.destroy(),
            x if x == Opcode::Ioctl as u32 => self.ioctl(in_header, r, w),
            x if x == Opcode::Poll as u32 => self.poll(in_header, r, w),
            x if x == Opcode::NotifyReply as u32 => self.notify_reply(in_header, r, w),
            x if x == Opcode::BatchForget as u32 => self.batch_forget(in_header, r, w),
            x if x == Opcode::Fallocate as u32 => self.fallocate(in_header, r, w),
            x if x == Opcode::Readdirplus as u32 => self.readdirplus(in_header, r, w),
            x if x == Opcode::Rename2 as u32 => self.rename2(in_header, r, w),
            x if x == Opcode::Lseek as u32 => self.lseek(in_header, r, w),
            x if x == Opcode::CopyFileRange as u32 => self.copyfilerange(in_header, r, w),
            x if x == Opcode::SetupMapping as u32 => self.setupmapping(in_header, r, w, vu_req),
            x if x == Opcode::RemoveMapping as u32 => self.removemapping(in_header, r, w, vu_req),
            _ => reply_error(
                io::Error::from_raw_os_error(libc::ENOSYS),
                in_header.unique,
                w,
            ),
        }
    }

    fn setupmapping<T: FsCacheReqHandler>(
        &self,
        in_header: InHeader,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
    ) -> Result<usize> {
        if let Some(req) = vu_req {
            let SetupmappingIn {
                fh,
                foffset,
                len,
                flags,
                moffset,
            } = r.read_obj().map_err(Error::DecodeMessage)?;

            match self.fs.setupmapping(
                Context::from(in_header),
                in_header.nodeid.into(),
                fh.into(),
                foffset,
                len,
                flags,
                moffset,
                req,
            ) {
                Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
                Err(e) => reply_error(e, in_header.unique, w),
            }
        } else {
            reply_error(
                io::Error::from_raw_os_error(libc::EINVAL),
                in_header.unique,
                w,
            )
        }
    }

    fn removemapping<T: FsCacheReqHandler>(
        &self,
        in_header: InHeader,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
    ) -> Result<usize> {
        if let Some(req) = vu_req {
            let RemovemappingIn { count } = r.read_obj().map_err(Error::DecodeMessage)?;

            if let Some(size) = (count as usize).checked_mul(size_of::<RemovemappingOne>()) {
                if size > MAX_BUFFER_SIZE as usize {
                    return reply_error(
                        io::Error::from_raw_os_error(libc::ENOMEM),
                        in_header.unique,
                        w,
                    );
                }
            } else {
                return reply_error(
                    io::Error::from_raw_os_error(libc::EOVERFLOW),
                    in_header.unique,
                    w,
                );
            }

            let mut requests = Vec::with_capacity(count as usize);
            for _ in 0..count {
                requests.push(
                    r.read_obj::<RemovemappingOne>()
                        .map_err(Error::DecodeMessage)?,
                );
            }

            match self
                .fs
                .removemapping(Context::from(in_header), requests, req)
            {
                Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
                Err(e) => reply_error(e, in_header.unique, w),
            }
        } else {
            reply_error(
                io::Error::from_raw_os_error(libc::EINVAL),
                in_header.unique,
                w,
            )
        }
    }

    fn lookup(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0u8; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(buf.as_ref())?;

        match self
            .fs
            .lookup(Context::from(in_header), in_header.nodeid.into(), &name)
        {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn forget(&self, in_header: InHeader, mut r: Reader) -> Result<usize> {
        let ForgetIn { nlookup } = r.read_obj().map_err(Error::DecodeMessage)?;

        self.fs
            .forget(Context::from(in_header), in_header.nodeid.into(), nlookup);

        // There is no reply for forget messages.
        Ok(0)
    }

    fn getattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetattrIn { flags, fh, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let handle = if (flags & GETATTR_FH) != 0 {
            Some(fh.into())
        } else {
            None
        };

        match self
            .fs
            .getattr(Context::from(in_header), in_header.nodeid.into(), handle)
        {
            Ok((st, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr: st.into(),
                };
                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn setattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let setattr_in: SetattrIn = r.read_obj().map_err(Error::DecodeMessage)?;

        let handle = if setattr_in.valid & FATTR_FH != 0 {
            Some(setattr_in.fh.into())
        } else {
            None
        };

        let valid = SetattrValid::from_bits_truncate(setattr_in.valid);

        let st: libc::stat64 = setattr_in.into();

        match self.fs.setattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            st,
            handle,
            valid,
        ) {
            Ok((st, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr: st.into(),
                };
                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn readlink(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        match self
            .fs
            .readlink(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(linkname) => {
                // We need to disambiguate the option type here even though it is `None`.
                reply_ok(None::<u8>, Some(&linkname), in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn symlink(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        // Unfortunately the name and linkname are encoded one after another and
        // separated by a nul character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (name, linkname) = buf.split_at(split_pos);

        match self.fs.symlink(
            Context::from(in_header),
            bytes_to_cstr(linkname)?,
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mknod(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let MknodIn {
            mode, rdev, umask, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MknodIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.mknod(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
            mode,
            rdev,
            umask,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mkdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let MkdirIn { mode, umask } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MkdirIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.mkdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
            mode,
            umask,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn unlink(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.unlink(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn rmdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.rmdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn do_rename(
        &self,
        in_header: InHeader,
        msg_size: usize,
        newdir: u64,
        flags: u32,
        mut r: Reader,
        w: Writer,
    ) -> Result<usize> {
        let buflen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(msg_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; buflen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (oldname, newname) = buf.split_at(split_pos);

        match self.fs.rename(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(oldname)?,
            newdir.into(),
            bytes_to_cstr(newname)?,
            flags,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn rename(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let RenameIn { newdir } = r.read_obj().map_err(Error::DecodeMessage)?;

        self.do_rename(in_header, size_of::<RenameIn>(), newdir, 0, r, w)
    }

    fn rename2(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let Rename2In { newdir, flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let flags = flags & (libc::RENAME_EXCHANGE | libc::RENAME_NOREPLACE) as u32;

        self.do_rename(in_header, size_of::<Rename2In>(), newdir, flags, r, w)
    }

    fn link(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let LinkIn { oldnodeid } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<LinkIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.link(
            Context::from(in_header),
            oldnodeid.into(),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn open(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let OpenIn { flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self
            .fs
            .open(Context::from(in_header), in_header.nodeid.into(), flags)
        {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn read(&self, in_header: InHeader, mut r: Reader, mut w: Writer) -> Result<usize> {
        let ReadIn {
            fh,
            offset,
            size,
            read_flags,
            lock_owner,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let owner = if read_flags & READ_LOCKOWNER != 0 {
            Some(lock_owner)
        } else {
            None
        };

        // Split the writer into 2 pieces: one for the `OutHeader` and the rest for the data.
        let data_writer = ZCWriter(w.split_at(size_of::<OutHeader>()).unwrap());

        match self.fs.read(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            data_writer,
            size,
            offset,
            owner,
            flags,
        ) {
            Ok(count) => {
                // Don't use `reply_ok` because we need to set a custom size length for the
                // header.
                let out = OutHeader {
                    len: (size_of::<OutHeader>() + count) as u32,
                    error: 0,
                    unique: in_header.unique,
                };

                w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
                Ok(out.len as usize)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn write(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let WriteIn {
            fh,
            offset,
            size,
            write_flags,
            lock_owner,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let owner = if write_flags & WRITE_LOCKOWNER != 0 {
            Some(lock_owner)
        } else {
            None
        };

        let delayed_write = write_flags & WRITE_CACHE != 0;

        let data_reader = ZCReader(r);

        match self.fs.write(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            data_reader,
            size,
            offset,
            owner,
            delayed_write,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn statfs(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        match self
            .fs
            .statfs(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(st) => reply_ok(Some(Kstatfs::from(st)), None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn release(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let ReleaseIn {
            fh,
            flags,
            release_flags,
            lock_owner,
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let flush = release_flags & RELEASE_FLUSH != 0;
        let flock_release = release_flags & RELEASE_FLOCK_UNLOCK != 0;
        let lock_owner = if flush || flock_release {
            Some(lock_owner)
        } else {
            None
        };

        match self.fs.release(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
            flush,
            flock_release,
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn fsync(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsync(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn setxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let SetxattrIn { size, flags } = r.read_obj().map_err(Error::DecodeMessage)?;

        // The name and value and encoded one after another and separated by a '\0' character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<SetxattrIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (name, value) = buf.split_at(split_pos);

        if size != value.len() as u32 {
            return Err(Error::InvalidXattrSize((size, value.len())));
        }

        match self.fs.setxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            value,
            flags,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn getxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetxattrIn { size, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<GetxattrIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        match self.fs.getxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
            size,
        ) {
            Ok(GetxattrReply::Value(val)) => reply_ok(None::<u8>, Some(&val), in_header.unique, w),
            Ok(GetxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn listxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetxattrIn { size, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        match self
            .fs
            .listxattr(Context::from(in_header), in_header.nodeid.into(), size)
        {
            Ok(ListxattrReply::Names(val)) => reply_ok(None::<u8>, Some(&val), in_header.unique, w),
            Ok(ListxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn removexattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(&buf)?;

        match self
            .fs
            .removexattr(Context::from(in_header), in_header.nodeid.into(), name)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn flush(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FlushIn { fh, lock_owner, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.flush(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn init(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let InitIn {
            major,
            minor,
            max_readahead,
            flags,
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if major < KERNEL_VERSION {
            error!("Unsupported fuse protocol version: {}.{}", major, minor);
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                w,
            );
        }

        if major > KERNEL_VERSION {
            // Wait for the kernel to reply back with a 7.X version.
            let out = InitOut {
                major: KERNEL_VERSION,
                minor: KERNEL_MINOR_VERSION,
                ..Default::default()
            };

            return reply_ok(Some(out), None, in_header.unique, w);
        }

        if minor < KERNEL_MINOR_VERSION {
            error!(
                "Unsupported fuse protocol minor version: {}.{}",
                major, minor
            );
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                w,
            );
        }

        // These fuse features are supported by this server by default.
        let supported = FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::BIG_WRITES
            | FsOptions::AUTO_INVAL_DATA
            | FsOptions::HANDLE_KILLPRIV
            | FsOptions::ASYNC_DIO
            | FsOptions::HAS_IOCTL_DIR
            | FsOptions::ATOMIC_O_TRUNC
            | FsOptions::MAX_PAGES;

        let capable = FsOptions::from_bits_truncate(flags);

        let page_size: u32 = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
        let max_pages = ((MAX_BUFFER_SIZE - 1) / page_size) + 1;

        match self.fs.init(capable) {
            Ok(want) => {
                let enabled = capable & (want | supported);

                let out = InitOut {
                    major: KERNEL_VERSION,
                    minor: KERNEL_MINOR_VERSION,
                    max_readahead,
                    flags: enabled.bits(),
                    max_background: ::std::u16::MAX,
                    congestion_threshold: (::std::u16::MAX / 4) * 3,
                    max_write: MAX_BUFFER_SIZE,
                    time_gran: 1, // nanoseconds
                    max_pages: max_pages.try_into().unwrap(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn opendir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let OpenIn { flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self
            .fs
            .opendir(Context::from(in_header), in_header.nodeid.into(), flags)
        {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn do_readdir(
        &self,
        in_header: InHeader,
        mut r: Reader,
        mut w: Writer,
        plus: bool,
    ) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let available_bytes = w.available_bytes();
        if available_bytes < size as usize {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        // Skip over enough bytes for the header.
        let mut cursor = w.split_at(size_of::<OutHeader>()).unwrap();

        let res = if plus {
            self.fs.readdirplus(
                Context::from(in_header),
                in_header.nodeid.into(),
                fh.into(),
                size,
                offset,
                |d, e| add_dirent(&mut cursor, size, d, Some(e)),
            )
        } else {
            self.fs.readdir(
                Context::from(in_header),
                in_header.nodeid.into(),
                fh.into(),
                size,
                offset,
                |d| add_dirent(&mut cursor, size, d, None),
            )
        };

        if let Err(e) = res {
            reply_error(e, in_header.unique, w)
        } else {
            // Don't use `reply_ok` because we need to set a custom size length for the
            // header.
            let out = OutHeader {
                len: (size_of::<OutHeader>() + cursor.bytes_written()) as u32,
                error: 0,
                unique: in_header.unique,
            };

            w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
            Ok(out.len as usize)
        }
    }

    fn readdir(&self, in_header: InHeader, r: Reader, w: Writer) -> Result<usize> {
        self.do_readdir(in_header, r, w, false)
    }

    fn readdirplus(&self, in_header: InHeader, r: Reader, w: Writer) -> Result<usize> {
        self.do_readdir(in_header, r, w, true)
    }

    fn releasedir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let ReleaseIn { fh, flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.releasedir(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn fsyncdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsyncdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn getlk(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.getlk() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn setlk(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.setlk() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn setlkw(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.setlkw() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn access(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let AccessIn { mask, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self
            .fs
            .access(Context::from(in_header), in_header.nodeid.into(), mask)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn create(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let CreateIn {
            flags, mode, umask, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<CreateIn>()))
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(&buf)?;

        match self.fs.create(
            Context::from(in_header),
            in_header.nodeid.into(),
            name,
            mode,
            flags,
            umask,
        ) {
            Ok((entry, handle, opts)) => {
                let entry_out = EntryOut {
                    nodeid: entry.inode,
                    generation: entry.generation,
                    entry_valid: entry.entry_timeout.as_secs(),
                    attr_valid: entry.attr_timeout.as_secs(),
                    entry_valid_nsec: entry.entry_timeout.subsec_nanos(),
                    attr_valid_nsec: entry.attr_timeout.subsec_nanos(),
                    attr: entry.attr.into(),
                };
                let open_out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                // Kind of a hack to write both structs.
                reply_ok(
                    Some(entry_out),
                    Some(open_out.as_slice()),
                    in_header.unique,
                    w,
                )
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn interrupt(&self, _in_header: InHeader) -> Result<usize> {
        Ok(0)
    }

    fn bmap(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.bmap() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn destroy(&self) -> Result<usize> {
        // No reply to this function.
        self.fs.destroy();

        Ok(0)
    }

    fn ioctl(&self, in_header: InHeader, _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.ioctl() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn poll(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.poll() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn notify_reply(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.notify_reply() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn batch_forget(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let BatchForgetIn { count, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        if let Some(size) = (count as usize).checked_mul(size_of::<ForgetOne>()) {
            if size > MAX_BUFFER_SIZE as usize {
                return reply_error(
                    io::Error::from_raw_os_error(libc::ENOMEM),
                    in_header.unique,
                    w,
                );
            }
        } else {
            return reply_error(
                io::Error::from_raw_os_error(libc::EOVERFLOW),
                in_header.unique,
                w,
            );
        }

        let mut requests = Vec::with_capacity(count as usize);
        for _ in 0..count {
            requests.push(
                r.read_obj::<ForgetOne>()
                    .map(|f| (f.nodeid.into(), f.nlookup))
                    .map_err(Error::DecodeMessage)?,
            );
        }

        self.fs.batch_forget(Context::from(in_header), requests);

        // No reply for forget messages.
        Ok(0)
    }

    fn fallocate(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FallocateIn {
            fh,
            offset,
            length,
            mode,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.fallocate(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            mode,
            offset,
            length,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn lseek(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let LseekIn {
            fh, offset, whence, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.lseek(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            offset,
            whence,
        ) {
            Ok(offset) => {
                let out = LseekOut { offset };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn copyfilerange(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let CopyfilerangeIn {
            fh_in,
            off_in,
            nodeid_out,
            fh_out,
            off_out,
            len,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.copyfilerange(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh_in.into(),
            off_in,
            nodeid_out.into(),
            fh_out.into(),
            off_out,
            len,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }
}

fn reply_ok<T: ByteValued>(
    out: Option<T>,
    data: Option<&[u8]>,
    unique: u64,
    mut w: Writer,
) -> Result<usize> {
    let mut len = size_of::<OutHeader>();

    if out.is_some() {
        len += size_of::<T>();
    }

    if let Some(ref data) = data {
        len += data.len();
    }

    let header = OutHeader {
        len: len as u32,
        error: 0,
        unique,
    };

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    if let Some(out) = out {
        w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
    }

    if let Some(data) = data {
        w.write_all(data).map_err(Error::EncodeMessage)?;
    }

    debug_assert_eq!(len, w.bytes_written());
    Ok(w.bytes_written())
}

fn reply_error(e: io::Error, unique: u64, mut w: Writer) -> Result<usize> {
    let header = OutHeader {
        len: size_of::<OutHeader>() as u32,
        error: -e.raw_os_error().unwrap_or(libc::EIO),
        unique,
    };

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    debug_assert_eq!(header.len as usize, w.bytes_written());
    Ok(w.bytes_written())
}

fn bytes_to_cstr(buf: &[u8]) -> Result<&CStr> {
    // Convert to a `CStr` first so that we can drop the '\0' byte at the end
    // and make sure there are no interior '\0' bytes.
    CStr::from_bytes_with_nul(buf).map_err(Error::InvalidCString)
}

fn add_dirent(
    cursor: &mut Writer,
    max: u32,
    d: DirEntry,
    entry: Option<Entry>,
) -> io::Result<usize> {
    if d.name.len() > ::std::u32::MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }

    let dirent_len = size_of::<Dirent>()
        .checked_add(d.name.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    // Directory entries must be padded to 8-byte alignment.  If adding 7 causes
    // an overflow then this dirent cannot be properly padded.
    let padded_dirent_len = dirent_len
        .checked_add(7)
        .map(|l| l & !7)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    let total_len = if entry.is_some() {
        padded_dirent_len
            .checked_add(size_of::<EntryOut>())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?
    } else {
        padded_dirent_len
    };

    if (max as usize).saturating_sub(cursor.bytes_written()) < total_len {
        Ok(0)
    } else {
        if let Some(entry) = entry {
            cursor.write_all(EntryOut::from(entry).as_slice())?;
        }

        let dirent = Dirent {
            ino: d.ino,
            off: d.offset,
            namelen: d.name.len() as u32,
            type_: d.type_,
        };

        cursor.write_all(dirent.as_slice())?;
        cursor.write_all(d.name)?;

        // We know that `dirent_len` <= `padded_dirent_len` due to the check above
        // so there's no need for checked arithmetic.
        let padding = padded_dirent_len - dirent_len;
        if padding > 0 {
            cursor.write_all(&DIRENT_PADDING[..padding])?;
        }

        Ok(total_len)
    }
}
