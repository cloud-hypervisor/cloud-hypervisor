# Disk Image Locking

Cloud Hypervisor places an advisory lock on each disk image opened via
`--disk` to prevent multiple instances from concurrently accessing the
same file. This avoids potential data corruption from overlapping writes.
Locks are advisory and require cooperating processes; a non-cooperating
process can still open and write to a locked file. Locking is host-local
and does not enforce coordination across multiple hosts.

If the backing file resides on network storage, the storage system must
correctly translate or propagate OFD (Open File Description) locks across
the network to ensure that advisory locking semantics are preserved in a
multi-host environment. In the case of Linux, OFD locks are translated
into NFS locks by the NFS driver.

The implementation uses Open File Description (OFD) locks (`F_OFD_SETLK`)
rather than traditional POSIX locks (`F_SETLK`). OFD locks are only
released when the last file descriptor referencing the open file
description is closed, preventing accidental early release.

## Lock Granularity

The `lock_granularity` parameter controls how the lock is placed on the
disk image:

```
--disk path=/foo.img,lock_granularity=byte-range
--disk path=/bar.img,lock_granularity=full
```

### `byte-range` (default)

Locks the byte range `[0, physical_file_size)`. The physical file size
is evaluated once at startup; if the file grows after the lock is
acquired, the newly appended region is not covered by the lock.

The file is protected against concurrent access by other instances of
Cloud Hypervisor. That's the only thing we can guarantee.

#### Fallback to full

One caveat is that if the physical size of the disk image cannot be
determined at startup (e.g. with certain vhost-user backends), Cloud
Hypervisor falls back to a whole-file lock regardless of the
`lock_granularity` setting, as a byte-range lock cannot be safely
computed without knowing the physical file size.

### `full`

Locks the entire file using the OFD whole-file semantic (`l_start=0`,
`l_len=0`). This may be needed in environments that depend on whole-file
lock semantics. Note that on some network storage backends, whole-file
OFD locks may be treated as mandatory rather than advisory, which can
cause external tools to fail when accessing the disk image. Lock
behavior may also vary across network filesystem implementations.

## Disk Resizing

Cloud Hypervisor supports live disk resizing. Currently, byte-range
locks are not updated. However, as a part of the file is still locked,
no new Cloud Hypervisor instance can open the disk image.
