# Disk Logical Block Size

A raw disk image advertises the logical block size probed from its
backing file or device, so the geometry the guest sees is dictated by
the host storage. The `logical_block_size` disk option overrides the
advertised value, so an image keeps the geometry it was built for
regardless of what backs it, for example a 512 byte sector image on
4096 byte native storage, or a 4096 byte device backed by storage
that reports 512.

```
--disk path=/foo.raw,logical_block_size=4096
```

## Semantics

The option changes the advertised topology only and adds no read
modify write emulation of its own. The advertised physical block size
and minimum I/O size are raised to at least the overridden value,
since a disk cannot have a physical block or minimum I/O below one
logical block.

With buffered I/O (`direct=off`) any accepted value works regardless
of the backing storage geometry. An advertised block size smaller
than the backing storage entitles the guest to writes the device
cannot serve directly, for example a 512 byte write to a 4096 byte
native device, and the page cache performs the required read modify
write of the surrounding block. A 512 byte sector image on 4096 byte
native storage then presents to the guest as a standard 512e disk,
logical block size 512 with a 4096 byte physical block size.

With `direct=on` the value must match the logical block size probed
from the backing storage. Direct I/O bypasses the page cache, and
emulating a mismatched block size without it is not supported, so
the configuration is rejected at disk open. For a block device the
probed value is the device logical block size. For a regular file it
is the filesystem direct I/O alignment.

## Restrictions

- The image must be raw, where the advertised geometry is purely a
  property of the backing storage. Other formats are rejected.
- The value must be a power of 2, at least 512, and fit the u32
  `blk_size` field of the virtio configuration space.
- vhost-user disks are rejected because the external backend provides
  the virtio configuration space.

## Verifying inside the guest

```
$ cat /sys/block/vda/queue/logical_block_size
4096
```

The `LOG-SEC` column of `lsblk -t` reports the same value.
