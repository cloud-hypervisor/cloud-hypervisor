# Virtio Block Size Override

A disk advertises a logical block size to the guest derived from its
backing storage, so the geometry the guest sees is dictated by the
host. The `x_override_virtio_block_size` disk option overrides the
logical block size advertised by virtio-block, so an image keeps the
geometry it was built for regardless of what backs it, for example a
512 byte sector image on 4096 byte native storage, or a 4096 byte GPT
inside a qcow2 file.

```
--disk path=/foo.raw,x_override_virtio_block_size=512
```

The `x_` prefix marks the option experimental. It applies to every
disk backend, since it shapes the advertised virtio-block topology
rather than the format backend.

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

With `direct=on` there is no page cache to perform that read modify
write. The backend can bounce a single unaligned request through
`AlignedFile`, but it does not serialize concurrent ones, so two guest
writes into the same backend block could race and lose an update. An
override below the backend logical block size is therefore rejected at
disk open, while an override at or above it keeps guest I/O aligned and
is accepted. For a block device the backend value is the device
logical block size. For a regular file it is the filesystem direct
I/O alignment.

## Restrictions

- The value must be a power of 2, at least 512, and fit the u32
  `blk_size` field of the virtio configuration space.
- vhost-user disks are rejected because the external backend provides
  the virtio configuration space.

## Verifying inside the guest

```
$ cat /sys/block/vda/queue/logical_block_size
512
```

The `LOG-SEC` column of `lsblk -t` reports the same value.
