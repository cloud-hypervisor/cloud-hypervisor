# How to use generic vhost-user devices

## What is a generic vhost-user device?

Cloud Hypervisor deliberately does not have support for all types of virtio devices.
For instance, it does not natively support sound or media.

However, the vhost-user protocol does not require the frontend to have separate
code for each type of vhost-user device. This allows writing a *generic* frontend
that supports almost all of them.

Any vhost-user device that only uses supported protocol messages is
expected to work. It can (and often will) be of a type that Cloud
Hypervisor does not know about. It can even be of a type that is
not standardized.

Virtio-GPU is known to *not* work. The version implemented in QEMU
requires `VHOST_USER_GPU_SET_SOCKET`, which is standard but will
never be implemented by Cloud Hypervisor. Other versions require
messages that have not been standardized. In the future, these
versions might be supported.

## Examples

virtiofsd meets these requirements if the `--tag` argument is passed.
Therefore, generic vhost-user can be used as an alternative to the built-in
virtio-fs support. See [fs.md](fs.md) for how to build the virtiofs daemon.

To use generic vhost-user with virtiofsd, use a command line argument
similar to this:

```bash
/path/to/virtiofsd \
   --tag=myfs \
   --log-level=debug \
   "--socket-path=$path_to_virtiofsd_socket" \
   "--shared-dir=$path_to_shared_directory" \
   "${other_virtiofsd_options[@]}" &

/path/to/cloud-hypervisor \
    --cpus boot=1 \
    --memory size=1G,shared=on \
    --disk path=your-linux-image.iso \
    --kernel vmlinux \
    --cmdline "console=hvc0 root=/dev/vda1 rw" \
    --generic-vhost-user "socket=\"${path_to_virtiofsd_socket//\"/\"\"}\",virtio_id=26,queue_sizes=[512,512]" \
   "${other_cloud_hypervisor_options[@]}"
```

26 is the ID for a virtio-fs device. The IDs for other devices are defined
by the VIRTIO specification. The odd-looking variable expansion escapes
any double quotes in the socket path.  It is also possible to provide
the name that is defined by the virtio specification, so `virtio_id=fs`
will also work.

Inside the guest, you can mount the virtio-fs device with

```bash
mkdir mount_dir
mount -t virtiofs -- myfs mount_dir/
```

## Limitations

Cloud Hypervisor does not save, restore, or migrate the PCI configuration
space of a generic vhost-user device. The backend can do it itself, but if
it does not these features will not work.

Cloud Hypervisor cannot validate the number or size of the queues. Some
guest drivers do not validate these and will crash if they are wrong.
Notably, at least some versions of Linux will crash if one creates a
virtio-fs device (id 26) with only one queue.

If any access to configuration space fails, Cloud Hypervisor will panic
instead of injecting an exception into the guest. It is unclear what
correct behavior is in this case.
