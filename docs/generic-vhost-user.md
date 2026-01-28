# How to use generic vhost-user devices

## What is a generic vhost-user device?

Cloud Hypervisor deliberately does not have support for all types of virtio devices.
For instance, it does not natively support sound or media.

However, the vhost-user protocol does not require the frontend to have separate
code for each type of vhost-user device. This allows writing a *generic* frontend
that supports almost all of them. The only requirements are:

- The protocol must not require any non-standard message types.
  This currently excludes virtio-GPU, though this may change in the future.
- The backend must be able to handle all configuration space accesses.
  This means negotiating the `VHOST_USER_PROTOCOL_F_CONFIG` feature.

Otherwise, any vhost-user device is expected to work. It can
(and often will) be of a type that Cloud Hypervisor does not
know about. It can even be of a type that is not standardized.

## Examples

virtiofsd meets these requirements, and generic vhost-user can be used as
an alternative to the built-in virtio-fs support. See [fs.md](fs.md)
for information about virtiofs.

To use generic vhost-user, replace the
```bash
./cloud-hypervisor \
    --cpus boot=1 \
    --memory size=1G,shared=on \
    --disk path=focal-server-cloudimg-amd64.raw \
    --kernel vmlinux \
    --cmdline "console=hvc0 root=/dev/vda1 rw" \
    --fs tag=myfs,socket=/tmp/virtiofs,num_queues=1,queue_size=512
```

command in that document with

```bash
./cloud-hypervisor \
    --cpus boot=1 \
    --memory size=1G,shared=on \
    --disk path=focal-server-cloudimg-amd64.raw \
    --kernel vmlinux \
    --cmdline "console=hvc0 root=/dev/vda1 rw" \
    --generic-vhost-user 'socket=/tmp/virtiofs,virtio_id=26,queue_size=[512,512]'
```

26 is the ID for a virtio-fs device. The ID for other devices is defined
by the virtio specification. The number of queues is simply the number
of queue sizes that are provided.

## Limitations

Cloud Hypervisor does not save, restore, or migrate the PCI configuration
space of a generic vhost-user device. The backend can do it itself, but if
it does not these features will not work.

Cloud Hypervisor cannot validate the number of parameters of a generic
vhost-user device.  Notably, it cannot validate the number of queues.
For instance, using the generic vhost-user device to create a virtio-FS
device with only one queue will cause a Linux guest kernel to hit a BUG
in kfree().
