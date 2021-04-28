# How to use virtio-fs

In the context of virtualization, it is always convenient to be able to share a directory from the host with the guest.

__virtio-fs__, also known as __vhost-user-fs__ is a virtual device defined by the VIRTIO specification which allows any VMM to perform filesystem sharing.

## Pre-requisites

### The daemon

This virtual device relies on the _vhost-user_ protocol, which assumes the backend (device emulation) is handled by a dedicated process running on the host. This daemon is called __virtiofsd__ and needs to be present on the host.

_Build virtiofsd_
```bash
git clone --depth 1 "https://gitlab.com/virtio-fs/qemu.git" -b "qemu5.0-virtiofs-dax" $VIRTIOFSD_DIR
cd $VIRTIOFSD_DIR
./configure --prefix=$PWD --target-list=x86_64-softmmu
make virtiofsd -j `nproc`
sudo setcap cap_sys_admin+epi "virtiofsd"
```
_Create shared directory_
```bash
mkdir /tmp/shared_dir
```
_Run virtiofsd_
```bash
./virtiofsd \
    -d \
    --socket-path=/tmp/virtiofs \
    -o source=/tmp/shared_dir \
    -o cache=none
```

The `cache=none` option should be the default when using `virtiofsd` with the __cloud-hypervisor__ VMM. This prevents from using the guest page cache, which reduces the memory footprint of the guest. When running multiple virtual machines on the same host, this will let the host deal with page cache, which will increase the density of virtual machines which can be launched.

The `cache=always` option will allow for the guest page cache to be used, which will increase the memory footprint of the guest. This option should be used only for specific use cases where a single VM is going to be running on a host.

### Kernel support

Modern Linux kernels starting (at least v5.10) have support for virtio-fs. Use
of older kernels, with additional patches, are not supported.

## How to share directories with cloud-hypervisor

### Start the VM
Once the daemon is running, the option `--fs` from __cloud-hypervisor__ needs to be used.

Direct kernel boot is the preferred option, but we can boot from an EFI cloud image if it contains a recent enough kernel.

Because _vhost-user_ expects a dedicated process (__virtiofsd__ in this case) to be able to access the guest RAM to communicate through the _virtqueues_ with the driver running in the guest, `--memory` option needs to be slightly modified. It must specify `shared=on` to share the memory pages so that an external process can access them.

Assuming you have `focal-server-cloudimg-amd64.raw` and `vmlinux` on your system, here is the __cloud-hypervisor__ command you need to run:
```bash
./cloud-hypervisor \
    --cpus boot=1 \
    --memory size=1G,shared=on \
    --disk path=focal-server-cloudimg-amd64.raw \
    --kernel vmlinux \
    --cmdline "console=hvc0 root=/dev/vda1 rw" \
    --fs tag=myfs,socket=/tmp/virtiofs,num_queues=1,queue_size=512
```

By default, DAX is enabled with a cache window of 8GiB. You can specify a custom size (let's say 4GiB for this example) for the cache by explicitly setting DAX and the cache size:

```bash
--fs tag=myfs,socket=/tmp/virtiofs,num_queues=1,queue_size=512,dax=on,cache_size=4G

```

In case you don't want to use a shared window of cache to pass the shared files content, this means you will have to explicitly disable DAX with `dax=off`. Note that in this case, the `cache_size` parameter will be ignored.

```bash
--fs tag=myfs,socket=/tmp/virtiofs,num_queues=1,queue_size=512,dax=off

```

### Mount the shared directory
The last step is to mount the shared directory inside the guest, using the `virtiofs` filesystem type.
```bash
mkdir mount_dir
mount -t virtiofs -o dax myfs mount_dir/
```
The `tag` needs to be consistent with what has been provided through the __cloud-hypervisor__ command line, which happens to be `myfs` in this example.

The `-o dax` option must be removed in case the shared cache region is not enabled from the VMM.
