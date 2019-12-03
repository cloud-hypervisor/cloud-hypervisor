# How to use virtio-fs

In the context of virtualization, it is always convenient to be able to share a directory from the host with the guest.

__virtio-fs__, also known as __vhost-user-fs__ is a virtual device defined by the VIRTIO specification which allows any VMM to perform filesystem sharing.

## Pre-requisites

### The daemon

This virtual device relies on the _vhost-user_ protocol, which assumes the backend (device emulation) is handled by a dedicated process running on the host. This daemon is called __virtiofsd__ and needs to be present on the host.

_Build virtiofsd_
```bash
git clone --depth 1 "https://github.com/sboeuf/qemu.git" -b "virtio-fs" $VIRTIOFSD_DIR
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
    -o vhost_user_socket=/tmp/virtiofs \
    -o source=/tmp/shared_dir \
    -o cache=always
```

The `cache=always` option should be the default when using `virtiofsd` with the __cloud-hypervisor__ VMM. This allows the daemon to memory map the shared files, which gives better I/O performance.

The `cache=none` option is another way to run the daemon but because the _virtqueues_ are used to convey the files content in this case, the I/O performance is impacted.

### The kernel

In order to leverage __virtio-fs__ support from within the guest, and because the code has not been merged in upstream Linux kernel yet, it is required to build a custom kernel embedding the patches.

The following branch `virtio-fs-virtio-iommu` on the repository https://github.com/cloud-hypervisor/linux.git includes all the needed patches to support __virtio-fs__.

Make sure to build a kernel out of this branch that can be then used to boot the VM.

## How to share directories with cloud-hypervisor

### Start the VM
Once the daemon is running, the option `--fs` from __cloud-hypervisor__ needs to be used.

Direct kernel boot option is preferred since we need to provide the custom kernel including the __virtio-fs__ patches. We could boot from `hypervisor-fw` if we had previously edited the image to replace the kernel binary.

Because _vhost-user_ expects a dedicated process (__virtiofsd__ in this case) to be able to access the guest RAM to communicate through the _virtqueues_ with the driver running in the guest, `--memory` option needs to be slightly modified. It needs to specify a backing file for the memory so that an external process can access it.

Assuming you have `clear-kvm.img` and `custom-vmlinux.bin` on your system, here is the __cloud-hypervisor__ command you need to run:
```bash
./cloud-hypervisor \
    --cpus 4 \
    --memory "size=512,file=/dev/shm" \
    --disk path=clear-kvm.img \
    --kernel custom-vmlinux.bin \
    --cmdline "console=ttyS0 reboot=k panic=1 nomodules root=/dev/vda3" \ 
    --fs tag=virtiofs,sock=/tmp/virtiofs,num_queues=1,queue_size=512
```

By default, DAX is enabled with a cache window of 8GiB. You can specify a custom size (let's say 4GiB for this example) for the cache by explicitly setting DAX and the cache size:

```bash
--fs tag=virtiofs,sock=/tmp/virtiofs,num_queues=1,queue_size=512,dax=on,cache_size=4G

```

In case you don't want to use a shared window of cache to pass the shared files content, this means you will have to explicitly disable DAX with `dax=off`. Note that in this case, the `cache_size` parameter will be ignored.

```bash
--fs tag=virtiofs,sock=/tmp/virtiofs,num_queues=1,queue_size=512,dax=off

```

### Mount the shared directory
The last step is to mount the shared directory inside the guest, using the `virtio_fs` filesystem type.
```bash
mkdir mount_dir
mount \
    -t virtio_fs virtiofs mount_dir/ \
    -o rootmode=040000,user_id=0,group_id=0,dax
```
The `tag` needs to be consistent with what has been provided through the __cloud-hypervisor__ command line, which happens to be `virtiofs` in this example.

The `dax` option must be removed in case the shared cache region is not enabled from the VMM.
