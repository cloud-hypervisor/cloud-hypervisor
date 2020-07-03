# How to test vhost-user-blk with SPDK

The purpose of this document is to illustrate how to test vhost-user-blk in Cloud Hypervisor with SPDK as the backend.

## Framework

It's a simple test to validate the block read/write between VM and block backend.
```
             +----+----------+          +-------------+-----------+
             |    |          |          |             |           |
             |    |vhost-user|----------| vhost-user  |    dpdk   |
             |    |blk device|          | port 1      |           |
             |    |          |          |             |           |
             |    +----------+          +-------------+-----------+
             |               |          |                         |
             |      vm       |          |           spdk          |
             |               |          |                         |
          +--+----------------------------------------------------+--+
          |  |                  hugepages                         |  |
          |  +----------------------------------------------------+  |
          |                                                          |
          |                       host                               |
          |                                                          |
          +----------------------------------------------------------+
```
## Prerequisites

Prior to running the test, the following steps need to be performed.
- Enable hugepages
- Install SPDK

Here are some good references for detailing them.
- spdk
	* https://spdk.io/doc/

## Test environment

The below test environment is based on ubuntu release(16.04.1 LTS), as for other system, please check related document.
The test runs with multiple queue (MQ) support enabled, using 4 queues defined for both SPDK and the virtual machine.
Here are the details on how the test can be run.

### The hugepages settings in host linux
Add "default_hugepagesz=1G hugepagesz=1G hugepages=2" into host linux cmdline.
As for how to change Ubuntu linux cmdline in grub file, please ref below link:
https://www.ostechnix.com/configure-grub-2-boot-loader-settings-ubuntu-16-04/
reboot Ubuntu
sudo mount -t hugetlbfs -o pagesize=1G none /dev/hugepages

### Download the SPDK code
git clone https://github.com/spdk/spdk
cd spdk
git submodule update --init

### Create the build dep
./scripts/pkgdep.sh

### Build spdk
./configure
make

### Set the SPDk environment
sudo HUGEMEM=2048 scripts/setup.sh
sudo ./app/vhost/vhost -S /var/tmp -s 1024 -m 0x3 &

### Create 512M block device
sudo scripts/rpc.py bdev_malloc_create 512 512 -b Malloc0
sudo scripts/rpc.py vhost_create_blk_controller --cpumask 0x1 vhost.1 Malloc0

_Launch the VM_

VMs run in client mode. They connect to the socket created by the `dpdkvhostuser` in the SPDK backend.
```bash
# From the test terminal. We need to create one vhost-user-blk device for the --disk.
./cloud-hypervisor \
        --cpus boot=4 \
        --memory size=1024M,hugepages=on \
        --kernel linux/arch/x86/boot/compressed/vmlinux.bin \
        --cmdline "console=ttyS0 root=/dev/vda1 rw iommu=off" \
        --disk path=images/focal-server-cloudimg-amd64.raw vhost_user=true,socket=/var/tmp/vhost.1,num_queues=4,queue_size=128 \
        --console off \
        --serial tty \
        --rng
```

```bash
# How to test the vhost-user-blk device with SPDK backend
login in guest

# Use lsblk command to find out vhost-user-blk device
lsblk
NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
vda     252:0    0  2.2G  0 disk 
├─vda1  252:1    0  2.1G  0 part /
├─vda14 252:14   0    4M  0 part 
└─vda15 252:15   0  106M  0 part /boot/efi
vdb    253:16   0  512M  0 disk

The vhost-user-blk device is /dev/vdb

# How to do simple read/write test
dd if=/dev/vdb of=/dev/null bs=2M iflag=direct
dd of=/dev/vdb if=/dev/zero bs=2M oflag=direct count=256

If you want to do fio test, please install fio binary into guest. The detailed info is not listed here.
