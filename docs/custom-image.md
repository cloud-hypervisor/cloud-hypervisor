# How to create a custom Ubuntu image

In the context of adding more utilities to the Ubuntu cloud image being used
for integration testing, this quick guide details how to achieve the proper
modification of an official Ubuntu cloud image.

## Create the image

Let's go through the steps on how to extend an official Ubuntu image. These
steps can be applied to other distributions (with a few changes regarding
package management).

### Get latest Ubuntu cloud image

```bash
wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img
```

### Check the file format is QCOW2

```bash
file focal-server-cloudimg-amd64.img
focal-server-cloudimg-amd64.img: QEMU QCOW2 Image (v2), 2361393152 bytes
```

### Convert QCOW2 into RAW

```bash
qemu-img convert -p -f qcow2 -O raw focal-server-cloudimg-amd64.img focal-server-cloudimg-amd64.raw
```

### Identify the Linux partition

The goal is to mount the image rootfs so that it can be modified as needed.
That's why we need to identify where the Linux filesystem partition is located
in the image.

```bash
sudo fdisk -l focal-server-cloudimg-amd64.raw
Disk focal-server-cloudimg-amd64.raw: 2.2 GiB, 2361393152 bytes, 4612096 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: A1171ABA-2BEA-4218-A467-1B2B607E5953

Device                             Start     End Sectors  Size Type
focal-server-cloudimg-amd64.raw1  227328 4612062 4384735  2.1G Linux filesystem
focal-server-cloudimg-amd64.raw14   2048   10239    8192    4M BIOS boot
focal-server-cloudimg-amd64.raw15  10240  227327  217088  106M EFI System

Partition table entries are not in disk order.
```

### Mount the Linux partition

```bash
mkdir -p /mnt
sudo mount -o loop,offset=$((227328 * 512)) focal-server-cloudimg-amd64.raw /mnt
```

### Set up DNS

The next step describes changing the root directory to the rootfs contained by 
the cloud image. For DNS to work in the root directory, you will need to first bind-mount 
the host `/etc/resolv.conf` onto the mounted linux partition of the cloud image.

```bash
sudo mount -o bind /etc/resolv.conf /mnt/etc/resolv.conf
```

### Change root directory

Changing the root directory will allow us to install new packages to the rootfs
contained by the cloud image.

```bash
sudo chroot /mnt
mount -t proc proc /proc
mount -t devpts devpts /dev/pts
```

### Install needed packages

In the context Cloud Hypervisor's integration tests, we need several utilities.
Here is the way to install them for a Ubuntu image. This step is specific to
Ubuntu distributions.

```bash
apt update
apt install fio iperf iperf3 socat stress cpuid tpm2-tools
```

### Remove counterproductive packages

* snapd:

This prevents snapd from trying to mount squashfs filesystem when the kernel
might not support it. This might be the case when the image is used with direct
kernel boot. This step is specific to Ubuntu distributions.

* pollinate:

Remove this package which can fail and lead to the SSH daemon failing to start.
See #2113 for details.

```bash
apt remove --purge snapd pollinate
```


### Cleanup the image

Leave no trace in the image before unmounting its content.

```bash
umount /dev/pts
umount /proc
history -c
exit
umount /mnt/etc/resolv.conf
umount /mnt
```

### Rename the image

Renaming is important to identify this is a modified image.

```bash
mv focal-server-cloudimg-amd64.raw focal-server-cloudimg-amd64-custom-$(date "+%Y%m%d")-0.raw
```

The `-0` is the revision and is only necessary to change if multiple images are
updated on the same day.

### Create QCOW2 from RAW

Last step is to create the QCOW2 image back from the modified image.

```bash
qemu-img convert -p -f raw -O qcow2 focal-server-cloudimg-amd64-custom-$(date "+%Y%m%d")-0.raw focal-server-cloudimg-amd64-custom-$(date "+%Y%m%d")-0.qcow2
```

## Switch CI to use the new image

### Upload to Azure storage

The next step is to update both images (QCOW2 and RAW) stored as part of the
Azure storage account, replacing them with the newly created ones. This will
make these new images available from the integration tests. This is usually
achieved through the web interface.

### Update integration tests

Last step is about updating the integration tests to work with this new image.
The key point is to identify where the Linux filesystem partition is located,
as we might need to update the direct kernel boot command line, replacing
`/dev/vda1` with the appropriate partition number.

Update all references to the previous image name to the new one.

## NVIDIA image for VFIO baremetal CI

Here we are going to describe how to create a cloud image that contains the
necessary NVIDIA drivers for our VFIO baremetal CI.

### Download base image

We usually start from one of the custom cloud image we have previously created
but we can use a stock cloud image as well.

```bash
wget https://cloud-hypervisor.azureedge.net/jammy-server-cloudimg-amd64-custom-20230119-0.raw
mv jammy-server-cloudimg-amd64-custom-20230119-0.raw jammy-server-cloudimg-amd64-nvidia.raw
```

### Extend the image size

The NVIDIA drivers consume lots of space, which is why we must resize the image
before we proceed any further.

```bash
qemu-img resize jammy-server-cloudimg-amd64-nvidia.raw 5G
```

### Resize the partition

We use `parted` for fixing the GPT after the image was resized, as well as for
resizing the `Linux` partition.

```bash
sudo parted jammy-server-cloudimg-amd64-nvidia.raw

(parted) print
Warning: Not all of the space available to jammy-server-cloudimg-amd64-nvidia.raw
appears to be used, you can fix the GPT to use all of the space (an extra 5873664
blocks) or continue with the current setting?
Fix/Ignore? Fix
Model:  (file)
Disk jammy-server-cloudimg-amd64-nvidia.raw: 5369MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags:

Number  Start   End     Size    File system  Name  Flags
14      1049kB  5243kB  4194kB                     bios_grub
15      5243kB  116MB   111MB   fat32              boot, esp
 1      116MB   2361MB  2245MB  ext4

(parted) resizepart 1 5369MB
(parted) print
Model:  (file)
Disk jammy-server-cloudimg-amd64-nvidia.raw: 5369MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags:

Number  Start   End     Size    File system  Name  Flags
14      1049kB  5243kB  4194kB                     bios_grub
15      5243kB  116MB   111MB   fat32              boot, esp
 1      116MB   5369MB  5252MB  ext4

(parted) quit
```

### Create a macvtap interface

Rely on the following [documentation](docs/macvtap-bridge.md) to set up a
macvtap interface to provide your VM with proper connectivity.

### Boot the image

It is particularly important to boot with a `cloud-init` disk attached to the
VM as it will automatically resize the Linux `ext4` filesystem based on the
partition that we have previously resized.

```bash
./cloud-hypervisor \
	--kernel hypervisor-fw  \
	--disk path=focal-server-cloudimg-amd64-nvidia.raw path=/tmp/ubuntu-cloudinit.img \
	--cpus boot=4 \
	--memory size=4G \
	--net fd=3,mac=$mac 3<>$"$tapdevice"
```
	
### Bring up connectivity

If your network has a DHCP server, run the following from your VM

```bash
sudo dhclient
```

But if that's not the case, let's give it an IP manually (the IP addresses
depend on your actual network) and set the DNS server IP address as well.

```bash
sudo ip addr add 192.168.2.10/24 dev ens4
sudo ip link set up dev ens4
sudo ip route add default via 192.168.2.1
sudo resolvectl dns ens4 8.8.8.8
```

#### Check connectivity and update the image

```bash
sudo apt update
sudo apt upgrade
```

### Install NVIDIA drivers

The following steps and commands are referenced from the
[NVIDIA official documentation](https://docs.nvidia.com/datacenter/tesla/tesla-installation-notes/index.html#ubuntu-lts)
about Tesla compute cards.

```bash
distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g')
wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.0-1_all.deb
sudo dpkg -i cuda-keyring_1.0-1_all.deb
sudo apt-key del 7fa2af80
sudo apt update
sudo apt -y install cuda-drivers
```

### Check the `nvidia-smi` tool

Quickly validate that you can find and run the `nvidia-smi` command from your
VM. At this point it should fail given no NVIDIA card has been passed through
the VM, therefore no NVIDIA driver is loaded.

### Workaround LA57 reboot issue

Add `reboot=a` to `GRUB_CMDLINE_LINUX` in `etc/default/grub` so that the VM
will be booted with the ACPI reboot type. This resolves a reboot issue when
running on 5-level paging systems.

```bash
sudo vim /etc/default/grub
sudo update-grub
sudo reboot
```

### Remove previous logins

Since our integration tests rely on past logins to count the number of reboots,
we must ensure to clear the list.

```bash
>/var/log/lastlog
>/var/log/wtmp
>/var/log/btmp
```

### Clear history

```
history -c
rm /home/cloud/.bash_history
```

### Reset cloud-init

This is mandatory as we want `cloud-init` provisioning to work again when a new
VM will be booted with this image.

```
sudo cloud-init clean
```