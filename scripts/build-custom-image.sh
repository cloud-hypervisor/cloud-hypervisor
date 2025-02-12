#!/bin/bash
# shellcheck disable=SC2046,SC2086,SC2155

set -ex

#VFIO_CUSTOM_IMAGE="-vfio"

mkdir -p custom-image
pushd custom-image || exit
wget -N https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
export IMAGE_NAME_BASE=jammy-server-cloudimg-amd64
qemu-img convert -p -f qcow2 -O raw $IMAGE_NAME_BASE.img $IMAGE_NAME_BASE.raw
if [ -n "$VFIO_CUSTOM_IMAGE" ]; then
    qemu-img resize -f raw "$IMAGE_NAME_BASE.raw" 5G
    sudo sgdisk -e "$IMAGE_NAME_BASE.raw"
    sudo parted "$IMAGE_NAME_BASE.raw" resizepart 1 5369MB
fi
mkdir -p mnt
export ROOTFS=/dev/mapper/$(sudo kpartx -v -a $IMAGE_NAME_BASE.raw | grep "p1 " | cut -f 3 -d " ")
if [ -n "$VFIO_CUSTOM_IMAGE" ]; then
    sudo e2fsck -f "$ROOTFS"
    sudo resize2fs "$ROOTFS"
fi
sudo mount $ROOTFS mnt
sudo mv mnt/etc/resolv.conf mnt/etc/resolv.conf.backup

touch extra_commands

if [ -n "$VFIO_CUSTOM_IMAGE" ]; then
    cat >extra_commands <<EOF
    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
    sudo dpkg -i cuda-keyring_1.1-1_all.deb
    sudo apt-get update
    sudo apt-get -y install cuda-drivers
EOF
fi

cat >script <<EOF
#!/bin/bash
set -xe
mount -t proc proc /proc
mount -t devpts devpts /dev/pts
echo "nameserver 1.1.1.1" > /etc/resolv.conf
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y fio iperf iperf3 socat stress cpuid tpm2-tools kexec-tools
apt remove -y --purge snapd pollinate
source extra_commands
umount /dev/pts
umount /proc
history -c
exit
EOF

sudo cp script extra_commands mnt
sudo chmod +x mnt/script
sudo chroot mnt ./script
sudo mv mnt/etc/resolv.conf.backup mnt/etc/resolv.conf
sudo umount mnt
sudo kpartx -d $IMAGE_NAME_BASE.raw
cp $IMAGE_NAME_BASE.raw $IMAGE_NAME_BASE-custom$VFIO_CUSTOM_IMAGE-$(date "+%Y%m%d")-0.raw
qemu-img convert -p -f raw -O qcow2 $IMAGE_NAME_BASE-custom$VFIO_CUSTOM_IMAGE-$(date "+%Y%m%d")-0.raw $IMAGE_NAME_BASE-custom$VFIO_CUSTOM_IMAGE-$(date "+%Y%m%d")-0.qcow2
popd || exit
