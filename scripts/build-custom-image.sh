#!/bin/bash
# shellcheck disable=SC2046,SC2086,SC2155

set -ex

# IMAGE_ARCH=amd64|arm64
IMAGE_ARCH=${IMAGE_ARCH:-amd64}
#VFIO_CUSTOM_IMAGE="-vfio"
# NVIDIA_CUSTOM_IMAGE="-nvidia" with IMAGE_ARCH=arm64
# Ubuntu's NVIDIA kernel, the open NVIDIA driver and DCGM from NVIDIA's
# repository
#NVIDIA_CUSTOM_IMAGE="-nvidia"
CUSTOM_IMAGE_VARIANT="$VFIO_CUSTOM_IMAGE$NVIDIA_CUSTOM_IMAGE"

if [ -n "$NVIDIA_CUSTOM_IMAGE" ] && [ "$IMAGE_ARCH" != arm64 ]; then
    echo "NVIDIA_CUSTOM_IMAGE needs IMAGE_ARCH=arm64" >&2
    exit 1
fi
if [ -n "$NVIDIA_CUSTOM_IMAGE" ] && [ -n "$VFIO_CUSTOM_IMAGE" ]; then
    echo "NVIDIA_CUSTOM_IMAGE and VFIO_CUSTOM_IMAGE are two images" >&2
    exit 1
fi

# Unmount and unmap what the script set up, and exit with the failing
# step's status (the clean-up commands would otherwise replace it).
cleanup() {
    local rc=$?
    set +e

    for m in mnt/dev/pts mnt/proc mnt/dev mnt/boot/efi mnt/boot mnt; do
        if mountpoint -q "$m" 2>/dev/null; then
            sudo umount "$m"
        fi
    done
    if [ -e "$IMAGE_NAME_BASE.raw" ]; then
        sudo kpartx -d "$IMAGE_NAME_BASE.raw"
    fi
    exit "$rc"
}
trap cleanup ERR

mkdir -p custom-image
pushd custom-image || exit
wget -N https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-$IMAGE_ARCH.img
export IMAGE_NAME_BASE=noble-server-cloudimg-$IMAGE_ARCH
qemu-img convert -p -f qcow2 -O raw $IMAGE_NAME_BASE.img $IMAGE_NAME_BASE.raw
if [ -n "$NVIDIA_CUSTOM_IMAGE" ]; then
    # The driver, DCGM and its CUDA libraries need the room.
    qemu-img resize -f raw "$IMAGE_NAME_BASE.raw" 20G
    sudo sgdisk -e "$IMAGE_NAME_BASE.raw"
    sudo parted "$IMAGE_NAME_BASE.raw" resizepart 1 21474MB
elif [ -n "$CUSTOM_IMAGE_VARIANT" ]; then
    qemu-img resize -f raw "$IMAGE_NAME_BASE.raw" 10G
    sudo sgdisk -e "$IMAGE_NAME_BASE.raw"
    sudo parted "$IMAGE_NAME_BASE.raw" resizepart 1 10737MB
fi
mkdir -p mnt
export ROOTFS=/dev/mapper/$(sudo kpartx -v -a $IMAGE_NAME_BASE.raw | grep "p1 " | cut -f 3 -d " ")
if [ -n "$CUSTOM_IMAGE_VARIANT" ]; then
    # 1 means errors were corrected.
    sudo e2fsck -fy "$ROOTFS" || [ $? -le 1 ]
    sudo resize2fs "$ROOTFS"
fi
sudo mount $ROOTFS mnt
if [ -n "$NVIDIA_CUSTOM_IMAGE" ]; then
    # The kernel install writes the image's /boot partition
    sudo mount "${ROOTFS%p1}p16" mnt/boot
    # and its grub hook the EFI partition; both need the host's /dev.
    sudo mount "${ROOTFS%p1}p15" mnt/boot/efi
    # A slave bind, so that what the chroot mounts under /dev (devpts) does
    # not propagate to the host.
    sudo mount --bind /dev mnt/dev
    sudo mount --make-rslave mnt/dev
fi
sudo mv mnt/etc/resolv.conf mnt/etc/resolv.conf.backup

touch extra_commands

if [ -n "$VFIO_CUSTOM_IMAGE" ]; then
    cat >extra_commands <<EOF
    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
    sudo dpkg -i cuda-keyring_1.1-1_all.deb
    sudo apt-get update
    sudo apt-get -y install cuda-drivers
EOF
fi

if [ -n "$NVIDIA_CUSTOM_IMAGE" ]; then
    cat >extra_commands <<EOF
    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/sbsa/cuda-keyring_1.1-1_all.deb
    sudo dpkg -i cuda-keyring_1.1-1_all.deb
    sudo apt-get update
    echo 'GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT memhp_default_state=online_movable"' | sudo tee /etc/default/grub.d/99-gpu-memhp.cfg
    sudo apt-get -y install linux-nvidia
    sudo apt-get -y purge 'linux-image-[0-9].*-generic' 'linux-modules-[0-9].*-generic' linux-generic linux-image-generic linux-virtual linux-image-virtual
    sudo apt-get -y autoremove --purge
    sudo apt-get -y install nvidia-driver-580-server-open
    sudo apt-get -y install datacenter-gpu-manager-4-core datacenter-gpu-manager-4-cuda13
    rm cuda-keyring_1.1-1_all.deb
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
apt install -y fio iperf iperf3 socat stress $([ "$IMAGE_ARCH" = amd64 ] && echo cpuid) tpm2-tools kexec-tools
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
if [ -n "$NVIDIA_CUSTOM_IMAGE" ]; then
    sudo umount mnt/dev mnt/boot/efi mnt/boot
fi
sudo umount mnt
sudo kpartx -d $IMAGE_NAME_BASE.raw
cp $IMAGE_NAME_BASE.raw $IMAGE_NAME_BASE-custom$CUSTOM_IMAGE_VARIANT-$(date "+%Y%m%d")-0.raw
qemu-img convert -p -f raw -O qcow2 $IMAGE_NAME_BASE-custom$CUSTOM_IMAGE_VARIANT-$(date "+%Y%m%d")-0.raw $IMAGE_NAME_BASE-custom$CUSTOM_IMAGE_VARIANT-$(date "+%Y%m%d")-0.qcow2
popd || exit
