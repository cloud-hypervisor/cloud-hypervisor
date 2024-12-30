#!/bin/bash
set -e

FORM_BASE="/var/lib/form"
UBUNTU_VERSION="22.04"

echo "Checking for required tools..."
if ! command -v qemu-img &> /dev/null; then
    echo "Installing qemu-utils for image conversion..."
    sudo apt-get update
    sudo apt-get install -y qemu-utils cloud-image-utils
fi

echo "Creating directory structure..."
sudo mkdir -p "$FORM_BASE"/{kernel,images,cloud-init,working}
sudo mkdir -p "$FORM_BASE/images/ubuntu/$UBUNTU_VERSION"

echo "Downloading and converting Ubuntu $UBUNTU_VERSION cloud image..."
cd "$FORM_BASE/images/ubuntu/$UBUNTU_VERSION"
if [ ! -f "disk.raw" ]; then
    TEMP_IMG="ubuntu-$UBUNTU_VERSION-server-cloudimg-amd64.img"
    sudo wget "https://cloud-images.ubuntu.com/releases/$UBUNTU_VERSION/release/$TEMP_IMG"
    echo "Converting image to raw format..."
    sudo qemu-img convert -O raw "$TEMP_IMG" disk.raw
    sudo rm "$TEMP_IMG"
    echo "Raw image conversion complete"
fi

echo "Downloading Ubuntu kernel..."
cd "$FORM_BASE/kernel"
if [ ! -f "vmlinuz" ]; then
    sudo wget -O vmlinuz "https://cloud-images.ubuntu.com/releases/$UBUNTU_VERSION/release/unpacked/ubuntu-$UBUNTU_VERSION-server-cloudimg-amd64-vmlinuz-generic"
fi

echo "Setting permissions..."
sudo chown -R root:root "$FORM_BASE"
sudo chmod -R 755 "$FORM_BASE"

echo "Setup complete! Raw disk image and kernel are ready for use."
