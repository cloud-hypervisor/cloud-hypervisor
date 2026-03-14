#!/usr/bin/env bash
set -x

build_install_vdpa_sim_modules_ubuntu() {
    sudo apt install -y libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf git make dpkg-dev libmnl-dev pkg-config iproute2
    sudo sed -i -- 's/# deb-src/deb-src/g' /etc/apt/sources.list
    sudo apt update
    apt-get source linux-image-unsigned-"$(uname -r)"
    pushd linux-azure*/drivers/vdpa/vdpa_sim/ || exit
    # REUSE-IgnoreStart
    cat <<'EOF' >Makefile
# SPDX-License-Identifier: GPL-2.0
obj-m += vdpa_sim.o
obj-m += vdpa_sim_net.o
obj-m += vdpa_sim_blk.o
EOF
    # REUSE-IgnoreEnd
    make -C /lib/modules/"$(uname -r)"/build M="$PWD"
    sudo make -C /lib/modules/"$(uname -r)"/build M="$PWD" modules_install
    popd || exit
    sudo depmod -a
}

check_vdpa_sim_modules() {
    for module in $MODULES; do
        modinfo "$module" || {
            echo "Module $module is not installed. Please build and install it first."
            exit 1
        }
    done
}

modproobe_modules() {
    for module in $MODULES; do
        sudo modprobe "$module" || {
            echo "Failed to load module $module. Please check if it is installed correctly."
            exit 1
        }
    done
}

prepare_vdpa() {
    # Create /dev/vhost-vdpa-0
    sudo vdpa dev add name vdpa-blk1 mgmtdev vdpasim_blk
    # Create /dev/vhost-vdpa-1
    sudo vdpa dev add name vdpa-blk2 mgmtdev vdpasim_blk
    # Create /dev/vhost-vdpa-2
    sudo vdpa dev add name vdpa-net1 mgmtdev vdpasim_net
    sudo chmod 660 /dev/vhost-vdpa-0
    sudo chmod 660 /dev/vhost-vdpa-1
    sudo chmod 660 /dev/vhost-vdpa-2
    vdpa dev show -jp
}

MODULES="vdpa vhost_vdpa vdpa_sim vdpa_sim_blk vdpa_sim_net"
DISTRO_NAME="ubuntu"
if [[ -f /etc/lsb-release ]]; then
    DISTRO_NAME=$(grep DISTRIB_ID /etc/lsb-release | cut -d '=' -f 2)
    # Converts the value of the DISTRO_NAME variable to lowercase letters.
    DISTRO_NAME=$(echo "$DISTRO_NAME" | tr '[:upper:]' '[:lower:]')
    echo "Distribution Name: $DISTRO_NAME"
fi

if [[ "$DISTRO_NAME" == "ubuntu" ]]; then
    build_install_vdpa_sim_modules_ubuntu
fi
# For other distros, we assume the modules are already built and installed
# For Azure Linux, the modules are included in the kernel and should be available by default
check_vdpa_sim_modules

modproobe_modules

prepare_vdpa
