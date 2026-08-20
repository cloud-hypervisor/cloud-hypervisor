#!/usr/bin/env bash
set -x

install_vdpa_sim_modules_ubuntu() {
    sudo apt update
    sudo apt install -y linux-modules-extra-"$(uname -r)"
}

modprobe_modules() {
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
    install_vdpa_sim_modules_ubuntu
fi

modprobe_modules
prepare_vdpa
