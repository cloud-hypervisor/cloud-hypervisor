#!/bin/bash
set -x

sudo apt install -y libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf git make dpkg-dev libmnl-dev pkg-config
sudo sed -i -- 's/# deb-src/deb-src/g' /etc/apt/sources.list
sudo apt update
apt-get source linux-image-unsigned-`uname -r`
pushd linux-azure*/drivers/vdpa/vdpa_sim/
cat <<'EOF' > Makefile
# SPDX-License-Identifier: GPL-2.0
obj-m += vdpa_sim.o
obj-m += vdpa_sim_net.o
obj-m += vdpa_sim_blk.o
EOF
make -C /lib/modules/`uname -r`/build M=$PWD
sudo make -C /lib/modules/`uname -r`/build M=$PWD modules_install
popd
sudo depmod -a
sudo modprobe vdpa
sudo modprobe vhost_vdpa
sudo modprobe vdpa_sim
sudo modprobe vdpa_sim_blk
sudo modprobe vdpa_sim_net
# After the Jenkins builder are moved to Ubuntu 22.04, manually building and
# installing iproute2/vdpa won't be required.
# Tracked by: https://github.com/cloud-hypervisor/cloud-hypervisor/issues/3862
git clone https://github.com/shemminger/iproute2.git
pushd iproute2
./configure 
make -j
sudo make install
popd
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