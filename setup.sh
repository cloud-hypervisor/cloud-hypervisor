#!/bin/bash
# SPDX-license-identifier: Apache-2.0
##############################################################################
# Copyright (c) 2019 Intel Corporation
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################

set -o errexit
set -o nounset
set -o pipefail

echo "Install dependencies..."
if ! $( cargo --version &>/dev/null); then
    curl https://sh.rustup.rs -sSf -o install_rust.sh
    chmod +x install_rust.sh
    ./install_rust.sh -y
    rm install_rust.sh
    export PATH=$PATH:$HOME/.cargo/bin
    sudo sed -i "s|^PATH=.*|PATH=\"$PATH\"|" /etc/environment
fi

# shellcheck disable=SC1091
source /etc/os-release || source /usr/lib/os-release
case ${ID,,} in
    *suse)
        sudo zypper install --no-confirm libcap-progs
    ;;
esac

cargo build --release
sudo mv ./target/release/cloud-hypervisor /usr/bin/
sudo setcap cap_net_admin+ep /usr/bin/cloud-hypervisor
