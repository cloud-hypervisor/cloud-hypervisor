# Copyright © 2025 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# When changing this file don't forget to update the tag name in the
# .github/workflows/docker-image.yaml file if doing multiple per day

FROM ubuntu:24.04 AS dev

ARG TARGETARCH
ARG RUST_TOOLCHAIN="1.88.0"
ARG CLH_SRC_DIR="/cloud-hypervisor"
ARG CLH_BUILD_DIR="$CLH_SRC_DIR/build"
ARG CARGO_REGISTRY_DIR="$CLH_BUILD_DIR/cargo_registry"
ARG CARGO_GIT_REGISTRY_DIR="$CLH_BUILD_DIR/cargo_git_registry"

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=$CARGO_HOME
ENV PATH="$PATH:$CARGO_HOME/bin"
ENV DEBIAN_FRONTEND=noninteractive

# Install all CI dependencies
# DL3015 ignored cause not installing openvswitch-switch-dpdk recommended packages breaks ovs_dpdk test
# hadolint ignore=DL3008,DL3015
RUN apt-get update \
        && apt-get -yq upgrade \
        && apt-get install --no-install-recommends -yq \
        build-essential \
        bc \
        curl \
        wget \
        sudo \
        mtools \
        musl-tools \
        libssl-dev \
        pkg-config \
        flex \
        bison \
        libelf-dev \
        qemu-utils \
        libglib2.0-dev \
        libpixman-1-dev \
        libseccomp-dev \
        libcap-ng-dev \
        socat \
        dosfstools \
        cpio \
        python3 \
        python3-setuptools \
        ntfs-3g \
        uuid-dev \
        iperf3 \
        zip \
        git-core \
        dnsmasq \
        dmsetup \
        ca-certificates \
        unzip \
        iproute2 \
        dbus \
    && apt-get install openvswitch-switch-dpdk -yq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/log/*log  /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old

RUN update-alternatives --set ovs-vswitchd /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk

# hadolint ignore=DL3008
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        apt-get update \
        && apt-get -yq upgrade \
        && apt-get install --no-install-recommends -yq swtpm \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/* /var/log/*log  /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old; fi

# hadolint ignore=DL3008
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        # On AArch64, `setcap` binary should be installed via `libcap2-bin`.
        # The `setcap` binary is used in integration tests.
        # `libguestfs-tools` is used for modifying cloud image kernel, and it requires
        # kernel (any version) image in `/boot` and modules in `/lib/modules`.
        apt-get update \
        && apt-get -yq upgrade \
        && apt-get install --no-install-recommends -yq \
        libcap2-bin \
        libguestfs-tools \
        linux-image-generic \
        autotools-dev \
        autoconf \
        automake \
        perl \
        texinfo \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/* /var/log/*log  /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old; fi

# Fix the libssl-dev install
# hadolint ignore=SC2155
RUN export ARCH="$(uname -m)" \
    && cp /usr/include/"$ARCH"-linux-gnu/openssl/opensslconf.h /usr/include/openssl/
ENV X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/
ENV X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/
ENV AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu/
ENV AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu/
ENV OPENSSL_INCLUDE_DIR=/usr/include/

# Install the rust toolchain
# hadolint ignore=DL4006,SC2155
RUN export ARCH="$(uname -m)" \
    && nohup curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" \
    && rustup target add "$ARCH"-unknown-linux-musl --toolchain "$RUST_TOOLCHAIN" \
    && if [ "$TARGETARCH" = "amd64" ]; then \
        rustup toolchain add --profile minimal --force-non-host \
            $RUST_TOOLCHAIN-x86_64-unknown-linux-musl; fi \
    && if [ "$TARGETARCH" = "amd64" ]; then rustup component add rustfmt; fi \
    && if [ "$TARGETARCH" = "amd64" ]; then rustup component add clippy; fi \
    && rm -rf "$CARGO_HOME/registry" \
    && ln -s "$CARGO_REGISTRY_DIR" "$CARGO_HOME/registry" \
    && rm -rf "$CARGO_HOME/git" \
    && ln -s "$CARGO_GIT_REGISTRY_DIR" "$CARGO_HOME/git"

# Set the rust environment
# hadolint ignore=SC2016
RUN echo 'source $CARGO_HOME/env' >> "$HOME"/.bashrc \
    && mkdir "$HOME"/.cargo \
    && ln -s $CARGO_HOME/env "$HOME"/.cargo/env

# Allow pip to install packages system wide
# hadolint ignore=DL3003,SC2046
RUN rm /usr/lib/python3.12/EXTERNALLY-MANAGED \
        && git clone https://github.com/spdk/spdk \
        && cd spdk \
        && git checkout ef8bcce58f3f02b79c0619a297e4f17e81e62b24 \
        && git submodule update --init \
        && apt-get update \
        && ./scripts/pkgdep.sh \
        && apt-get clean \
        && ./configure --with-vfio-user \
        && if [ "$TARGETARCH" = "amd64" ]; then \
            make -j $(nproc) TARGET_ARCHITECTURE=skylake; \
        elif [ "$TARGETARCH" = "arm64" ]; then \
            make -j $(nproc) TARGET_ARCHITECTURE="armv8.2-a" DPDKBUILD_FLAGS="-Dplatform=generic"; \
        else \
            echo "Unsupported architecture: ${TARGETARCH}" && exit 1; \
        fi \
        && rm -rf /usr/local/bin/spdk-nvme \
        && mkdir /usr/local/bin/spdk-nvme \
        && cp -f ./build/bin/nvmf_tgt /usr/local/bin/spdk-nvme \
        && cp -f ./scripts/rpc.py /usr/local/bin/spdk-nvme \
        && cp -rf ./python/spdk/ /usr/local/bin/spdk-nvme \
        && cp -rf ./python /usr/local/bin \
        && cd .. && rm -rf spdk

# install ethr tool for performance tests
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    wget -nv https://github.com/microsoft/ethr/releases/latest/download/ethr_linux.zip \
    && unzip ethr_linux.zip \
    && cp ethr /usr/local/bin \
    && rm ethr_linux.zip; fi
