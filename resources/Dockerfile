FROM ubuntu:20.04 as dev

ARG TARGETARCH
ARG RUST_TOOLCHAIN="1.51.0"
ARG CLH_SRC_DIR="/cloud-hypervisor"
ARG CLH_BUILD_DIR="$CLH_SRC_DIR/build"
ARG CARGO_REGISTRY_DIR="$CLH_BUILD_DIR/cargo_registry"
ARG CARGO_GIT_REGISTRY_DIR="$CLH_BUILD_DIR/cargo_git_registry"

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=$CARGO_HOME
ENV PATH="$PATH:$CARGO_HOME/bin"

# Install all CI dependencies
RUN apt-get update \
	&& apt-get -yq upgrade \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -yq \
	build-essential \
	bc \
	docker.io \
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
	qemu-system \
	libglib2.0-dev \
	libpixman-1-dev \
	libseccomp-dev \
	libcap-ng-dev \
	socat \
	dosfstools \
	cpio \
	python \
	python3 \
	python3-setuptools \
	ntfs-3g \
	python3-distutils \
	uuid-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN if [ "$TARGETARCH" = "amd64" ]; then \
	apt-get update \
	&& apt-get -yq upgrade \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -yq gcc-multilib \
	&& apt-get clean \
    && rm -rf /var/lib/apt/lists/*;	fi

RUN if [ "$TARGETARCH" = "arm64" ]; then \
        # On AArch64, `setcap` binary should be installed via `libcap2-bin`.
        # The `setcap` binary is used in integration tests.
        apt-get update \
        && apt-get -yq upgrade \
        && DEBIAN_FRONTEND=noninteractive apt-get install -yq libcap2-bin \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*;	fi

# Fix the libssl-dev install
RUN export ARCH="$(uname -m)" \
    && cp /usr/include/$ARCH-linux-gnu/openssl/opensslconf.h /usr/include/openssl/
ENV X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/
ENV X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/
ENV AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu/
ENV AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu/
ENV OPENSSL_INCLUDE_DIR=/usr/include/

# Install the rust toolchain
RUN export ARCH="$(uname -m)" \
    && nohup curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" \
    && rustup target add $ARCH-unknown-linux-musl --toolchain "$RUST_TOOLCHAIN" \
    && if [ "$TARGETARCH" = "amd64" ]; then rustup toolchain add $RUST_TOOLCHAIN-x86_64-unknown-linux-musl; fi \
    && if [ "$TARGETARCH" = "amd64" ]; then rustup component add rustfmt; fi \
    && if [ "$TARGETARCH" = "amd64" ]; then rustup component add clippy; fi \
    && cargo install cargo-audit \
    && rm -rf "$CARGO_HOME/registry" \
    && ln -s "$CARGO_REGISTRY_DIR" "$CARGO_HOME/registry" \
    && rm -rf "$CARGO_HOME/git" \
    && ln -s "$CARGO_GIT_REGISTRY_DIR" "$CARGO_HOME/git"

# Set the rust environment
RUN echo 'source $CARGO_HOME/env' >> $HOME/.bashrc \
    && mkdir $HOME/.cargo \
    && ln -s $CARGO_HOME/env $HOME/.cargo/env
