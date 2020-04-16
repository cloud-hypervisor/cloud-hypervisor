#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Copyright © 2020 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

CLI_NAME="Cloud Hypervisor"

CTR_IMAGE_TAG="cloudhypervisor/dev"
CTR_IMAGE_VERSION="v2"
CTR_IMAGE="${CTR_IMAGE_TAG}:${CTR_IMAGE_VERSION}"

DOCKER_RUNTIME="docker"

# Host paths
CLH_SCRIPTS_DIR=$(cd "$(dirname "$0")" && pwd)
CLH_ROOT_DIR=$(cd "${CLH_SCRIPTS_DIR}/.." && pwd)
CLH_BUILD_DIR="${CLH_ROOT_DIR}/build"
CLH_CARGO_TARGET="${CLH_BUILD_DIR}/cargo_target"
CLH_DOCKERFILE="${CLH_SCRIPTS_DIR}/../resources/Dockerfile"
CLH_CTR_BUILD_DIR="/tmp/cloud-hypervisor/ctr-build"
CLH_INTEGRATION_WORKLOADS="${HOME}/workloads"

# Container paths
CTR_CLH_ROOT_DIR="/cloud-hypervisor"
CTR_CLH_CARGO_BUILT_DIR="${CTR_CLH_ROOT_DIR}/build"
CTR_CLH_CARGO_TARGET="${CTR_CLH_CARGO_BUILT_DIR}/cargo_target"
CTR_CLH_INTEGRATION_WORKLOADS="/root/workloads"

# Cargo paths
# Full path to the cargo registry dir on the host. This appears on the host
# because we want to persist the cargo registry across container invocations.
# Otherwise, any rust crates from crates.io would be downloaded again each time
# we build or test.
CARGO_REGISTRY_DIR="${CLH_BUILD_DIR}/cargo_registry"

# Full path to the cargo git registry on the host. This serves the same purpose
# as CARGO_REGISTRY_DIR, for crates downloaded from GitHub repos instead of
# crates.io.
CARGO_GIT_REGISTRY_DIR="${CLH_BUILD_DIR}/cargo_git_registry"

# Full path to the cargo target dir on the host.
CARGO_TARGET_DIR="${CLH_BUILD_DIR}/cargo_target"

# Send a decorated message to stdout, followed by a new line
#
say() {
    [ -t 1 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 2)[$CLI_NAME]$(tput sgr0) $*" \
        || echo "[$CLI_NAME] $*"
}

# Send a decorated message to stdout, without a trailing new line
#
say_noln() {
    [ -t 1 ] && [ -n "$TERM" ] \
        && echo -n "$(tput setaf 2)[$CLI_NAME]$(tput sgr0) $*" \
        || echo "[$CLI_NAME] $*"
}

# Send a text message to stderr
#
say_err() {
    [ -t 2 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 1)[$CLI_NAME] $*$(tput sgr0)" 1>&2 \
        || echo "[$CLI_NAME] $*" 1>&2
}

# Send a warning-highlighted text to stdout
say_warn() {
    [ -t 1 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 3)[$CLI_NAME] $*$(tput sgr0)" \
        || echo "[$CLI_NAME] $*"
}

# Exit with an error message and (optional) code
# Usage: die [-c <error code>] <error message>
#
die() {
    code=1
    [[ "$1" = "-c" ]] && {
        code="$2"
        shift 2
    }
    say_err "$@"
    exit $code
}

# Exit with an error message if the last exit code is not 0
#
ok_or_die() {
    code=$?
    [[ $code -eq 0 ]] || die -c $code "$@"
}

# Make sure the build/ dirs are available. Exit if we can't create them.
# Upon returning from this call, the caller can be certain the build/ dirs exist.
#
ensure_build_dir() {
    for dir in "$CLH_BUILD_DIR" \
		   "$CLH_INTEGRATION_WORKLOADS" \
		   "$CLH_CTR_BUILD_DIR" \
		   "$CARGO_TARGET_DIR" \
		   "$CARGO_REGISTRY_DIR" \
		   "$CARGO_GIT_REGISTRY_DIR"; do
        mkdir -p "$dir" || die "Error: cannot create dir $dir"
        [ -x "$dir" ] && [ -w "$dir" ] || \
            {
                say "Wrong permissions for $dir. Attempting to fix them ..."
                chmod +x+w "$dir"
            } || \
            die "Error: wrong permissions for $dir. Should be +x+w"
    done
}

# Make sure we're using the latest dev container, by just pulling it.
ensure_latest_ctr() {
    $DOCKER_RUNTIME pull "$CTR_IMAGE"

    ok_or_die "Error pulling container image. Aborting."
}

# Fix main directory permissions after a container ran as root.
# Since the container ran as root, any files it creates will be owned by root.
# This fixes that by recursively changing the ownership of /cloud-hypervisor to the
# current user.
#
fix_dir_perms() {
    # Yes, running Docker to get elevated privileges, just to chown some files
    # is a dirty hack.
    $DOCKER_RUNTIME run \
	--workdir "$CTR_CLH_ROOT_DIR" \
	   --rm \
	   --volume /dev:/dev \
	   --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	   "$CTR_IMAGE" \
           chown -R "$(id -u):$(id -g)" "$CTR_CLH_ROOT_DIR"

    return $1
}

cmd_help() {
    echo ""
    echo "Cloud Hypervisor $(basename $0)"
    echo "Usage: $(basename $0) <command> [<command args>]"
    echo ""
    echo "Available commands:"
    echo ""
    echo "    build [--debug|--release] [--libc musl|gnu] [-- [<cargo args>]]"
    echo "        Build the Cloud Hypervisor binaries."
    echo "        --debug               Build the debug binaries. This is the default."
    echo "        --release             Build the release binaries."
    echo "        --libc                Select the C library Cloud Hypervisor will be built against. Default is gnu"
    echo ""
    echo "    tests [--unit|--cargo|--all] [--libc musl|gnu] [-- [<cargo test args>]]"
    echo "        Run the Cloud Hypervisor tests."
    echo "        --unit               Run the unit tests."
    echo "        --cargo              Run the cargo tests."
    echo "        --integration        Run the integration tests."
    echo "        --libc               Select the C library Cloud Hypervisor will be built against. Default is gnu"
    echo "        --all                Run all tests."
    echo ""
    echo "    build-container [--type]"
    echo "        Build the Cloud Hypervisor container."
    echo "        --dev                Build dev container. This is the default."
    echo ""
    echo "    clean [<cargo args>]]"
    echo "        Remove the Cloud Hypervisor artifacts."
    echo ""
    echo "    help"
    echo "        Display this help message."
    echo ""
}

cmd_build() {
    build="debug"
    libc="gnu"

    while [ $# -gt 0 ]; do
	case "$1" in
            "-h"|"--help")  { cmd_help; exit 1;     } ;;
            "--debug")      { build="debug";      } ;;
            "--release")    { build="release";    } ;;
            "--libc")
                shift
                [[ "$1" =~ ^(musl|gnu)$ ]] || \
                    die "Invalid libc: $1. Valid options are \"musl\" and \"gnu\"."
                libc="$1"
                ;;
            "--")           { shift; break;         } ;;
            *)
		die "Unknown build argument: $1. Please use --help for help."
		;;
	esac
	shift
    done

    target="$(uname -m)-unknown-linux-${libc}"

    cargo_args=("$@")
    [ $build = "release" ] && cargo_args+=("--release")
    cargo_args+=(--target "$target")
    [ $(uname -m) = "aarch64" ] && cargo_args+=("--no-default-features")
    [ $(uname -m) = "aarch64" ] && cargo_args+=(--features "mmio")

    rustflags=""
    if [ $(uname -m) = "aarch64" ] && [ $libc = "musl" ] ; then
        rustflags="-C link-arg=-lgcc"
    fi

    $DOCKER_RUNTIME run \
	   --user "$(id -u):$(id -g)" \
	   --workdir "$CTR_CLH_ROOT_DIR" \
	   --rm \
	   --volume /dev:/dev \
	   --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	   --env RUSTFLAGS="$rustflags" \
	   "$CTR_IMAGE" \
	   cargo build \
	         --target-dir "$CTR_CLH_CARGO_TARGET" \
	         "${cargo_args[@]}" && say "Binaries placed under $CLH_CARGO_TARGET/$target/$build"
}

cmd_clean() {
    cargo_args=("$@")

    $DOCKER_RUNTIME run \
	   --user "$(id -u):$(id -g)" \
	   --workdir "$CTR_CLH_ROOT_DIR" \
	   --rm \
	   --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	   "$CTR_IMAGE" \
	   cargo clean \
	         --target-dir "$CTR_CLH_CARGO_TARGET" \
	         "${cargo_args[@]}"
    }

cmd_tests() {
    unit=false
    cargo=false
    integration=false
    libc="gnu"

    while [ $# -gt 0 ]; do
	case "$1" in
            "-h"|"--help")           { cmd_help; exit 1;     } ;;
            "--unit")                { unit=true;      } ;;
            "--cargo")               { cargo=true;    } ;;
            "--integration")         { integration=true;    } ;;
            "--libc")
                shift
                [[ "$1" =~ ^(musl|gnu)$ ]] || \
                    die "Invalid libc: $1. Valid options are \"musl\" and \"gnu\"."
                libc="$1"
                ;;
	    "--all")                 { cargo=true; unit=true; integration=true;  } ;;
            "--")                    { shift; break;         } ;;
            *)
		die "Unknown tests argument: $1. Please use --help for help."
		;;
	esac
	shift
    done

    target="$(uname -m)-unknown-linux-${libc}"
    cflags=""
    target_cc=""
    if [[ "$target" == "x86_64-unknown-linux-musl" ]]; then
	target_cc="musl-gcc"
	cflags="-I /usr/include/x86_64-linux-musl/ -idirafter /usr/include/"
    fi

    if [ "$unit" = true ] ;  then
	say "Running unit tests for $target..."
	$DOCKER_RUNTIME run \
	       --workdir "$CTR_CLH_ROOT_DIR" \
	       --rm \
	       --device /dev/kvm \
	       --device /dev/net/tun \
	       --cap-add net_admin \
	       --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	       --env BUILD_TARGET="$target" \
	       --env CFLAGS="$cflags" \
	       --env TARGET_CC="$target_cc" \
	       "$CTR_IMAGE" \
	       ./scripts/run_unit_tests.sh "$@" || fix_dir_perms $? || exit $?
    fi

    if [ "$cargo" = true ] ;  then
	say "Running cargo tests..."
	$DOCKER_RUNTIME run \
	       --workdir "$CTR_CLH_ROOT_DIR" \
	       --rm \
	       --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	       "$CTR_IMAGE" \
	       ./scripts/run_cargo_tests.sh || fix_dir_perms $? || exit $?
    fi

    if [ "$integration" = true ] ;  then
	say "Running integration tests for $target..."
	$DOCKER_RUNTIME run \
	       --workdir "$CTR_CLH_ROOT_DIR" \
	       --rm \
	       --privileged \
	       --security-opt seccomp=unconfined \
	       --ipc=host \
	       --net=host \
	       --mount type=tmpfs,destination=/tmp \
	       --volume /dev:/dev \
	       --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	       --volume "$CLH_INTEGRATION_WORKLOADS:$CTR_CLH_INTEGRATION_WORKLOADS" \
	       --env USER="root" \
	       --env BUILD_TARGET="$target" \
	       --env CFLAGS="$cflags" \
	       --env TARGET_CC="$target_cc" \
	       "$CTR_IMAGE" \
	       ./scripts/run_integration_tests.sh "$@" || fix_dir_perms $? || exit $?
    fi

    fix_dir_perms $?
}

cmd_build-container() {
    container_type="dev"

    while [ $# -gt 0 ]; do
	case "$1" in
            "-h"|"--help")  { cmd_help; exit 1;     } ;;
            "--dev")        { container_type="dev"; } ;;
            "--")           { shift; break;         } ;;
            *)
		die "Unknown build-container argument: $1. Please use --help for help."
		;;
	esac
	shift
    done

    BUILD_DIR=/tmp/cloud-hypervisor/container/

    mkdir -p $BUILD_DIR
    cp $CLH_DOCKERFILE $BUILD_DIR

    $DOCKER_RUNTIME build \
	   --target $container_type \
	   -t $CTR_IMAGE \
	   -f $BUILD_DIR/Dockerfile \
	   --build-arg TARGETARCH="$(uname -m)" \
	   $BUILD_DIR
}

# Parse main command line args.
#
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)              { cmd_help; exit 1;     } ;;
        -y|--unattended)        { OPT_UNATTENDED=true;  } ;;
        -*)
            die "Unknown arg: $1. Please use \`$0 help\` for help."
            ;;
        *)
            break
            ;;
    esac
    shift
done

# $1 is now a command name. Check if it is a valid command and, if so,
# run it.
#
declare -f "cmd_$1" > /dev/null
ok_or_die "Unknown command: $1. Please use \`$0 help\` for help."

cmd=cmd_$1
shift

ensure_build_dir
if [ $(uname -m) = "x86_64" ]; then
    ensure_latest_ctr
fi

# Before a public image for AArch64 ready, we build the container if needed.
if [ $(uname -m) = "aarch64" ]; then
    cmd_build-container
fi

$cmd "$@"
