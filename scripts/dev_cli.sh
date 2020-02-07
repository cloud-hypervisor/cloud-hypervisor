#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Copyright © 2020 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

CLI_NAME="Cloud Hypervisor"

CTR_IMAGE_TAG="cloudhypervisor/dev"
CTR_IMAGE_VERSION="v1"
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
CTR_CLH_CARGO_TARGET="${CTR_CLH_ROOT_DIR}/build/cargo_target"
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

cmd_help() {
    echo ""
    echo "Cloud Hypervisor $(basename $0)"
    echo "Usage: $(basename $0) <command> [<command args>]"
    echo ""
    echo "Available commands:"
    echo ""
    echo "    build [--debug|--release] [-- [<cargo args>]]"
    echo "        Build the Cloud Hypervisor binaries."
    echo "        --debug               Build the debug binaries. This is the default."
    echo "        --release             Build the release binaries."
    echo ""
    echo "    tests [--unit|--cargo|--all] [-- [<cargo test args>]]"
    echo "        Run the Cloud Hypervisor tests."
    echo "        --unit               Run the unit tests."
    echo "        --cargo              Run the cargo tests."
    echo "        --integration        Run the integration tests."
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

    while [ $# -gt 0 ]; do
	case "$1" in
            "-h"|"--help")  { cmd_help; exit 1;     } ;;
            "--debug")      { build="debug";      } ;;
            "--release")    { build="release";    } ;;
            "--")           { shift; break;         } ;;
            *)
		die "Unknown build argument: $1. Please use --help for help."
		;;
	esac
	shift
    done

    cargo_args=("$@")
    [ $build = "release" ] && cargo_args+=("--release")

    $DOCKER_RUNTIME run \
	   --workdir "$CTR_CLH_ROOT_DIR" \
	   --rm \
	   --volume /dev:/dev \
	   --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	   "$CTR_IMAGE" \
	   cargo build \
	         --target-dir "$CTR_CLH_CARGO_TARGET" \
	         "${cargo_args[@]}"

    ret=$?

    # If `cargo build` was successful, let's copy the binaries to a more
    # accessible location.
    [ $ret -eq 0 ] && {
        cargo_bin_dir="$CLH_CARGO_TARGET/$build"
        say "Binaries placed under $cargo_bin_dir"
    }
}

cmd_clean() {
    cargo_args=("$@")

    $DOCKER_RUNTIME run \
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

    while [ $# -gt 0 ]; do
	case "$1" in
            "-h"|"--help")    { cmd_help; exit 1;     } ;;
            "--unit")         { unit=true;      } ;;
            "--cargo")        { cargo=true;    } ;;
	    "--integration")  { integration=true;    } ;;
	    "--all")          { cargo=true; unit=true; integration=true;  } ;;
            "--")             { shift; break;         } ;;
            *)
		die "Unknown tests argument: $1. Please use --help for help."
		;;
	esac
	shift
    done

    if [ "$unit" = true ] ;  then
	say "Running unit tests..."
	$DOCKER_RUNTIME run \
	       --workdir "$CTR_CLH_ROOT_DIR" \
	       --rm \
	       --privileged \
	       --volume /dev:/dev \
	       --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	       "$CTR_IMAGE" \
	       ./scripts/run_unit_tests.sh "$@"
    fi

    if [ "$cargo" = true ] ;  then
	say "Running cargo tests..."
	$DOCKER_RUNTIME run \
	       --workdir "$CTR_CLH_ROOT_DIR" \
	       --rm \
	       --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	       "$CTR_IMAGE" \
	       ./scripts/run_cargo_tests.sh
    fi

    if [ "$integration" = true ] ;  then
	say "Running integration tests..."
	$DOCKER_RUNTIME run \
	       --workdir "$CTR_CLH_ROOT_DIR" \
	       --rm \
	       --privileged \
	       --mount type=tmpfs,destination=/tmp \
	       --volume /dev:/dev \
	       --volume "$CLH_ROOT_DIR:$CTR_CLH_ROOT_DIR" \
	       --volume "$CLH_INTEGRATION_WORKLOADS:$CTR_CLH_INTEGRATION_WORKLOADS" \
	       "$CTR_IMAGE" \
	       ./scripts/run_integration_tests.sh "$@"
    fi
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

$cmd "$@"
