#!/bin/bash
#
# Copyright © 2025 Meta Platforms, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Write a cargo vendor config and exec the remaining arguments.
# Used inside the container where .cargo/ lives on a tmpfs.

VENDOR_CONFIG="build/cargo_vendor_config.toml"

if [ -f "$VENDOR_CONFIG" ]; then
    mkdir -p .cargo
    cp "$VENDOR_CONFIG" .cargo/config.toml
fi

exec "$@"
