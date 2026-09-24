#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$BENCHMARK_DIR/.." && pwd)
ASSET_DIR=${ASSET_DIR:-$BENCHMARK_DIR/assets}
ASSET_CATALOG=$REPO_ROOT/scripts/test_assets.yaml

command -v curl >/dev/null || {
    echo "curl is required" >&2
    exit 1
}

download_asset() {
    local filename=$1
    local url checksum
    url=$(awk -v filename="$filename" '
        $1 == "-" && $2 == "filename:" { selected = ($3 == filename) }
        selected && $1 == "url:" { print $2; exit }
    ' "$ASSET_CATALOG")
    checksum=$(awk -v filename="$filename" '
        $1 == "-" && $2 == "filename:" { selected = ($3 == filename) }
        selected && $1 == "sha1:" { print $2; exit }
    ' "$ASSET_CATALOG")
    [[ -n "$url" && -n "$checksum" ]] || {
        echo "Asset metadata not found for $filename" >&2
        exit 1
    }

    mkdir -p "$ASSET_DIR"
    echo "Downloading $filename"
    curl --fail --location --retry 3 --continue-at - \
        --output "$ASSET_DIR/$filename" "$url"
    printf '%s  %s\n' "$checksum" "$ASSET_DIR/$filename" | sha1sum --check -
}

download_asset vmlinux-x86_64
download_asset jammy-server-cloudimg-amd64-custom-20241017-0.qcow2

cat <<EOF
Assets are ready. Start the example VM with:

KERNEL_PATH=$ASSET_DIR/vmlinux-x86_64 \\
DISK_PATH=$ASSET_DIR/jammy-server-cloudimg-amd64-custom-20241017-0.qcow2 \\
  ./benchmark/source-vm.sh start -- --net tap=tap0,mac=12:34:56:78:90:ab
EOF