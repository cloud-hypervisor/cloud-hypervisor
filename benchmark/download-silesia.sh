#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASSET_DIR=${ASSET_DIR:-$BENCHMARK_DIR/assets}
SILESIA_PATH=${SILESIA_PATH:-$ASSET_DIR/silesia.tar}
SILESIA_URL=${SILESIA_URL:-https://sun.aei.polsl.pl/~sdeor/corpus/silesia.zip}
SILESIA_SHA256=${SILESIA_SHA256:-0626e25f45c0ffb5dc801f13b7c82a3b75743ba07e3a71835a41e3d9f63c77af}

for command_name in curl sha256sum tar unzip; do
    command -v "$command_name" >/dev/null || {
        echo "$command_name is required to prepare Silesia" >&2
        exit 1
    }
done

if [[ -f "$SILESIA_PATH" ]]; then
    echo "Silesia tar already exists: $SILESIA_PATH"
    exit 0
fi

working_dir=$(mktemp -d)
trap 'rm -rf "$working_dir"' EXIT
archive=$working_dir/silesia.zip
corpus_dir=$working_dir/corpus

echo "Downloading the Silesia corpus"
curl --fail --location --retry 3 --output "$archive" "$SILESIA_URL"
printf '%s  %s\n' "$SILESIA_SHA256" "$archive" | sha256sum --check -
mkdir -p "$corpus_dir" "$(dirname -- "$SILESIA_PATH")"
unzip -q "$archive" -d "$corpus_dir"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cf "$SILESIA_PATH" -C "$corpus_dir" .
echo "Silesia tar created: $SILESIA_PATH"