#!/usr/bin/env bash
# Build, codesign with the hypervisor entitlement, then run hvf-vmm.
# HVF requires the com.apple.security.hypervisor entitlement; ad-hoc signing
# (codesign --sign -) is sufficient for local development on Apple Silicon.
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="${PROFILE:-release}"
if [ "$PROFILE" = "release" ]; then
    cargo build --release
    BIN="target/release/hvf-vmm"
else
    cargo build
    BIN="target/debug/hvf-vmm"
fi

codesign --sign - --entitlements entitlements.plist --force --options runtime "$BIN" >/dev/null 2>&1
echo "[run] signed $BIN"
exec "$BIN" "$@"
