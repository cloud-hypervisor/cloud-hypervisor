#!/bin/bash
# Build cloud-hypervisor with Profile-Guided Optimization (PGO).
#
# PGO uses runtime profiling data to guide compiler optimizations.
# QEMU reported 5-15% improvement with PGO on hot paths. This script
# automates the three-phase PGO build process for cloud-hypervisor.
#
# Usage:
#   ./scripts/build-pgo.sh              # Phase 1: instrumented build
#   # ... run your workload ...
#   SKIP_PHASE1=1 ./scripts/build-pgo.sh  # Phase 3: optimized build
#
# Requirements:
#   - llvm-tools component: rustup component add llvm-tools
#   - For BOLT (optional): llvm-bolt from your distro's LLVM package

set -euo pipefail

PROFILE_DIR="${PROFILE_DIR:-/tmp/ch-pgo-profiles}"
OUTPUT_DIR="${OUTPUT_DIR:-target/pgo}"

if [ "${SKIP_PHASE1:-}" != "1" ]; then
    echo "=== Phase 1: Instrumented build ==="
    rm -rf "$PROFILE_DIR"
    mkdir -p "$PROFILE_DIR" "$OUTPUT_DIR"

    RUSTFLAGS="-Cprofile-generate=$PROFILE_DIR" \
        cargo build --release --target-dir "$OUTPUT_DIR/instrumented"

    BINARY="$OUTPUT_DIR/instrumented/release/cloud-hypervisor"
    echo ""
    echo "Instrumented binary: $BINARY"
    echo ""
    echo "Run it with a representative workload (boot VM, drive network"
    echo "traffic, disk I/O, then shut down). Profiling data writes to:"
    echo "  $PROFILE_DIR/"
    echo ""
    echo "After training, rebuild with: SKIP_PHASE1=1 $0"
    exit 0
fi

echo "=== Phase 2: Merge profiling data ==="
PROFDATA=$(find "$(rustc --print sysroot)" -name llvm-profdata 2>/dev/null | head -1)
if [ -z "$PROFDATA" ]; then
    PROFDATA=$(command -v llvm-profdata 2>/dev/null || true)
fi
if [ -z "$PROFDATA" ]; then
    echo "Error: llvm-profdata not found. Install with: rustup component add llvm-tools"
    exit 1
fi

"$PROFDATA" merge -o "$PROFILE_DIR/merged.profdata" "$PROFILE_DIR"

echo "=== Phase 3: Optimized build ==="
RUSTFLAGS="-Cprofile-use=$PROFILE_DIR/merged.profdata" \
    cargo build --release --target-dir "$OUTPUT_DIR/optimized"

echo ""
echo "PGO-optimized binary: $OUTPUT_DIR/optimized/release/cloud-hypervisor"
echo ""
echo "Compare against the regular release build:"
echo "  ls -la target/release/cloud-hypervisor"
echo "  ls -la $OUTPUT_DIR/optimized/release/cloud-hypervisor"
