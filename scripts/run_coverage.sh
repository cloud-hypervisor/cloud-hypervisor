#!/usr/bin/env bash

set -x

# shellcheck source=/dev/null
source "$HOME"/.cargo/env
source "$(dirname "$0")"/test-util.sh

PROJECT_DIR="/cloud-hypervisor"
SCRIPT_DIR="$PROJECT_DIR/scripts"
TARGET_DIR="$PROJECT_DIR/target"

pushd $PROJECT_DIR || exit

libc="gnu"
if [ -z "$BUILD_TARGET" ]; then
    BUILD_TARGET="$(uname -m)-unknown-linux-$libc"
fi

sudo apt -y install build-essential
# rustc >= 1.74
cargo install grcov || exit 1
rustup component add llvm-tools-preview || exit 1

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"

export LLVM_PROFILE_FILE="ch-%p-%m.profraw"
find . -type f -name 'ch*.profraw' -exec rm {} \;
rm default*.profraw

bash $SCRIPT_DIR/run_unit_tests.sh

bash $SCRIPT_DIR/run_integration_tests_x86_64.sh || exit 1

bash $SCRIPT_DIR/run_integration_tests_live_migration.sh || exit 1

rm "coverage.info"

grcov . -s . --binary-path "$TARGET_DIR/$BUILD_TARGET/release/" -t lcov --branch --ignore-not-existing -o "coverage.info"

# Generate HTML report
#OUTPUT_DIR="$TARGET_DIR/coverage"
#rm -rf $OUTPUT_DIR
#grcov . -s . --binary-path "$TARGET_DIR/$BUILD_TARGET/release/" -t html --branch --ignore-not-existing -o $OUTPUT_DIR

popd || exit 1