# Code coverage

LLVM provides a set of tools to collect code coverage data and present the data
in human-consumable forms.

## Building a suitable binary

The compiler flag to generate code coverage data has been stabilized since Rust
1.60.

An instrumented binary can be built with the following command:

```shell
cargo clean && RUSTFLAGS='-C instrument-coverage' cargo build
```

Using either `debug` or `release` profile is fine. You will need to adjust
the path for some commands.

## Running the binary

Run the binary as you normally would. When the process exits, you will see
files with the prefix `profraw`.

Multiple runs of the same binary will produce multiple `profraw` files.

The more diverse the runs are, the better. Try to exercise different features
as much as possible.

## Combining raw data

Raw data files can be combined with `llvm-profdata`.

```shell
rustup component add llvm-tools-preview
# Assuming profraw files reside in the current directory and its children directories
find . -name '*.profraw' -exec llvm-profdata merge -sparse {} -o coverage.profdata \;
```

A file named `coverage.profdata` will be generated.

## Generating HTML files for human consumption

This can be done either with LLVM or `grcov`.

Here is an example using grcov.

```shell
cargo install grcov
# Assuming the profdata file is in the top level directory of the Cloud Hypervisor repository
grcov . --binary-path ./target/x86_64-unknown-linux-gnu/release -s . -t html --branch --ignore-not-existing -o coverage-html-output/
```

You can then open the `index.html` file under coverage-html-output to see the
results.

## Notes on running the in-tree integration tests and unit tests

Please set RUSTFLAGS the same way while invoking `dev_cli.sh`. The script will
pass RUSTFLAGS to the container.

Since the `profraw` files are generated from within the container, the file
paths embedded in the data files are going to be different. It is easier to do
the data processing from within the container if you don't want to fight the
tool chain.

```shell
# Set env to enable code coverage
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="ch-%p-%m.profraw"

# Run unit tests
scripts/dev_cli.sh tests --unit --libc gnu

# Run integration tests
scripts/dev_cli.sh tests --integration --libc gnu
scripts/dev_cli.sh tests --integration-live-migration --libc gnu

# Export code coverage report
scripts/dev_cli.sh tests --coverage -- -- html
```
