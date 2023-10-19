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
# Get a shell
./scripts/dev_cli.sh shell

# Install llvm-tools-preview for llvm-profdata
rustup component add llvm-tools-preview
# Merge data files by using the following command
find . -name '*.profraw' -exec `rustc --print sysroot`/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata merge -sparse {} -o coverage.profdata \;

# As of writing, the container has Rust 1.67.1. It is too old for grcov.
rustup install stable
cargo +stable install grcov
# Run grcov as usual
grcov . --binary-path ./target/x86_64-unknown-linux-gnu/release -s . -t html --branch --ignore-not-existing -o coverage-html-output/
```
