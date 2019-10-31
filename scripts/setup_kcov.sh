#!/bin/bash

source $HOME/.cargo/env

cargo install cargo-kcov
cargo kcov --print-install-kcov-sh | sh
