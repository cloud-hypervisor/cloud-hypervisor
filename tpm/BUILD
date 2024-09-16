load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tpm",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "//net_gen",
        "@crates//:anyhow",
        "@crates//:libc",
        "@crates//:byteorder",
        "@crates//:log",
        "@crates//:thiserror",
        "@crates//:vmm-sys-util"
        ],
)