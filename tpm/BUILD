load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

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
        "@crates//:byteorder",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:thiserror",
        "@crates//:vmm-sys-util",
    ],
)

rust_test(
    name = "tpm_test",
    size = "small",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "//net_gen",
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:thiserror",
        "@crates//:vmm-sys-util",
    ],
)
