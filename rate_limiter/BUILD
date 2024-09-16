load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "rate_limiter",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:epoll",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:thiserror",
        "@crates//:vmm-sys-util"
        ],
)