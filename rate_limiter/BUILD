load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

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
        "@crates//:vmm-sys-util",
    ],
)

rust_test(
    name = "rate_limiter_test",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:epoll",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:thiserror",
        "@crates//:vmm-sys-util",
    ],
)
