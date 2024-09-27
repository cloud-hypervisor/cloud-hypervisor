load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "net_util",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "//net_gen",
        "//rate_limiter",
        "//vm-virtio",
        "@crates//:epoll",
        "@crates//:getrandom",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:virtio-bindings",
        "@crates//:virtio-queue",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)
