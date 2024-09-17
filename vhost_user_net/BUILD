load("@rules_rust//rust:defs.bzl", "rust_library", "rust_binary")

rust_library(
    name = "vhost_user_net",
    srcs = ["src/lib.rs"],
    visibility = ["//visibility:public"],
    deps = [
        "//net_util",
        "//option_parser",
        "@crates//:epoll",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:vhost",
        "@crates//:vhost-user-backend",
        "@crates//:virtio-bindings",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)

rust_binary(
    name = "bin/vhost_user_net",
    srcs = ["src/main.rs"],
    visibility = ["//visibility:public"],
    deps = [
        ":vhost_user_net",
        "@crates//:clap",
        "@crates//:env_logger",
    ],
)
