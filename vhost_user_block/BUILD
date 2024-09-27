load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "vhost_user_block",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "//block",
        "//option_parser",
        "@crates//:epoll",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:vhost",
        "@crates//:vhost-user-backend",
        "@crates//:virtio-bindings",
        "@crates//:virtio-queue",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)

rust_binary(
    name = "bin/vhost_user_block",
    srcs = ["src/main.rs"],
    visibility = ["//visibility:public"],
    deps = [
        ":vhost_user_block",
        "@crates//:clap",
        "@crates//:env_logger",
    ],
)
