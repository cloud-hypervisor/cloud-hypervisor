load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "block",
    srcs = glob(["src/*.rs", "src/qcow/*.rs", "src/vhdx/*.rs"]),
    visibility = ["//visibility:public"],
    proc_macro_deps = [
        "@crates//:remain",
    ],
    deps = [
        "//vm-virtio",
        "@crates//:vmm-sys-util",
        "@crates//:thiserror",
        "@crates//:byteorder",
        "@crates//:crc-any",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:smallvec",
        "@crates//:uuid",
        "@crates//:virtio-bindings",
        "@crates//:virtio-queue",
        "@crates//:vm-memory"
        ],
)