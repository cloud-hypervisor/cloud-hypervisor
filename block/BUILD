load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "block",
    srcs = glob([
        "src/*.rs",
        "src/qcow/*.rs",
        "src/vhdx/*.rs",
    ]),
    proc_macro_deps = [
        "@crates//:remain",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//vm-virtio",
        "@crates//:byteorder",
        "@crates//:crc-any",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:smallvec",
        "@crates//:thiserror",
        "@crates//:uuid",
        "@crates//:virtio-bindings",
        "@crates//:virtio-queue",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)

rust_test(
    name = "block_test",
    size = "small",
    srcs = glob([
        "src/*.rs",
        "src/qcow/*.rs",
        "src/vhdx/*.rs",
    ]),
    proc_macro_deps = [
        "@crates//:remain",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//vm-virtio",
        "@crates//:byteorder",
        "@crates//:crc-any",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:smallvec",
        "@crates//:thiserror",
        "@crates//:uuid",
        "@crates//:virtio-bindings",
        "@crates//:virtio-queue",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)
