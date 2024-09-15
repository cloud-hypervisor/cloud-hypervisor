load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "block",
    srcs = glob(["src/*.rs", "src/qcow/*.rs", "src/vhdx/*.rs"]),
    visibility = ["//visibility:public"],
    proc_macro_deps = [
        "@cloud-hypervisor_crate_index//:remain",
    ],
    deps = [
        "//vm-virtio",
        "@cloud-hypervisor_crate_index//:vmm-sys-util",
        "@cloud-hypervisor_crate_index//:thiserror",
        "@cloud-hypervisor_crate_index//:byteorder",
        "@cloud-hypervisor_crate_index//:crc-any",
        "@cloud-hypervisor_crate_index//:libc",
        "@cloud-hypervisor_crate_index//:log",
        "@cloud-hypervisor_crate_index//:serde",
        "@cloud-hypervisor_crate_index//:smallvec",
        "@cloud-hypervisor_crate_index//:uuid",
        "@cloud-hypervisor_crate_index//:virtio-bindings",
        "@cloud-hypervisor_crate_index//:virtio-queue",
        "@cloud-hypervisor_crate_index//:vm-memory"
        ],
)