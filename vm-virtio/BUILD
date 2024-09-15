load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "vm-virtio",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@cloud-hypervisor_crate_index//:virtio-queue",
        "@cloud-hypervisor_crate_index//:vm-memory"
        ],
)