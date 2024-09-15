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
        "@cloud-hypervisor_crate_index//:epoll",
        "@cloud-hypervisor_crate_index//:getrandom",
        "@cloud-hypervisor_crate_index//:libc",
        "@cloud-hypervisor_crate_index//:serde",
        "@cloud-hypervisor_crate_index//:log",
        "@cloud-hypervisor_crate_index//:thiserror",
        "@cloud-hypervisor_crate_index//:virtio-bindings",
        "@cloud-hypervisor_crate_index//:virtio-queue",
        "@cloud-hypervisor_crate_index//:vm-memory",
        "@cloud-hypervisor_crate_index//:vmm-sys-util"
        ],
)
