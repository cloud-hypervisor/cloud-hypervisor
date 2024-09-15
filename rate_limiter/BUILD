load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "rate_limiter",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@cloud-hypervisor_crate_index//:epoll",
        "@cloud-hypervisor_crate_index//:libc",
        "@cloud-hypervisor_crate_index//:log",
        "@cloud-hypervisor_crate_index//:thiserror",
        "@cloud-hypervisor_crate_index//:vmm-sys-util"
        ],
)