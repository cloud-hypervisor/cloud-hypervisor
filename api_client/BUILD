load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "api_client",
    srcs = ["src/lib.rs"],
    visibility = ["//visibility:public"],
    deps = [
        "@cloud-hypervisor_crate_index//:vmm-sys-util",
        "@cloud-hypervisor_crate_index//:thiserror"
        ],
)
