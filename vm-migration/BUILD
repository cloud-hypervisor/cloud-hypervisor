load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "vm-migration",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@cloud-hypervisor_crate_index//:anyhow",
        "@cloud-hypervisor_crate_index//:thiserror",
        "@cloud-hypervisor_crate_index//:vm-memory",
        "@cloud-hypervisor_crate_index//:serde",
        "@cloud-hypervisor_crate_index//:serde_json"
        ],
)
