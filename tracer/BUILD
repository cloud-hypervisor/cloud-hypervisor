load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tracer",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@cloud-hypervisor_crate_index//:libc",
        "@cloud-hypervisor_crate_index//:log",
        "@cloud-hypervisor_crate_index//:once_cell",
        "@cloud-hypervisor_crate_index//:serde",
        "@cloud-hypervisor_crate_index//:serde_json"
        ],
)