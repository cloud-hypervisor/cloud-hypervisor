load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "net_gen",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@cloud-hypervisor_crate_index//:vmm-sys-util"
        ],
)