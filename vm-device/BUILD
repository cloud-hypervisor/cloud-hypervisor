load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "vm-device",
    srcs = glob([
        "src/*.rs",
        "src/**/*.rs",
    ]),
    crate_features = ["kvm"],
    visibility = ["//visibility:public"],
    deps = [
        "//hypervisor",
        "@crates//:anyhow",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
        "@vfio//crates/vfio-ioctls",
    ],
)

rust_test(
    name = "vm-device_test",
    srcs = glob([
        "src/*.rs",
        "src/**/*.rs",
    ]),
    crate_features = ["kvm"],
    visibility = ["//visibility:public"],
    deps = [
        "//hypervisor",
        "@crates//:anyhow",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
        "@vfio//crates/vfio-ioctls",
    ],
)
