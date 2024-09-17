load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "pci",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    crate_features = ["kvm"],
    deps = [
        "//hypervisor",
        "//vm-allocator",
        "//vm-device",
        "//vm-migration",
        "@vfio//crates/vfio-ioctls",
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:vfio-bindings",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
        "@vfio-user//:vfio-user",
    ],
)


rust_test(
    name = "pci_test",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    crate_features = ["kvm"],
    deps = [
        "//hypervisor",
        "//vm-allocator",
        "//vm-device",
        "//vm-migration",
        "@vfio//crates/vfio-ioctls",
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:vfio-bindings",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
        "@vfio-user//:vfio-user",
    ],
)
