load("@bazel_skylib//lib:selects.bzl", "selects")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

CLOUD_HYPERVISOR_ARM_TARGET_CPUS = (
    "@platforms//cpu:aarch64",
)

CLOUD_HYPERVISOR_X86_TARGET_CPUS = (
    "@platforms//cpu:x86_64",
)

rust_library(
    name = "arch",
    srcs = [
        "src/lib.rs",
    ] + selects.with_or({
        CLOUD_HYPERVISOR_ARM_TARGET_CPUS: [
            "src/aarch64/fdt.rs",
            "src/aarch64/layout.rs",
            "src/aarch64/mod.rs",
            "src/aarch64/regs.rs",
            "src/aarch64/uefi.rs",
        ],
        CLOUD_HYPERVISOR_X86_TARGET_CPUS: [
            "src/x86_64/interrupts.rs",
            "src/x86_64/layout.rs",
            "src/x86_64/mod.rs",
            "src/x86_64/mpspec.rs",
            "src/x86_64/mptable.rs",
            "src/x86_64/regs.rs",
            "src/x86_64/smbios.rs",
            "src/x86_64/tdx/mod.rs",
        ],
    }),
    visibility = ["//visibility:public"],
    deps = [
        "//hypervisor",
        "//vm-migration",
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:libc",
        "@crates//:linux-loader",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:uuid",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ] + selects.with_or({
        CLOUD_HYPERVISOR_ARM_TARGET_CPUS: [
            "@crates//:fdt",
            "@crates//:vm-fdt",
        ],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "arch_test",
    size = "small",
    srcs = [
        "src/lib.rs",
    ] + selects.with_or({
        CLOUD_HYPERVISOR_ARM_TARGET_CPUS: [
            "src/aarch64/fdt.rs",
            "src/aarch64/layout.rs",
            "src/aarch64/mod.rs",
            "src/aarch64/regs.rs",
            "src/aarch64/uefi.rs",
        ],
        CLOUD_HYPERVISOR_X86_TARGET_CPUS: [
            "src/x86_64/interrupts.rs",
            "src/x86_64/layout.rs",
            "src/x86_64/mod.rs",
            "src/x86_64/mpspec.rs",
            "src/x86_64/mptable.rs",
            "src/x86_64/regs.rs",
            "src/x86_64/smbios.rs",
            "src/x86_64/tdx/mod.rs",
        ],
    }),
    visibility = ["//visibility:public"],
    deps = [
        "//hypervisor",
        "//vm-migration",
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:libc",
        "@crates//:linux-loader",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:thiserror",
        "@crates//:uuid",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ] + selects.with_or({
        CLOUD_HYPERVISOR_ARM_TARGET_CPUS: [
            "@crates//:fdt",
            "@crates//:vm-fdt",
        ],
        "//conditions:default": [],
    }),
)
