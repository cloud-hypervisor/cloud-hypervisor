load("@bazel_skylib//lib:selects.bzl", "selects")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

CLOUD_HYPERVISOR_ARM_TARGET_CPUS = (
    "@platforms//cpu:aarch64",
)

CLOUD_HYPERVISOR_X86_TARGET_CPUS = (
    "@platforms//cpu:x86_64",
)

rust_library(
    name = "hypervisor",
    srcs = [
        "src/arch/aarch64/gic.rs",
        "src/arch/aarch64/mod.rs",
        "src/arch/emulator/mod.rs",
        "src/arch/mod.rs",
        "src/cpu.rs",
        "src/device.rs",
        "src/hypervisor.rs",
        "src/kvm/mod.rs",
        "src/lib.rs",
        "src/vm.rs",
    ] + selects.with_or({
        CLOUD_HYPERVISOR_ARM_TARGET_CPUS: [
            "src/kvm/aarch64/gic/dist_regs.rs",
            "src/kvm/aarch64/gic/icc_regs.rs",
            "src/kvm/aarch64/gic/mod.rs",
            "src/kvm/aarch64/gic/redist_regs.rs",
            "src/kvm/aarch64/mod.rs",
        ],
        CLOUD_HYPERVISOR_X86_TARGET_CPUS: [
            "src/arch/x86/gdt.rs",
            "src/arch/x86/mod.rs",
            "src/arch/x86/msr_index.rs",
            "src/arch/x86/regs.rs",
            "src/kvm/x86_64/mod.rs",
            "src/kvm/x86_64/sev.rs",
        ],
    }),
    crate_features = ["kvm"],
    proc_macro_deps = [
        "@crates//:concat-idents",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:kvm-bindings",
        "@crates//:kvm-ioctls",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:serde_with",
        "@crates//:thiserror",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
        "@crates//:igvm_defs",
        "@vfio//crates/vfio-ioctls",
    ],
)

rust_test(
    name = "hypervisor_test",
    srcs = [
        "src/arch/aarch64/gic.rs",
        "src/arch/aarch64/mod.rs",
        "src/arch/emulator/mod.rs",
        "src/arch/mod.rs",
        "src/cpu.rs",
        "src/device.rs",
        "src/hypervisor.rs",
        "src/kvm/mod.rs",
        "src/lib.rs",
        "src/vm.rs",
    ] + selects.with_or({
        CLOUD_HYPERVISOR_ARM_TARGET_CPUS: [
            "src/kvm/aarch64/gic/dist_regs.rs",
            "src/kvm/aarch64/gic/icc_regs.rs",
            "src/kvm/aarch64/gic/mod.rs",
            "src/kvm/aarch64/gic/redist_regs.rs",
            "src/kvm/aarch64/mod.rs",
        ],
        CLOUD_HYPERVISOR_X86_TARGET_CPUS: [
            "src/arch/x86/gdt.rs",
            "src/arch/x86/mod.rs",
            "src/arch/x86/msr_index.rs",
            "src/arch/x86/regs.rs",
            "src/kvm/x86_64/mod.rs",
            "src/kvm/x86_64/sev.rs",
        ],
    }),
    crate_features = ["kvm"],
    proc_macro_deps = [
        "@crates//:concat-idents",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:anyhow",
        "@crates//:byteorder",
        "@crates//:kvm-bindings",
        "@crates//:kvm-ioctls",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:serde",
        "@crates//:serde_with",
        "@crates//:igvm_defs",
        "@crates//:thiserror",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
        "@vfio//crates/vfio-ioctls",
    ],
)
