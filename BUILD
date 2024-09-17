licenses(["notice"])

exports_files(["LICENSE"])

load("@rules_rust//rust:defs.bzl", "rust_binary")

CLOUD_HYPERVISOR_RUSTC_ENV = {
    "BUILD_VERSION": "nightly/2024-02-01",
}

rust_binary(
    name = "bin/cloud-hypervisor",
    srcs = ["src/main.rs"],
    crate_features = ["kvm"],
    rustc_env = CLOUD_HYPERVISOR_RUSTC_ENV,
    proc_macro_deps = [
        "@crates//:clap_derive",
    ],
    deps = [
        "//api_client",
        "//event_monitor",
        "//hypervisor",
        "//option_parser",
        "//tpm",
        "//tracer",
        "//vmm",
        "@crates//:anyhow",
        "@crates//:clap",
        "@crates//:epoll",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:seccompiler",
        "@crates//:serde_json",
        "@crates//:signal-hook",
        "@crates//:thiserror",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)

rust_binary(
    name = "bin/ch-remote",
    srcs = ["src/bin/ch-remote.rs"],
    crate_features = [
        "kvm",
    ],
    rustc_env = CLOUD_HYPERVISOR_RUSTC_ENV,
    visibility = ["//visibility:public"],
    deps = [
        "//api_client",
        "//event_monitor",
        "//hypervisor",
        "//option_parser",
        "//tpm",
        "//tracer",
        "//vmm",
        "@crates//:anyhow",
        "@crates//:clap",
        "@crates//:epoll",
        "@crates//:libc",
        "@crates//:log",
        "@crates//:seccompiler",
        "@crates//:serde_json",
        "@crates//:signal-hook",
        "@crates//:thiserror",
        "@crates//:vm-memory",
        "@crates//:vmm-sys-util",
    ],
)
