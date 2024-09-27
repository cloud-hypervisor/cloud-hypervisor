load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "vm-migration",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:anyhow",
        "@crates//:serde",
        "@crates//:serde_json",
        "@crates//:thiserror",
        "@crates//:vm-memory",
    ],
)
