load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "tracer",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:libc",
        "@crates//:log",
        "@crates//:once_cell",
        "@crates//:serde",
        "@crates//:serde_json",
    ],
)
