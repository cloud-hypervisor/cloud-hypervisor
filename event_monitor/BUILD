load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "event_monitor",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "@crates//:flume",
        "@crates//:libc",
        "@crates//:once_cell",
        "@crates//:serde",
        "@crates//:serde_json",
    ],
)
