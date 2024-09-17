load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "vm-allocator",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "//arch",
        "@crates//:libc",
        "@crates//:vm-memory",
    ],
)

rust_test(
    name = "vm-allocator_test",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
    deps = [
        "//arch",
        "@crates//:libc",
        "@crates//:vm-memory",
    ],
)
