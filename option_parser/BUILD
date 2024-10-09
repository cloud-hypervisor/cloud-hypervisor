load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "option_parser",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
)

rust_test(
    name = "option_parser_test",
    size = "small",
    srcs = glob(["src/*.rs"]),
    visibility = ["//visibility:public"],
)
