workspace(name = "hats-cloud-hypervisor")

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.76.0",
        "nightly/2024-02-01",
    ],
)

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies(bootstrap = True)

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

# Stash packages used by rust code in a repository.
crates_repository(
    name = "cloud-hypervisor_crate_index",
    cargo_lockfile = "//:Cargo.bazel.lock",
    lockfile = "//:cargo-bazel-lock.json",
    packages = {
        "vmm-sys-util": crate.spec(version = "0.12.1"),
        "thiserror": crate.spec(
            version = "*",
        ),
        "remain": crate.spec(
            version = "*",
        ),
        "byteorder": crate.spec(
            version = "*",
        ),
        "anyhow": crate.spec(
            version = "*",
        ),
        "crc-any": crate.spec(
            version = "*",
        ),
        "libc": crate.spec(
            version = "*",
        ),
        "log": crate.spec(
            version = "*",
        ),
        "serde": crate.spec(
            version = "*",
            features = ["derive"],
        ),
        "getrandom": crate.spec(
            version = "*",
        ),
        "smallvec": crate.spec(
            version = "*",
        ),
        "flume": crate.spec(
            version = "*",
        ),
        "once_cell": crate.spec(
            version = "*",
        ),
        "serde_json": crate.spec(
            version = "*",
        ),
        "epoll": crate.spec(
            version = "*",
        ),
        "uuid": crate.spec(
            version = "*",
            features = ["getrandom", "rng", "std", "v4"],
        ),
        "virtio-bindings": crate.spec(
            version = "*",
        ),
        "virtio-queue": crate.spec(
            version = "*",
        ),
        "vm-memory": crate.spec(
            version = "*",
            features = ["arc-swap", "backend-atomic", "backend-mmap", "backend-bitmap"],
        ),
    },
)

load("@cloud-hypervisor_crate_index//:defs.bzl", hats_crate_repositories = "crate_repositories")

hats_crate_repositories()