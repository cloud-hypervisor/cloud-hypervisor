# Cloud Hypervisor vendoring

The `cloud-hypervisor` build relies on having all dependencies locally vendored,
for several reasons:

1. Reproducible builds: Separate builds from the same cloud-hypervisor git
   commit will build against exactly the same set of dependencies.

1. Network isolated builds: Vendoring allows us to build cloud-hypervisor
   in a network isolated environment. All dependencies are locally fetched
   and thus `cargo` will not try to fetch crates from external repositories.

1. Simplified custom dependencies: When having to deal with custom, temporary
   dependencies, vendoring allows for a centralized and simple way of overriding
   an existing dependency with a custom one.

## Workflow

The `cargo vendor` tool does 2 things:

1. It generates vendored copies of all dependencies that the project crates
   describe through their `Cargo.toml` files.

1. It creates a `.cargo/config` amendment to force cargo builds to use the
   vendored copies instead of the external ones.

It's important to note that `cargo vendor` can not force a dependency version
or revision. All dependencies are described through the project crates
`Cargo.toml` files.

As a consequence, vendoring and dependency revision pinning are 2 separate
things, and `cargo vendor` only handles the former.

All the `cloud-hypervisor` vendored dependencies are under the `vendor`
directory. For all intents and purposes the `vendor` directory is read-only and
should not be manually modified.

The sections below describe a few vendoring use cases:

### Overriding a crates.io dependency

For overriding a `crates.io` crate with a local or remote crate, we first need
to modify the project's top-level `Cargo.toml` file.

For example, if we want to switch from the `crates.io` `kvm-ioctls` package to
a forked one containing some specific feature or fix we would add the following
lines to the project top-level `Cargo.toml` file:

```toml
[patch.crates-io]
kvm-ioctls = { git = "https://github.com/sboeuf/kvm-ioctls", branch = "kvm_signal_msi" }

```

Then we need to vendor that change:

```shell
cargo vendor --relative-path --no-merge-sources ./vendor > .cargo/config
```

### pinning a git dependency

Some crates may depend on non published crates, that are developed and
maintained in some git repository.

Let's take the `vm-memory` crate as one example. It is a `rust-vmm` crate that
is not yet published in `crates.io`. Several `cloud-hypervisor` crates depend
on it. Provided that none of those dependent crates rely on a specific branch
or revision of the `vm-memory` crate, we may want to pin our project to the
crate revision `281b8bd6cd2927f7a65130194b203a1c2b0ad2e3`.

We need to describe that revision pin and then vendor it. First we need to add
the following lines to the project top-level `Cargo.toml`:

```toml
[dependencies.vm-memory]
git = "https://github.com/rust-vmm/vm-memory"
rev = "281b8bd6cd2927f7a65130194b203a1c2b0ad2e3"
```

And then vendor that change:

```shell
cargo vendor --relative-path --no-merge-sources ./vendor > .cargo/config
```
