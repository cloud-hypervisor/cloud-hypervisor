# Contributing to kvm-bindings

## Dependencies

### Bindgen
The bindings are currently generated using
[bindgen](https://crates.io/crates/bindgen) version 0.46.0:
```bash
cargo install bindgen --vers 0.46.0
```

### Linux Kernel
Generating bindings depends on the Linux kernel, so you need to have the
repository on your machine:

```bash
git clone https://github.com/torvalds/linux.git
```

## Add a new architecture
When adding a new architecture, the bindings must be generated for all existing
versions for consistency reasons.

### Example for arm64 and version 4.14 and 4.20

For this example we assume that you have both linux and kvm-bindings
repositories in your root.

```bash
# Step 1: Crate a new module using the name of the architecture in src/
cd kvm-bindings
mkdir src/arm64
cd ~

# linux is the repository that you cloned at the previous step.
cd linux
# Step 2: Checkout the version you want to generate the bindings for.
git checkout v4.14

# Step 3: Generate the bindings.
# This will generate the headers for the targeted architecture and place them
# in the user specified directory. In this case, we generate them in the
# arm64_v4_20_headers directory.
make headers_install ARCH=arm64 INSTALL_HDR_PATH=arm64_v4_20_headers
cd arm64_v4_20_headers
bindgen include/linux/kvm.h -o bindings_v4_20_0.rs \
  --with-derive-default
  --with-derive-partialeq
  -- -Iinclude
cd ~

# Step 4: Copy the generated file to the arm64 module.
cp linux/arm64_v4_20_headers/bindings_v4_20_0.rs
```

Steps 2, 3 and 4 must be repeated for each of the existing KVM versions. Don't
forget to change the name of the bindings file using the appropriate version.

Now that we have the bindings generated, we can copy the module file from
one of the existing modules as this is only changed when a new version is
added.

```bash
cp arm/mod.rs arm64/
```

Also, you will need to add the new architecture to `kvm-bindings/lib.rs`.

# Future Improvements
All the above steps are scriptable, so in the next iteration I will add a
script to generate the bindings.