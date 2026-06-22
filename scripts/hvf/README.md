# Capturing a real arm64 KVM snapshot for the Hypervisor.framework port

The macOS Hypervisor.framework (HVF) backend's KVM→HVF translator
(`hypervisor::hvf::translate`) needs a **real** cloud-hypervisor arm64 snapshot,
taken under KVM, to validate against — both the per-vCPU registers
(`VcpuKvmState`) and the GICv3 state (`Gicv3ItsState { dist, rdist, icc,
gicd_ctlr }`). cloud-hypervisor serializes all of it into the snapshot's
`state.json`.

A snapshot can only be **produced** on a host with real `/dev/kvm` on arm64.
There are two ways to get one.

## Option A — entirely on an Apple M3+ Mac (recommended)

Apple added hardware **nested virtualization** on M3 (and later) chips, exposed
by Virtualization.framework on macOS 15+. That lets a Linux VM on the Mac expose
`/dev/kvm`, so cloud-hypervisor can run inside it and snapshot a guest — no cloud
box, no cost.

```sh
scripts/hvf/capture-on-mac.sh
```

This:
1. checks you are on an M3+ Mac running macOS 15+,
2. installs [Lima](https://lima-vm.io) via Homebrew if needed,
3. starts `lima-arm-kvm.yaml` (a `vmType: vz` guest with
   `nestedVirtualization: true`) and confirms nested `/dev/kvm`,
4. runs `capture-arm-snapshot.sh` inside it, and
5. copies the snapshot back to `./ch-arm-snapshot` on the Mac.

Set `KEEP_VM=0` to stop the Lima VM afterwards. The Lima VM is reusable; the
downloads are cached.

> Requires Apple **M3 or later**. M1/M2 have no nested virtualization — the
> script detects this and points you at Option B.

## Option B — a cloud ARM bare-metal box (fallback)

Use any arm64 host with real `/dev/kvm`: an AWS Graviton `c7g.metal` /
`m7g.metal`, an Oracle `BM.Standard.A1.160`, or any ARM `*.metal`. Regular ARM
cloud *VMs* (Graviton non-metal, Azure Dpsv5, GCP T2A, Hetzner CAX, …) do **not**
expose `/dev/kvm` and will not work.

```sh
# on the bare-metal ARM host:
scp scripts/hvf/capture-arm-snapshot.sh user@host:/tmp/
ssh user@host 'bash /tmp/capture-arm-snapshot.sh'
# then copy ./ch-arm-snapshot/ch-arm-snapshot.tar.zst back
```

A `c7g.metal` spot instance for ~20 minutes costs roughly a dollar.

## What you get

```
ch-arm-snapshot/
  snapshot/                 full cloud-hypervisor snapshot
    state.json              vCPU VcpuKvmState + GIC Gicv3ItsState (the fixture)
    config.json             VM config
    memory-ranges …         guest RAM (large; not needed by the translator)
  state.json                copy of the above, for convenience
  ch-arm-snapshot.tar.zst   packaged snapshot
```

`state.json` is the artifact the translator consumes. It is small enough to
commit as a test fixture under `hypervisor/tests/data/` so future iteration is
fully offline on the Mac.

## Tunables

Both scripts honour environment variables, e.g. `GUEST_CPUS`, `GUEST_MEM_MB`,
`CH_VERSION`, `IMG_URL`, `OUT_DIR`, `BOOT_TIMEOUT`. See the CONFIG block at the
top of `capture-arm-snapshot.sh`.
