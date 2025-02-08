# `cloud-hypervisor` debug IO ports

When running x86 guests, `cloud-hypervisor` provides different kinds of debug ports:

- [`0x80` debug port](https://web.archive.org/web/20211028033025/https://www.intel.com/content/www/us/en/support/articles/000005500/boards-and-kits.html)
- Debug console (by default at `0xe9`).
- Firmware debug port at `0x402`.

All of them can be used to trace user-defined guest events and all of them can
be used simultaneously.

## Debug Ports Overview

### `0x80` I/O port

Whenever the guest write one byte between `0x0` and `0xF` on this particular
I/O port, `cloud-hypervisor` will log and timestamp that event at the `debug`
log level.

It is up to the guest stack to decide when and what to write to the 0x80 port
in order to signal the host about specific events and have `cloud-hypervisor`
log it.

`cloud-hypervisor` defines several debug port code ranges that should be used
for debugging specific components of the guest software stack. When logging a
write of one of those codes to the debug port, `cloud-hypervisor` adds a
pre-defined string to the logs.

| Code Range       | Component  | Log string   |
| ---------------- | ---------- | ------------ |
| `0x00` to `0x1f` | Firmware   | `Firmware`   |
| `0x20` to `0x3f` | Bootloader | `Bootloader` |
| `0x40` to `0x5f` | Kernel     | `Kernel`     |
| `0x60` to `0x7f` | Userspace  | `Userspace`  |
| `0x80` to `0xff` | Custom     | `Custom`     |

One typical use case is guest boot time measurement and tracing. By writing
different values to the debug I/O port at different boot process steps, the
guest will have `cloud-hypervisor` generate timestamped logs of all those steps.
That provides a basic but convenient way of measuring not only the overall guest
boot time but all intermediate steps as well.

#### Logging

Assuming parts of the guest software stack have been instrumented to use the
`cloud-hypervisor` debug I/O port, we may want to gather the related logs.

To do so we need to start `cloud-hypervisor` with the right debug level
(`-vvv`). It is also recommended to have it log into a dedicated file in order
to easily grep for the tracing logs (e.g.
`--log-file /tmp/cloud-hypervisor.log`):

```
./target/debug/cloud-hypervisor \
    --kernel ~/rust-hypervisor-firmware/target/target/release/hypervisor-fw \
    --disk path=~/hypervisor/images/focal-server-cloudimg-amd64.raw \
    --cpus 4 \
    --memory size=1024M \
    --rng \
    --log-file /tmp/ch-fw.log \
    -vvv
```

After booting the guest, we then have to grep for the debug I/O port traces in
the log file:

```Shell
$ grep "Debug I/O port" /tmp/ch-fw.log
cloud-hypervisor: 19.762449ms: DEBUG:vmm/src/vm.rs:510 -- [Debug I/O port: Firmware code 0x0] 0.019004 seconds
cloud-hypervisor: 403.499628ms: DEBUG:vmm/src/vm.rs:510 -- [Debug I/O port: Firmware code 0x1] 0.402744 seconds
```

### Debug console port

The debug console is inspired by QEMU and Bochs, which have a similar feature.
By default, the I/O port `0xe9` is used. This port can be configured like a
console. Thus, it can print to a tty, a file, or a pty, for example.

### Firmware debug port

The firmware debug port is also a simple port that prints all bytes written to
it. The firmware debug port only prints to stdout.

## When do I need these ports?

The ports are on the one hand interesting for firmware or kernel developers, as
they provide an easy way to print debug information from within a guest.
Furthermore, you can patch "normal" software to measure certain events, such as
the boot time of a guest.

## Which port should I choose?

The `0x80` debug port and the port of the firmware debug device are always
available. The debug console must be activated via the command line, but
provides more configuration options.

You can use different ports for different aspect of your logging messages.
