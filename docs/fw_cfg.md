# Firmware Configuration (fw_cfg) Device

The `fw_cfg` device is a QEMU-compatible device that allows the hypervisor to pass configuration and data to the guest operating system. This is particularly useful for firmware to access information like ACPI tables, kernel images, initramfs, kernel command lines, and other arbitrary data blobs.

Cloud Hypervisor implements the `fw_cfg` device with DMA-enabled access.

## Purpose

The `fw_cfg` device serves as a generic information channel between the VMM and the guest. It can be used to:

*   Load the kernel, initramfs, and kernel command line for direct kernel boot with firmware.
*   Provide ACPI tables to the guest firmware or OS.
*   Pass custom configuration files or data blobs (e.g., attestation data, SEV-SNP launch secrets) to the guest.
*   Supply an E820 memory map to the guest.

## Enabling `fw_cfg`

The `fw_cfg` device is enabled via the `fw_cfg` feature flag when building Cloud Hypervisor:

```bash
cargo build --features fw_cfg
```

## Guest Kernel Configuration

For the guest Linux kernel to recognize and use the `fw_cfg` device via sysfs, the following kernel configuration option must be enabled:

*   `CONFIG_FW_CFG_SYSFS=y`

This option allows the kernel to expose `fw_cfg` entries under `/sys/firmware/qemu_fw_cfg/by_name/`.

## Command Line Options

The `fw_cfg` device is configured using the `--fw-cfg-config` command-line option.

**Parameters:**
*   `e820=on|off`: (Default: `on`) Whether to add an E820 memory map entry to `fw_cfg`.
*   `kernel=on|off`: (Default: `on`) Whether to add the kernel image (specified by `--kernel`) to `fw_cfg`.
*   `cmdline=on|off`: (Default: `on`) Whether to add the kernel command line (specified by `--cmdline`) to `fw_cfg`.
*   `initramfs=on|off`: (Default: `on`) Whether to add the initramfs image (specified by `--initramfs`) to `fw_cfg`.
*   `acpi_table=on|off`: (Default: `on`) Whether to add generated ACPI tables to `fw_cfg`.
*   `items=[... : ...]`: A list of custom key-value pairs to be exposed via `fw_cfg`.
    *   `name=<guest_sysfs_path>`: The path under which the item will appear in the guest's sysfs (e.g., `opt/org.example/my-data`).
    *   `file=<host_file_path>`: The path to the file on the host whose content will be provided to the guest for this item.

**Example Usage:**

1.  **Direct kernel boot with custom `fw_cfg` entries:**

    ```bash
    cloud-hypervisor \
        --kernel /path/to/vmlinux \
        --cmdline "console=hvc0 root=/dev/vda1" \
        --disk path=/path/to/rootfs.img \
        --fw-cfg-config initramfs=off,items=[name=opt/org.mycorp/setup_info,file=/tmp/guest_setup.txt] \
        ...
    ```
    In the guest, `/tmp/guest_setup.txt` from the host will be accessible at `/sys/firmware/qemu_fw_cfg/by_name/opt/org.mycorp/setup_info/raw`.

2.  **Disabling `fw_cfg` explicitly:**

    ```bash
    cloud-hypervisor \
        --fw-cfg-config disable \
        ...
    ```

## Accessing `fw_cfg` Items in the Guest

If `CONFIG_FW_CFG_SYSFS` is enabled in the guest kernel, items added to `fw_cfg` can be accessed via sysfs.

For example, an item added with `name=opt/org.example/my-data` will be available at:
`/sys/firmware/qemu_fw_cfg/by_name/opt/org.example/my-data/raw`

The `raw` file contains the binary content of the host file provided.

Standard items like kernel, initramfs, cmdline, and ACPI tables also have predefined names (e.g., `etc/kernel`, `etc/cmdline`) if they are enabled to be passed via `fw_cfg`.
