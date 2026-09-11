# SMBIOS

Cloud Hypervisor can set SMBIOS fields for x86-64 guests. Use `--platform` on
the command line, or the `platform` object in the VM API configuration.
These options do not configure SMBIOS on AArch64 or RISC-V.

## System information (Type 1)

| Option | Field | Default |
| --- | --- | --- |
| `system_manufacturer` | Manufacturer | `Cloud Hypervisor` |
| `system_product_name` | Product name | `cloud-hypervisor` |
| `system_version` | Version | Not set |
| `system_serial_number` | Serial number | Not set |
| `system_uuid` | UUID | All-zero UUID |
| `system_sku_number` | SKU number | Not set |
| `system_family` | Family | Not set |

For example, add this option to the VM command:

```shell
--platform 'system_serial_number=vm-001,system_uuid=00112233-4455-6677-8899-aabbccddeeff'
```

The old names `serial_number` and `uuid` still work, but they are deprecated.
Use `system_serial_number` and `system_uuid` in new configurations.

## System enclosure (Type 3)

Use `chassis_asset_tag` to set the asset tag:

```shell
--platform 'chassis_asset_tag=asset-001'
```

Cloud Hypervisor adds a Type 3 table when you set this option.
You cannot set the other chassis fields.

## OEM strings (Type 11)

Use `oem_strings` to supply strings directly:

```shell
--platform 'oem_strings=[public-label,another-label]'
```

Use `oem_string_paths` to read strings from host files:

```shell
--platform 'oem_strings=[public-label],oem_string_paths=[/run/secrets/bootstrap]'
```

Put all platform settings in one `--platform` argument. In the API, use the
same option names in the `platform` object:

```json
{
  "platform": {
    "system_serial_number": "vm-001",
    "oem_strings": ["public-label"],
    "oem_string_paths": ["/run/secrets/bootstrap"]
  }
}
```

Each file supplies one complete OEM string. The file must contain UTF-8 text
and at least one byte. It must not contain NUL bytes.
Cloud Hypervisor preserves spaces, newlines, and non-ASCII characters.
It does not split a file into separate strings at each newline.

Inline strings come first. File contents follow in the order of
`oem_string_paths`. The order of the two options does not change this result.
The combined list must not exceed 255 strings. An empty path list adds no
strings. Cloud Hypervisor does not interpret the strings or check for duplicate
credential names.

The VMM reads the files at boot, not when it parses the configuration.
The paths refer to files on the VMM host, not on the API client or in the guest.
A missing, unreadable, or invalid file causes boot to fail.
Keep the files available for subsequent boots.

### Example: a systemd credential

Use a host file that only the VMM user can read. For this example,
`/run/secrets/bootstrap` contains this complete string:

```text
io.systemd.credential:bootstrap_secret=example-secret
```

Use `oem_string_paths` as shown above. In a guest that supports systemd SMBIOS
credentials, read the credential with this command:

```shell
systemd-creds --system cat bootstrap_secret
```

Include a newline at the end of the file only if the credential needs it.
Do not put a real secret in a shell command that shell history will record.

File input keeps secret contents out of process arguments and configuration
logs. The VMM does not copy those contents into the API configuration.
This feature does not encrypt the strings. The guest can read them from SMBIOS.
Guest memory snapshots and dumps can also contain them. Protect those files.

## Read the fields in the guest

Use `dmidecode` to read individual fields:

```shell
sudo dmidecode -s system-serial-number
sudo dmidecode -s chassis-asset-tag
sudo dmidecode --oem-string 1
```

`dmidecode` changes non-printable and non-ASCII bytes in its text output.
To check the original OEM string bytes, read the Type 11 entry after its
five-byte header:

```shell
sudo od -An -v -tx1 -j5 /sys/firmware/dmi/entries/11-0/raw
```
