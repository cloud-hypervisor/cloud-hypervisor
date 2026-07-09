# Windows Kernel Debugging over virtio-net (KDNET)

Windows can run its kernel debugging transport (KDNET) over a network adapter
instead of a serial port.
 
This document describes how to configure KDNET over a Cloud Hypervisor
`virtio-net` device,  and how to configure a debuggee/debugger pair.

## Overview

KDNET is the network kernel-debugging transport built into Windows. The
Windows debuggee runs a small, self-contained NIC driver ("KDNET
extensibility module") that operates the network card directly, bypassing the
normal NDIS stack, and exchanges debug packets over UDP with a debugger host
running WinDbg.

Recent Windows builds ship a KDNET extensibility module for `virtio-net`, so a
plain Cloud Hypervisor `virtio-net` device can be used as the debug transport.

## Host configuration (Cloud Hypervisor)

Give the guest a tap-backed virtio-net device so that the debug UDP traffic can
reach the WinDbg host, and boot with the Hyper-V enlightenments Windows needs:

```bash
cloud-hypervisor \
    --kernel /path/to/CLOUDHV.fd \
    --disk path=/path/to/windows.raw \
    --cpus boot=2,kvm_hyperv=on \
    --memory size=4G \
    --net tap=chdbg0,mac=2e:89:a0:1e:6f:01 \
    --serial tty --console off
```

`kvm_hyperv=on` is required: without the Hyper-V enlightenments the Windows
guest hangs early in boot. The debug NIC can be the guest's only NIC or a
dedicated one; a dedicated NIC keeps normal networking (and remote access to the
debuggee) working, since KDNET takes exclusive ownership of the NIC it uses.

Bridge `chdbg0` to a network that the debugger host can reach (or assign the
host tap an address on the same subnet as the WinDbg host). KDNET uses UDP, so
routing/firewalling must allow the chosen debug port -- in particular, open the
UDP debug port inbound on the **debugger** host's firewall, otherwise the
target's connection packets are dropped before WinDbg sees them.

## Guest configuration (Windows debuggee)

Identify the virtio-net adapter's PCI bus/device/function (KDNET selects the NIC
by `busparams`). The location of each adapter can be read with PowerShell:

```powershell
Get-NetAdapter | ForEach-Object {
    $loc = (Get-PnpDeviceProperty -InstanceId $_.PnpDeviceID `
        -KeyName DEVPKEY_Device_LocationInfo).Data
    "$($_.MacAddress)  ::  $loc"   # e.g. "PCI bus 0, device 3, function 0"
}
```

Then, from an elevated prompt on the debuggee:

```bat
bcdedit /debug on
bcdedit /dbgsettings net hostip:<debugger-ip> port:<50000-50039> key:<key>
bcdedit /set "{dbgsettings}" busparams <bus>.<device>.<function>
```

- `hostip` is the WinDbg host address.
- `port` is a UDP port in the 49152-65535 range (50000-50039 is conventional).
- `key` is the debug encryption key (four dot-separated groups). Use a fixed
  key, or omit it to let Windows generate one and print it.
- `busparams` selects the virtio-net NIC. Omit it to let KDNET auto-select a
  supported adapter.

Reboot the debuggee after applying the settings.

## Debugger host (WinDbg)

Start WinDbg listening on the same port/key:

```bat
windbg -k net:port=<port>,key=<key>
```

or configure an equivalent network kernel-debug connection in the WinDbg UI.

### Notes

- KDNET takes exclusive ownership of its NIC, so keep the management/SSH NIC
  separate from the debug NIC, and put the debug NICs on their own bridge/subnet
  to avoid same-subnet ARP flux on the multi-homed guests.
- When bridging guests through the host, add
  `iptables -t mangle -A POSTROUTING -o <dev> -p udp -j CHECKSUM --checksum-fill`
  so DHCP/DNS replies with offloaded checksums are not dropped by the guests.

## Troubleshooting

- **KDNET does not attach / falls back to no debugger.** Confirm the guest sees
  the adapter as a network controller and that `VIRTIO_NET_F_STATUS` is
  offered. Both are provided by Cloud Hypervisor's virtio-net device.
- **The target sends connect packets but WinDbg never connects.** The most
  common cause is the **debugger** host's firewall dropping the inbound UDP
  debug port. Allow the port (and/or the `windbg.exe` program) inbound.
  KDNET connections are always initiated by the *target*, so the debugger must
  be listening before (or while) the target polls; start it first, or reboot
  the debuggee with the debugger already running.
- **No packets reach the debugger host.** Check tap bridging and host routing.
  When bridging guests through the host, note that host-originated replies can
  carry offloaded (incomplete) UDP checksums; if a guest ignores them, add an
  `iptables -t mangle -A POSTROUTING -o <dev> -p udp -j CHECKSUM --checksum-fill`
  rule for the bridge/tap. KDNET's own packets use a zero UDP checksum and are
  unaffected.

## References

- Virtual I/O Device (VIRTIO) Version 1.2, §4.1.4.9 "PCI configuration access
  capability".
- [Setting Up Network Debugging of a Windows guest](https://learn.microsoft.com/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection).
- [Windows Support](windows.md): general Windows guest setup and the
  serial-based debugging alternative.
