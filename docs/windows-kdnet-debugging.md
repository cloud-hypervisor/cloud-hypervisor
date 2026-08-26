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
    --disk path=/path/to/windows.raw,image_type=raw \
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

### Routing the debug NIC with NAT for remote or cross subnet debuggers

Bridging assumes the debug NIC can appear directly on a network the debugger
shares. That is not always possible or desirable. The debugger may live on a
different subnet reached only through the default route of the host, or the
host uplink may drop frames carrying the debuggee MAC. Many cloud and virtual
switch uplinks reject foreign MACs unless MAC address spoofing is explicitly
enabled.

Because KDNET connections are always **target initiated**, source NAT on the
Cloud Hypervisor host is sufficient. The outbound UDP from the debuggee creates
a conntrack entry and the replies from the debugger return along it, so no
inbound port forward is needed on the Cloud Hypervisor host. Put the tap on its
own private subnet and masquerade it out the uplink.

```bash
sudo ip addr add 192.168.250.1/24 dev chdbg0
sudo ip link set chdbg0 up

sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 192.168.250.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i chdbg0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o chdbg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t mangle -A POSTROUTING -o chdbg0 -p udp -j CHECKSUM --checksum-fill

sudo dnsmasq --port=0 --interface=chdbg0 --bind-interfaces \
    --dhcp-range=192.168.250.50,192.168.250.150,255.255.255.0,1h \
    --dhcp-option=option:router,192.168.250.1 --dhcp-authoritative
```

KDNET needs a routable address on the tap subnet, provided in one of two ways.
Either serve DHCP on the tap with the dnsmasq invocation above, or assign a
static address on the debug subnet from SAC as shown in the guest
configuration. A link local `169.254.x` address is not enough. The Linux
kernel refuses to forward it per RFC 3927, so those packets die on the tap
before reaching NAT. When using a static address, the dnsmasq line is not
needed. Set `hostip` to the debugger address, and the firewall on the debugger
must still allow the debug port inbound.

## Guest configuration (Windows debuggee)

Cloud Hypervisor exposes no VGA adapter, so with `--serial tty --console off`
the only built-in console is **SAC**, a minimal text menu over the serial line.
SAC is not a full shell. It can assign a NIC address with its `i` command and
open a plain `cmd` channel, which is enough to run `bcdedit`. The channel
prompts for the guest credentials, and once logged in it is an ordinary
Windows command prompt from which `powershell` can be started. PowerShell is
needed only for `busparams` discovery, so no RDP or SSH is required. See
[Windows Support](windows.md).

### Enable KDNET from SAC

Give the debug NIC a static address on the debug subnet, where `10` is the
device index printed by bare `i`, then open a command channel. This is the
alternative to serving DHCP on the tap. Either one gives KDNET a routable
address.

```
SAC>i
SAC>i 10 192.168.250.2 255.255.255.0 192.168.250.1
SAC>cmd
SAC>ch -si 1
```

In that channel, enable KDNET. `busparams` is omitted here so KDNET
autoselects the single virtio-net adapter.

```bat
bcdedit /debug on
bcdedit /dbgsettings net hostip:<debugger-ip> port:<50000-50039> key:<key>
```

- `hostip` is the WinDbg host address.
- `port` is a UDP port in the 49152-65535 range (50000-50039 is conventional).
- `key` is the debug encryption key (four dot-separated groups). Use a fixed
  key, or omit it to let Windows generate one and print it.

Reboot the debuggee after applying the settings.

### Optionally pinning a specific NIC with busparams

When the guest has more than one supported adapter, select the debug NIC
explicitly by its PCI bus/device/function. Read the location from a
PowerShell started in the logged in SAC `cmd` channel, no RDP or SSH needed.

```powershell
Get-NetAdapter | ForEach-Object {
    $loc = (Get-PnpDeviceProperty -InstanceId $_.PnpDeviceID `
        -KeyName DEVPKEY_Device_LocationInfo).Data
    "$($_.MacAddress)  ::  $loc"   # e.g. "PCI bus 0, device 3, function 0"
}
```

Then, from an elevated prompt, pin it and reboot.

```bat
bcdedit /set "{dbgsettings}" busparams <bus>.<device>.<function>
```

- `busparams` selects the virtio-net NIC. Omit it entirely to let KDNET
  autoselect a supported adapter. It is only a disambiguator, not a
  requirement. When omitted, KDNET scans the PCI bus at boot. It picks the
  first adapter that has a KDNET extensibility module and skips unsupported
  ones. A single supported NIC therefore works without it. With several
  supported NICs, leave only the debug NIC attached. Otherwise confirm which
  one KDNET chose by MAC with `.kdtargetmac` in WinDbg.

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
  the debuggee with the debugger already running. When routing with NAT, KDNET
  must have a routable address on the tap, from DHCP or a static SAC
  assignment. Without one it uses a link local `169.254.x` source that the
  kernel will not forward.
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
