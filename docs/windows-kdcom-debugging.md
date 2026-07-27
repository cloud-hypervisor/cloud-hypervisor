# Windows Kernel Debugging over serial (KDCOM)

This document describes serial-based (COM/KDCOM) kernel debugging of a Windows
guest running under Cloud Hypervisor. The shell variables used below
(`$OVMF_DIR`, `$IMG_FILE`) are the ones introduced in the image preparation
section of [Windows Support](windows.md). The `$LINUX_HOST_IP` variable is the
address of the Linux host that runs the debuggee.

The setup consists of two parts:

- A debuggee, the Windows guest running under Cloud Hypervisor on a Linux host.
- A debugger, WinDbg running on any Windows machine that carries the debugging tools.

Cloud Hypervisor exposes the guest serial port on a UNIX socket. On the Linux host, [socat](http://www.dest-unreach.org/socat/) turns that socket into a TCP listener. On the Windows side, a bridge tool such as [convey](https://github.com/weltling/convey) turns the TCP endpoint back into a named pipe that WinDbg attaches to. Because the transport is TCP, the debugger and the debuggee can run on different machines across the network. The serial port, while slow, is common enough to support a wide range of cases and tools.

In this exercise, [WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) is used. Any other debugger of choice with the ability to use a serial connection can be used instead.

## Debuggee VM configuration

The debuggee VM is the one that we've learned to configure and run in the first section. There might be various reasons to debug. For example, there could be an issue in the Windows guest with an emulated device or an included driver. Or, we might want to develop a custom feature like a kernel driver to be available in the guest.

Note, that there are several ways to debug Windows, not all of them need to be enabled at the same time. For example, if developing a kernel module, the only useful options would be to configure for the serial debugging and enable the kernel debug. In that case, any crash or misbehavior in the boot loader or kernel would be ignored. The commands below must be run as administrator on the debuggee guest VM.

### Turn On Serial Debugging

This will configure the debugging to be enabled and instruct to use the serial port for it.

```cmd
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

### Turn On Kernel Debugging

```cmd
bcdedit /debug on
```

### Turn On Boot Loader Debug

```cmd
bcdedit /bootdebug on
```

### Turn on boot manager debug

```cmd
bcdedit /set {bootmgr} bootdebug on
```

### Disable Recovery Screen On Boot Failure

There could be a situation, where a crash is debugged. In such cases, the guest could be left in an inconsistent state. The default Windows behavior would be to boot into the recovery screen, however in some cases it might be not desired. To make Windows ignore failures and always proceed to booting the OS, use the command below:

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

## Debugging Process

### On the Linux host

Run the Windows guest under Cloud Hypervisor and expose the guest serial port on a UNIX socket. Attach `--console off` so that the serial port carries the debugging protocol rather than a console:

```shell
sudo ./target/release/cloud-hypervisor \
	--cpus boot=4 \
	--memory size=8192M \
	--kernel ./$OVMF_DIR/CLOUDHV.fd \
	--disk path=./$IMG_FILE \
	--console off \
	--serial socket=/tmp/serial.sock \
	--net tap=tap0
```

Then use `socat` to expose the UNIX socket as a TCP listener. Pick a free port, here `4445`:

```shell
sudo socat TCP-LISTEN:4445,reuseaddr,fork UNIX-CONNECT:/tmp/serial.sock
```

The debugger connects to this TCP port. If the debugger runs on a different machine, use the address of the Linux host in the next step.

### On the Windows host

WinDbg runs on any Windows machine that carries the debugging tools. In this setup the serial over TCP endpoint exposed above has to appear as a local COM port or named pipe that WinDbg can attach to. The [convey](https://github.com/weltling/convey) tool does this bridging and is the one that has been tested to work here. There are other open source and commercial COM to TCP bridge solutions that advertise similar capabilities, such as [com0com](https://sourceforge.net/projects/com0com/) with its com2tcp and hub4com companions, HW Virtual Serial Port, or Serial to Ethernet Connector, but they have not been tried in this setup.

Start the bridge, pointing it at the Linux host address and the port chosen for `socat`:

```powershell
convey --bridge --pipe-server \\.\pipe\kd0 tcp:$LINUX_HOST_IP:4445 --verbose
```

Then attach WinDbg to the named pipe. The `resets=0` and `reconnect` options let the session survive target resets:

```powershell
windbg -k com:pipe,port=\\.\pipe\kd0,resets=0,reconnect
```

The bridge carries raw bytes only and reconnects on its own, which lets it survive a debuggee reset. Once WinDbg is attached and the debuggee VM boots, the kernel debugging session is established.
