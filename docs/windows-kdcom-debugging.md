# Windows Kernel Debugging over serial (KDCOM)

This document describes serial-based (COM/KDCOM) kernel debugging of a Windows
guest. The shell variables used below (`$WIN_ISO_FILE`, `$VIRTIO_ISO_FILE`,
`$OVMF_DIR`, `$IMG_FILE`) are the ones introduced in the image preparation
section of [Windows Support](windows.md).

The Windows guest debugging process relies heavily on QEMU and [socat](http://www.dest-unreach.org/socat/). The procedure requires two Windows VMs:

- A debugger VM running under QEMU.
- A debuggee, a Windows VM that has been created in the previous steps, running under Cloud Hypervisor or QEMU.

The connection between both guests happens over TCP, whereby on the guest side it is automatically translated to a COM port. Because the VMs are connected through TCP, the debugging infrastructure can be distributed over the network. The serial port, while slowly transferring data, is common enough to support a wide range of cases and tools.

In this exercise, [WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) is used. Any other debugger of choice with the ability to use serial connection can be used instead.

## Debugger and Debuggee

### WinDbg VM

For simplicity, the debugger VM is supposed to be only running under QEMU. It will require VGA and doesn't necessarily depend on UEFI. As an OS, it can carry any supported Windows OS where the debugger of choice can be installed. The simplest way is to follow the image preparation instructions from the previous chapter, but avoid using the OVMF firmware. It is also not required to use VirtIO drivers, whereby it might be useful in some case. Though, while creating the image file for the debugger VM, be sure to choose a sufficient disk size that counts in the need to save the corresponding debug symbols and sources.

To create the debugger Windows VM, the following command can be used:

```shell
qemu-system-x86_64 \
	-machine q35,accel=kvm \
	-cpu host \
	-smp 1 \
	-m 4G \
	-cdrom ./$WIN_ISO_FILE \
	-drive file=./$VIRTIO_ISO_FILE,index=0,media=cdrom \
	-drive if=none,id=root,file=./windbg-disk.raw \
	-device virtio-blk-pci,drive=root,disable-legacy=on \
	-device virtio-net-pci,netdev=mynet0,disable-legacy=on \
	-netdev user,id=mynet0,net=192.168.178.0/24,host=192.168.178.1,dhcpstart=192.168.178.64,hostname=windbg-host \
	-vga std
```

A non server Windows OS like Windows 10 can be used to carry the debugging tools in the debugger VM.

### Debuggee VM

The debuggee VM is the one that we've learned to configure and run in the first section. There might be various reasons to debug. For example, there could be an issue in the Windows guest with an emulated device or an included driver. Or, we might want to develop a custom feature like a kernel driver to be available in the guest.

Note, that there are several ways to debug Windows, not all of them need to be enabled at the same time. For example, if developing a kernel module, the only useful options would be to configure for the serial debugging and enable the kernel debug. In that case, any crash or misbehavior in the boot loader or kernel would be ignored. The commands below must be run as administrator on the debuggee guest VM.

#### Turn On Serial Debugging

This will configure the debugging to be enabled and instruct to use the serial port for it.

```cmd
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

#### Turn On Kernel Debugging

```cmd
bcdedit /debug on
```

#### Turn On Boot Loader Debug

```cmd
bcdedit /bootdebug on
```

#### Turn on boot manager debug

```cmd
bcdedit /set {bootmgr} bootdebug on
```

#### Disable Recovery Screen On Boot Failure

There could be a situation, where a crash is debugged. In such cases, the guest could be left in an inconsistent state. The default Windows behavior would be to boot into the recovery screen, however in some cases it might be not desired. To make Windows ignore failures and always proceed to booting the OS, use the command below:

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

## Debugging Process

### Invoke the WinDbg VM

```shell
qemu-system-x86_64 \
	-machine q35,accel=kvm \
	-cpu host \
	-smp 1 \
	-m 4G \
	-drive if=none,id=root,file=./windbg-disk.raw \
	-device virtio-blk-pci,drive=root,disable-legacy=on \
	-serial tcp::4445,server,nowait \
	-device virtio-net-pci,netdev=mynet0,disable-legacy=on \
	-netdev user,id=mynet0,net=192.168.178.0/24,host=192.168.178.1,dhcpstart=192.168.178.64,hostname=windbg-host \
	-vga std
```

Note, this VM has the networking enabled. It is needed, because symbols and sources might need to be fetched from a network location.

Also, notice the `-serial` parameter - that's what does the magic on exposing the serial port to the guest while connecting the debugger VM with a client VM through the network. SAC/EMS needs to be disabled in the debugger VM, as otherwise the COM device might be blocked.

Hereafter, WinDbg can be started using a command below:

```cmd
set _NT_DEBUG_PORT=com1
set _NT_DEBUG_BAUD_RATE=115200

windbg -v -d -k
```

Once started, WinDbg will wait for an incoming connection which is going to be initialized by the debuggee VM started in the next section.

### Invoke the Debuggee VM

#### Under QEMU

Essentially it would be the command like depicted in the guest preparation sections, with a few modifications:

```shell
qemu-system-x86_64 \
	-machine q35,accel=kvm \
	-cpu host \
	-m 4G \
	-bios ./$OVMF_DIR/OVMF_CODE.fd \
	-cdrom ./$WIN_ISO_FILE \
	-drive file=./$VIRTIO_ISO_FILE,index=0,media=cdrom \
	-drive if=none,id=root,file=./$IMG_FILE \
	-device virtio-blk-pci,drive=root,disable-legacy=on \
	-device virtio-net-pci,netdev=mynet0,disable-legacy=on \
	-netdev user,id=mynet0 \
	-serial tcp:127.0.0.1:4445 \
	-vga std
```

It is to see, that `-serial` parameter is used here, to establish the connection with the debugger VM.

To disable HPET, attach `--no-hpet`. To enable hypervisor reference timer, use `-cpu host,hv-time`. These and other options can be used to achieve better [Hyper-V compatibility](https://archive.fosdem.org/2019/schedule/event/vai_enlightening_kvm/attachments/slides/2860/export/events/attachments/vai_enlightening_kvm/slides/2860/vkuznets_fosdem2019_enlightening_kvm.pdf).

#### Cloud Hypervisor

The `socat` tool is used to establish the QEMU compatible behavior. Here as well, the Cloud Hypervisor command used to run the Windows guest is to be used. Put the command into a shell script:

`socat SYSTEM:"./ch-script",openpty,raw,echo=0 TCP:localhost:4445`

The reason to pack the command into the shell script is that the command might contain a comma. When using SYSTEM, the shell command can't contain `,` or `!!`.
