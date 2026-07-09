# Windows Support

Starting with the release version [0.10.0](https://github.com/cloud-hypervisor/cloud-hypervisor/releases/tag/v0.10.0), Cloud Hypervisor supports Windows guests.

__Requirements__

- Host with KVM enabled
- [UEFI](uefi.md) capable Windows guest image with Virtio drivers integrated

Any modern Windows Server version is compatible, as well as Windows 11. Cloud Hypervisor has been successfully tested with Windows Server 2019, Windows Server Core 2004 and Windows 11 IoT Enterprise LTSC 2024.

At the current stage, only UEFI capable Windows images are supported. This implies the presence of the OVMF firmware during the Windows installation and in any subsequent usage. BIOS boot is not supported.

The subsequent sections will tell, in detail, how to prepare an appropriate Windows image.

## Image Preparation

### Installation using the stock Windows ISO

__Prerequisites__

- QEMU, version >=5.0.0 is recommended.
- Windows installation ISO. Obtained through MSDN, Visual Studio subscription, evaluation center, etc.
- [VirtIO driver ISO](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/)
  - Please use the [VirtIO Windows 11 attestation file](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/upstream-virtio/virtio-win11-attestation-0.1-258.zip)
    for Windows 11
- Suitable firmware for Cloud Hypervisor (`CLOUDHV.fd`) and for QEMU (`OVMF.fd`)
- With the suggested image size of 30G for Windows Server, there should be enough free disk space to hold the installation ISO and any other necessary files
  - For Windows 11, increasing this image size to 64GB is recommended (see [minimal requirements](https://support.microsoft.com/en-us/windows/windows-11-system-requirements-86c11283-ea52-4782-9efd-7674389a7ba3))
- Windows 11 only: TPM 2.0 support
- Windows 11 only: 2 or more cores

This step currently requires QEMU to install Windows onto the guest. QEMU is only used at the preparation stage, the resulting image is then fully functional with Cloud Hypervisor.

Preparing several command parts as these will be used in the follow up sections as well.

```shell
IMG_FILE=windows-disk.raw
WIN_ISO_FILE=en_windows_server_version_2004_updated_may_2020_x64_dvd_1e7f1cfa.iso
VIRTIO_ISO_FILE=virtio-win-0.1.185.iso
OVMF_DIR=./FV
```

Create an empty image file, `raw` is supported.

```shell
qemu-img create -f raw $IMG_FILE 30G
```

Begin the Windows installation process under QEMU for Windows Server:

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
	-vga std
```

For Windows 11 you can use `swtpm` to fulfill the TPM 2.0 requirement:

```shell
# Create directory to store state
mkdir -p /tmp/mytpm1
# Start swtpm daemon for TPM 2.0 support
swtpm socket \
    --tpm2 \
    --ctrl type=unixio,path=/tmp/swtpm-sock \
    --tpmstate dir=/tmp/mytpm1 \
    --flags startup-clear \
    --log level=20 \
    --log file=/tmp/swtpm.log \
    --daemon
```

Begin the Windows 11 installation process under QEMU like this:

```shell
qemu-system-x86_64 \
    -machine q35,accel=kvm \
    -cpu host \
    -m 4G \
    -bios ./$OVMF_DIR/OVMF.fd \
    -cdrom ./$WIN_ISO_FILE \
    -drive file=./$VIRTIO_ISO_FILE,index=0,media=cdrom \
    -drive if=none,id=root,file=./$IMG_FILE \
    -device virtio-blk-pci,drive=root,disable-legacy=on \
    -device virtio-net-pci,netdev=mynet0,disable-legacy=on \
    -netdev user,id=mynet0 \
    -vga std \
    -smp 4 \
    -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0
```

This command needs at least `-smp 2` (2 cores), as well as the last three lines (TPM 2.0), to support Windows 11 minimal requirements. Additionally, using `OVMF_CODE.fd` leads to the following error: `qemu: could not load PC BIOS '././FV/OVMF_CODE.fd'`. Switching to `OVMF.fd` is therefore necessary.

For more details about TPM specifically, please continue with the [TPM documentation](./tpm.md).

Before the installation can proceed, point the Windows installation program to the VirtIO disk and install the necessary storage controller drivers. For Windows 11 with the attestation drivers, you need to navigate to the `viostor` directory to be able to see and install it. After that, the attached hard drive will become visible and the actual installation can commence.

Do not install network drivers for Windows 11 just yet, if you don't want to be forced to log-in to/create a Microsoft account. Simply select `I don't have internet` for now.

After the installation has completed, proceed further to the [configuration section](#image-configuration). QEMU will be needed at least once more to enable/install the Windows Special Administration Console (SAC) and to possibly install extra device drivers.

## Image Usage

The basic command to boot a Windows image is shown in the next code snippet. The [configuration section](#image-configuration), as well as the [Getting Started section](../README.md#2-getting-started) should be checked before executing it for the first time. Please especially read the documentation for giving the cloud-hypervisor binary the correct capabilities for it to set TAP interfaces up on the host, otherwise the command below will fail:

```shell
cloud-hypervisor \
	--kernel ./$OVMF_DIR/CLOUDHV.fd \
	--disk path=./$IMG_FILE \
	--cpus boot=1,kvm_hyperv=on \
	--memory size=4G \
	--serial tty \
	--console off \
	--net tap=
```

It is necessary to always:

- Carry the OVMF firmware in the `--kernel` option
- Add `kvm_hyperv=on` to the `--cpus` option

In cases where the host processor supports address space > 39 bits, it might be necessary to limit the address space. It can be done by appending the option `max_phys_bits=X` to the `--cpus` parameter, where `X` is the number of bits to be supported. Windows was tested to support at least 39-bit address space.

To daemonize the Cloud Hypervisor process, `nohup` can be used. Some STDIO redirections might need to be done. In a simple case it is sufficient to just redirect all the output to `/dev/null`.

Be aware, currently, running the Windows 11 VM on Cloud Hypervisor with TPM 2.0 was not proven successful: `thread 'vcpu0' panicked`. Running the VM without TPM is a valid option though. Therefore the command as shown above is also valid for a Windows 11 VM.

## Image Configuration

### Device Drivers

After the Windows installation has finished under QEMU, there might be still devices with no drivers installed. This might happen for example, when a device was not used during the installation. In particular it is important to ensure that the VirtIO network device is setup correctly because further steps for the configuration and the usage require network in most case.

Boot once more under QEMU and use the [Device Manager](https://support.microsoft.com/en-in/help/4028443/windows-10-update-drivers), to ensure all the device drivers, and especially the network card, are installed correctly. If not, right click on the unknown network device, choose `Update driver` and browse to the `NetKvm` directory on the CD.

Also, as Cloud Hypervisor can introduce new devices, it is advisable to repeat the procedure while booted under Cloud Hypervisor, when the [RDP](#remote-desktop-protocol-rdp-enablement) access to the image is functional.

### Windows Special Administration Console (SAC) enablement

SAC provides a text based console access to the Windows guest. As Cloud Hypervisor doesn't implement a VGA adaptor, SAC is an important instrument for the Windows guest management.

Boot the Windows image under QEMU. For all non-server Windows versions, the SAC needs to be downloaded and enabled first in the `Optional features` menu of Windows.

Execute the below commands to permanently enable SAC. You might need admin privileges.

```cmd
bcdedit /emssettings emsport:1 emsbaudrate:115200
bcdedit /ems on
bcdedit /bootems on
```

Once SAC is enabled, the image can be booted under Cloud Hypervisor. The SAC prompt will show up

<pre>
Computer is booting, SAC started and initialized.

Use the "ch -?" command for information about using channels.
Use the "?" command for general help.

SAC>
</pre>

To open a console on the guest, the command sequence below can be used
<pre>
SAC>cmd
The Command Prompt session was successfully launched.
SAC>
EVENT:   A new channel has been created.  Use "ch -?" for channel help.
Channel: Cmd0001
SAC>ch -si 1
</pre>

See also the [links](#Links) section for a more extended SAC documentation.

## Network

This section illustrates the Windows specific aspects of the VM network configuration.

### Basic Networking

As the simplest option, using `--net tap=` in the Cloud Hypervisor command line will create a `vmtapX` device on the host with the default IPv4 address `192.168.249.1`. After SAC becomes available, the guest configuration can be set with

<pre>
SAC>i 10 192.168.249.2 255.255.255.0 192.168.249.1
</pre>

Where `10` is the device index as shown by the `i` command.

### Guest Internet Connectivity

Additional steps are necessary to provide the guest with internet access.

- On the guest, add the DNS server either by using `netsh` or by opening `Network and Connectivity Center` and editing the adapter properties.
- On the host, configure the traffic forwarding. Replace the `NET_DEV` with the name of your network device.

```shell
NET_DEV=wlp3s0
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o $NET_DEV -j MASQUERADE
```

If needed, you can also allow ICMP from host to guest via the following command executed on the guest:

```shell
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow
```

This will enable simple `ping` requests from your host to the guest.

### Remote Desktop Protocol (RDP) enablement

#### Using QEMU

- Execute `SystemPropertiesRemote`
- In the properties window, choose "Allow remote connections to this computer"
- Click "Select Users" and add some user to the allow list

#### Using powershell

```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member someuser
```

Administrators can always RDP, non administrator users have to be explicitly enabled.

Once the configuration is set, RDP clients can connect to `192.168.249.2`.

### SSH

#### Enable using powershell

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType ‘Automatic’
```

This allows for SSH login from a remote machine, for example through the `administrator` user: `ssh administrator@192.168.249.2`.

On Windows 11, opening the firewall was needed as well:

```powershell
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

For a more detailed OpenSSH guide, please follow the MSDN article from the [links](#links) section.

## Hotplug capability

CPU hotplug is supported. The VM operating system needs to support hotplug and be appropriately licensed. SKU limitations like constraints on the number of cores are to be taken into consideration. Note, that Windows doesn't support CPU hot-remove. When `ch-remote` is invoked to reduce the number of CPUs, the result will be visible after the OS reboot within the same hypervisor instance.

RAM hotplug is supported. Note, that while the `pnpmem.sys` driver in use supports RAM hot-remove, the RAM being unplugged has to be not in use and have no reserved pages. In most cases it means, hot-remove won't work. Same as with the CPU hot-remove, when `ch-remote` is invoked to reduce the RAM size, the result will be visible after the OS reboot.

Network device hotplug and hot-remove are supported.

Disk hotplug and hot-remove are supported. After the device has been hotplugged, it will need to be onlined from within the guest. Among other tools, powershell applets `Get-Disk` and `Set-Disk` can be used for the disk configuration and activation.

## Debugging

Two methods of kernel debugging a Windows guest are documented separately:

- [Windows Kernel Debugging over virtio-net (KDNET)](windows-kdnet-debugging.md)
- [Windows Kernel Debugging over serial (KDCOM)](windows-kdcom-debugging.md)

## Links

- [Fedora VirtIO guide for Windows](https://docs.fedoraproject.org/en-US/quick-docs/creating-windows-virtual-machines-using-virtio-drivers/)
- [VirtIO driver binaries](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/)
- [VirtIO driver sources](https://github.com/virtio-win/kvm-guest-drivers-windows)
- [Emergency Management Services](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787940(v=ws.10))
- [OpenSSH server/client configuration](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
- [Windows guest debugging under KVM](https://www.linux-kvm.org/page/WindowsGuestDrivers/GuestDebugging)
- ["ENLIGHTENING" KVM](https://archive.fosdem.org/2019/schedule/event/vai_enlightening_kvm/attachments/slides/2860/export/events/attachments/vai_enlightening_kvm/slides/2860/vkuznets_fosdem2019_enlightening_kvm.pdf)
