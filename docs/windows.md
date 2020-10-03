# Windows Support

Starting with the release version [0.10.0](https://github.com/cloud-hypervisor/cloud-hypervisor/releases/tag/v0.10.0), Cloud Hypervisor supports Windows guests.

__Requirements__

- Host with KVM enabled 
- [UEFI](uefi.md) capable Windows guest image with Virtio drivers integrated

Any modern Windows Server version is compatible. Cloud Hypervisor has been successfully tested with Windows Server 2019 and Windows Server Core 2004.

At the current stage, only UEFI capable Windows images are supported. This implies the presence of the OVMF firmware during the Windows installation and in any subsequent usage. BIOS boot is not supported.

The subsequent sections will tell, in detail, how to prepare an appropriate Windows image.

## Image Preparation

### Installation using the stock Windows ISO

__Prerequisites__

- QEMU
- Windows installation ISO. Obtained through MSDN, Visual Studio subscription, evaluation center, etc. 
- [VirtIO driver ISO](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/)
- Suitable [OVMF](uefi.md) firmware 
- With the suggested image size of 30G, there should be enough free disk space to hold the installation ISO and any other necessary files

This step currently requires QEMU to install Windows onto the guest. QEMU is only used at the preparation stage, the resulting image is then fully functional with Cloud Hypervisor.

Preparing several command parts as these will be used in the follow up sections as well.

```shell
IMG_FILE=windows-disk.qcow
WIN_ISO_FILE=en_windows_server_version_2004_updated_may_2020_x64_dvd_1e7f1cfa.iso
VIRTIO_ISO_FILE=virtio-win-0.1.185.iso
OVMF_DIR=./FV
```

Create an empty image file, `qcow` or `raw` is supported.
```shell
qemu-img create -f qcow2 $IMG_FILE 30G
```

Begin the Windows installation process under QEMU
```shell
qemu-system-x86_64 -machine q35,accel=kvm \
	-cpu host \
	-m 4G \
	-bios ./$OVMF_DIR/OVMF_CODE.fd \
	-cdrom ./$WIN_ISO_FILE \
	-drive file=./$VIRTIO_ISO_FILE,index=0,media=cdrom
	-drive if=none,id=root,file=./$IMG_FILE \
	-device virtio-blk-pci,drive=root,disable-legacy=on \
	-device virtio-net-pci,netdev=mynet0,disable-legacy=on \
	-netdev user,id=mynet0 \
	-vga std
```

Before the installation can proceed, point the Windows installation program to the VirtIO disk and install the necessary storage controller drivers. After that, the attached hard drive will become visible and the actual installation can commence.

After the installation has completed, proceed further to the configuration section. QEMU will be needed at least once more to enable the Windows Special Administration Console (SAC) and to possibly install extra device drivers.

## Image Usage

The basic command to boot a Windows image. The configuration section should be checked before executing it for the first time.

```shell
cloud-hypervisor \
	--kernel ./$OVMF_DIR/OVMF.fd \
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

To daemonize the Cloud Hypervisor process, `nohup` can be used. Some STDIO redirections might need to be done. In a simple case it is sufficient to just redirect all the output to `/dev/null`.

## Image Configuration

### Device Drivers

After the Windows installation has finished under QEMU, there might be still devices with no drivers installed. This might happen for example, when a device was not used during the installation. In particular it is important to ensure that the VirtIO network device is setup correctly because further steps for the configuration and the usage require network in most case.

Boot once more under QEMU and use the [Device Manager](https://support.microsoft.com/en-in/help/4028443/windows-10-update-drivers), to ensure all the device drivers, and especially the network card, are installed correctly. Also, as Cloud Hypervisor can introduce new devices, it is advisable to repeat the procedure while booted under Cloud Hypervisor, when the RDP access to the image is functional.

### Windows Special Administration Console (SAC) enablement

SAC provides a text based console access to the Windows guest. As Cloud Hypervisor doesn't implement a VGA adaptor, SAC is an important instrument for the Windows guest management.

Boot the Windows image under QEMU and execute the below commands to permanently enable SAC

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

This section illustrates the Windows specific corner points for the VM network configuration. For the extended networking guide, including bridging for multiple VMs, follow [networking.md](networking.md).

### Basic Networking

As the simplest option, using `--net tap=` in the Cloud Hypervisor command line will create a `vmtapX` device on the host with the default IPv4 adress `192.168.249.1`. After SAC becomes available, the guest configuration can be set with

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

This allows for SSH login from a remote machine, for example through the `administrator` user: `ssh administrator@192.168.249.2`. For a more detailed OpenSSH guide, please follow the MSDN article from the [links](#links) section.

## Links

- [Fedora VirtIO guide for Windows](https://docs.fedoraproject.org/en-US/quick-docs/creating-windows-virtual-machines-using-virtio-drivers/)
- [VirtIO driver binaries](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/)
- [VirtIO driver sources](https://github.com/virtio-win/kvm-guest-drivers-windows)
- [Emergency Management Services](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787940(v=ws.10))
- [OpenSSH server/client configuration](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)

