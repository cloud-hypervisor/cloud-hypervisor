# How to create a custom Clear Linux image

In the context of adding more utility to the cloudguest image being used
for integration testing, this is a quick guide on how to achieve the creation
of your own Clear Linux image using the official Clear Linux tooling.

## Prepare the environment

From the host, the goal is run a Clear Linux VM that will allow us to build
the custom image we want.

```bash
# Get latest CL version:
IMG_VERSION=$(curl https://download.clearlinux.org/latest)
# Get latest clear-kvm image:
wget -P $HOME/workloads/ https://download.clearlinux.org/current/clear-${IMG_VERSION}-kvm.img.xz
# Extract the image
unxz $HOME/workloads/clear-${IMG_VERSION}-kvm.img.xz
# Make sure cloud-hypervisor binary has CAP_NET_ADMIN capability set
sudo setcap cap_net_admin+ep cloud-hypervisor
# Boot cloud-hypervisor VM with the downloaded image
./cloud-hypervisor -v --kernel $HOME/workloads/vmlinux --disk path=clear-${IMG_VERSION}-kvm.img --cmdline "console=ttyS0 console=hvc0 reboot=k panic=1 nomodules root=/dev/vda3 rw" --cpus 1 --memory size=4G --net tap=,mac=
# Setup connectivity
# First make sure to enable IP forwarding (disabled on Linux by default)
sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
# Retrieve the interface name and the gateway IP
IFACE=$(ip route | grep default | awk -F 'dev' '{print $2}' | awk -F ' ' '{print $1}')
GW=$(ip route | grep vmtap0 | awk -F ' ' '{print $1}')
# Create a new masquerade rule to tag the packets going out
sudo iptables -t nat -A POSTROUTING -s ${GW} -o ${IFACE} -j MASQUERADE
```

## Create the image

From the guest, we can now create the image.

```bash
# Setup connectivity
sudo ip addr add 192.168.249.2/24 dev enp0s3
sudo ip route add default via 192.168.249.1
# Install necessary bundles
sudo swupd bundle-add clr-installer
sudo swupd bundle-add os-installer
# Download and update cloudguest image configuration
wget https://download.clearlinux.org/current/config/image/cloudguest.yaml
sed -i '/size: \"864M\"/d' cloudguest.yaml
sed -i 's/\"800M\"/\"2G\"/g' cloudguest.yaml
sed -i 's/bootloader,/bootloader,\n    iperf,/g' cloudguest.yaml
sed -i 's/systemd-networkd-autostart/sysadmin-basic,\n    systemd-networkd-autostart/g' cloudguest.yaml
# Create the custom cloudguest image
clr-installer -c cloudguest.yaml
# Make the guest accessible through ssh
sudo mkdir -p /etc/ssh
sudo bash -c "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config"
```

### Retrieve the image

Once the new image has been created and the guest is accessible through
`ssh`, it is time to retrieve the image from the host.

```bash
# Retrieve new image (this is a raw image)
scp root@192.168.249.2:cloudguest.img .
mv cloudguest.img clear-cloudguest-raw.img
# Create the QCOW image from the RAW image
qemu-img convert -p -f raw -O qcow2 clear-cloudguest-raw.img clear-cloudguest.img
# Compress the QCOW image
xz -k -T $(nproc) clear-cloudguest.img
```

## Switch CI to use the new image

### Upload to Azure storage

The next step is to update the image stored as part of the Azure storage
account, replacing it with the newly created image. This will make this
new image available from the integration tests.
This is usually achieved through the web interface.

### Update integration tests

Last step is about updating the integration tests to work with this new image.
The key point is to identify the UUID of this new image so that it can be used
directly from the tests.

Proceed as follow to determine this UUID:

```bash
# Mount the image
sudo mount -o loop,offset=$((2048 * 512)) clear-cloudguest-raw.img /mnt/
# Identify UUID
sudo cat /mnt/loader/entries/Clear-linux-kvm-*.conf | grep "root=PARTUUID="
# Unmount the image
sudo umount /mnt
```
