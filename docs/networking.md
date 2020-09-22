# How to use networking

cloud-hypervisor can emulate one or more virtual network interfaces, represented at the hypervisor host by [tap devices](https://www.kernel.org/doc/Documentation/networking/tuntap.txt). This guide briefly describes, in a manual and distribution neutral way, how to setup and use networking with cloud-hypervisor.

## Multiple queue support for net devices ##

While multiple vcpus defined for guest, to gain the benefit of vcpu scalable to improve performance, it suggests to define multiple queue pairs for net devices, one Tx/Rx queue pair per one vcpu, that means the number of queue pairs at least is equal to the vcpu count. In that case, after virtnet driver set cpu affinity for virtqueues in guest kernel, vcpus could handle interrupt from different virtqueue pairs in parallel.

It will gain better performance for guest that has multiple queues defined for net devices while it has multiple net sessions running in userspace.

To enable multiple queue support in cloud-hypervisor, multiple queue pairs will be defined, while multiple tap fds will be opened for the same tap device, it will also have multiple threads started, each thread will monitor and handle the events from each virtqueue pairs and the associated tap fd.

Note:

- Currently, it does not support to use ethtool to change the combined queue numbers in guest.
- Multiple queue is enabled for vhost-user-net backend in cloud-hypervisor, however, multiple thread is not added to handle mq, thus, the performance for vhost-user-net backend is not supposed to be improved. The multiple thread will be added for backend later.
- Performance test for vhost-user-net will be covered once vhost-user-net backend has multiple thread supported.
- Performance test for virtio-net is done by comparing 2 queue pairs with 1 queue pairs, that to run 2 iperf3 sessions in the same test environments, throughput is improved about 37%.

## Start cloud-hypervisor with net devices

Use one `--net` command-line argument from cloud-hypervisor to specify the emulation of one or more virtual NIC's. The example below instructs cloud-hypervisor to emulate for instance 2 virtual NIC's:

```bash
./cloud-hypervisor \
    --cpus 4 \
    --memory "size=512M" \
    --disk path=focal-server-cloudimg-amd64.raw \
    --kernel my-vmlinux.bin \
    --cmdline "console=ttyS0 console=hvc0 root=/dev/vda1 rw" \
    --net tap=ich0,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0,num_queues=2,queue_size=256 \
          tap=ich1,mac=a4:a1:c2:00:00:02,ip=10.0.1.2,mask=255.255.255.0,num_queues=2,queue_size=256
```

The `--net` argument takes 1 or more space-separated strings of key value pairs containing the following 4 keys or fields:

| Name       | Purpose                    | Optional  |
| -----------|----------------------------| ----------|
| tap        | tap device name            | Yes       |
| mac        | vNIC mac address           | Yes       |
| ip         | tap IP IP address          | yes       |
| mask       | tap IP netmask             | Yes       |
| num_queues | the number of queues       | yes       |
| queue_size | the size of each queue     | Yes       |

num_queues is the total number of tx and rx queues, the default value is 2, and it could be increased by multiples of 2. Additionally, num_queues is suggested to be as 2 times of vcpu count. The default value for queue_size is 256.

If the tap device is pre-created on host before guest boot up. To use multiple queue support for net device in guest, the tap device should be opened like this from host.

```bash
[root@localhost ~]# ip tuntap add name ich0 mode tap multi_queue
```

And the `--net` device should specify support for multiple queues. `num_queues` must be a multiple of 2 starting at least from 4 since multiple queues really means multiple queue pairs. We need at least 2 pairs for this configuration to be correct:

```bash
--net tap=ich0,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0,num_queues=4,queue_size=256
```

## Configure the tap devices

After starting cloud-hypervisor as shown above, 2 tap devices with state down will become available at the host:

```bash
root@host:~# ip link show ich0
78: ich0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 72:54:12:ff:ce:6f brd ff:ff:ff:ff:ff:ff
root@host:~# ip link show ich1
79: ich1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 06:7a:fc:1b:9a:67 brd ff:ff:ff:ff:ff:ff
```

Set the tap devices to up state:

```bash
root@host:~# ip link set up ich0
root@host:~# ip link set up ich1

root@host:~# ip link show ich0
78: ich0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 72:54:12:ff:ce:6f brd ff:ff:ff:ff:ff:ff
root@host:~# ip link show ich1
79: ich1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 06:7a:fc:1b:9a:67 brd ff:ff:ff:ff:ff:ff
```

## Connect tap devices

Different networking models can be used to provide external connectivity. In this example we will
use 2 linux bridges emulating 2 different networks. The integration bridge (ich-int) in this example will also be used
for external connectivity.

Create the bridges and connect the cloud-hypervisor tap devices to the bridges:

```bash
root@host:~# brctl addbr ich-int
root@host:~# brctl addbr ich-dpl
root@host:~# ip link set up ich-int
root@host:~# ip link set up ich-dpl
root@host:~# brctl addif ich-int ich0
root@host:~# brctl addif ich-dpl ich1
root@host:~# brctl show
bridge name     bridge id               STP enabled     interfaces
ich-dpl         8000.067afc1b9a67       no              ich1
ich-int         8000.725412ffce6f       no              ich0
```
This completes the layer 2 wiring: The cloud-hypervisor is now connected to the hypervisor host via the 2 linux bridges.

## IP (Layer 3) provisioning

### Hypervisor host

On the hypervisor host add the network gateway IP address of each network to the 2 linux bridges:

```bash
root@host:~# ip addr add 192.168.4.1/24 dev ich-int
root@host:~# ip addr add 10.0.1.1/24 dev ich-dpl
```
The routing table of the hypervisor host should now also have corresponding routing entries:

```bash
root@host:~# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.178.1   0.0.0.0         UG    600    0        0 wlan1
10.0.1.0        0.0.0.0         255.255.255.0   U     0      0        0 ich-dpl
192.168.4.0     0.0.0.0         255.255.255.0   U     0      0        0 ich-int
192.168.178.0   0.0.0.0         255.255.255.0   U     600    0        0 wlan1
```
### Virtual Machine

Within the virtual machine set the vNIC's to up state and provision the corresponding IP addresses on the 2 vNIC's. The steps outlined below use the ip command as an example. Alternative distribution specific procedures can also apply.   

```bash
root@guest:~# ip link set up enp0s2
root@guest:~# ip link set up enp0s3
root@guest:~# ip addr add 192.168.4.2/24 dev enp0s2
root@guest:~# ip addr add 10.0.1.2/24 dev enp0s3
```

IP connectivity between the virtual machine and the hypervisor-host can be verified by sending
ICMP requests to the hypervisor-host for the gateway IP address from within the virtual machine:

```bash
root@guest:~# ping 192.168.4.1
PING 192.168.4.1 (192.168.4.1) 56(84) bytes of data.
64 bytes from 192.168.4.1: icmp_seq=1 ttl=64 time=0.456 ms
64 bytes from 192.168.4.1: icmp_seq=2 ttl=64 time=0.226 ms
root@guest:~# ping 10.0.1.1
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=64 time=0.449 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=64 time=0.393 ms
```

The connection can now be used for instance to log into the virtual machine with
ssh under the precondition that the machine has an ssh daemon provisioned:

```bash
root@host:~# ssh root@192.168.4.2
The authenticity of host '192.168.4.2 (192.168.4.2)' can't be established.
ECDSA key fingerprint is SHA256:qNAUmTtDMW9pNuZARkpLQhfw+Yc1tqUDBrQp7aZGSjw.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.4.2' (ECDSA) to the list of known hosts.
root@192.168.4.2's password:
Linux cloud-hypervisor 5.2.0 #2 SMP Thu Jul 11 08:08:16 CEST 2019 x86_64

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.                                                         


Last login: Fri Jul 12 13:27:56 2019 from 192.168.4.1
root@guest:~#
```

## Internet connectivity

To enable internet connectivity a default gw and a nameserver has to be set within
the virtual machine:

```bash
root@guest:~# ip route add default via 192.168.4.1
root@guest:~# cat /etc/resolv.conf
options timeout:2
domain vallis.nl
search vallis.nl
nameserver 192.168.178.1
```

make sure that the default gateway of the hypervisor host (in this example host 192.168.178.1 which is an adsl router) has an entry in the routing table for the 192.168.4.0/24 network otherwise IP connectivity will not work.

```bash
root@guest:~# nslookup  ftp.nl.debian.org       
Server:         192.168.178.1
Address:        192.168.178.1#53

Non-authoritative answer:
cdn-fastly.deb.debian.org       canonical name = prod.debian.map.fastly.net.
Name:   prod.debian.map.fastly.net
Address: 151.101.36.204

root@guest:~# apt-get update
Ign:1 http://cdn-fastly.deb.debian.org/debian stretch InRelease
Get:2 http://cdn-fastly.deb.debian.org/debian stretch Release [118 kB]
Get:3 http://cdn-fastly.deb.debian.org/debian stretch Release.gpg [2434 B]
Fetched 120 kB in 1s (110 kB/s)
```
