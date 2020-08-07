# How to test Vhost-user net with OpenVSwitch/DPDK

The purpose of this document is to illustrate how to test vhost-user-net in cloud-hypervisor with OVS/DPDK as the backend.

## Framework

It's a simple test to validate the communication between two virtual machine, connecting them to vhost-user ports respectively provided by `OVS/DPDK`.
```
             +----+----------+          +-------------+-----------+-------------+          +----------+----+  
             |    |          |          |             |           |             |          |          |    | 
             |    |vhost-user|----------| vhost-user  |   ovs     | vhost-user  |----------|vhost-user|    |           
             |    |net device|          | port 1      |           | port 2      |          |net device|    |           
             |    |          |          |             |           |             |          |          |    |           
             |    +----------+          +-------------+-----------+-------------+          +----------+    |           
             |               |          |                                       |          |               |           
             |vm1            |          |                  dpdk                 |          |           vm2 |           
             |               |          |                                       |          |               |           
          +--+---------------------------------------------------------------------------------------------+--+        
          |  |                                       hugepages                                             |  |        
          |  +---------------------------------------------------------------------------------------------+  |        
          |                                                                                                   |        
          |                                              host                                                 |        
          |                                                                                                   |  
          +---------------------------------------------------------------------------------------------------+        
```
## Prerequisites

Prior to running the test, the following steps need to be performed.
- Enable hugepages
- Install DPDK
- Install OVS

Here are some good references for detailing them.
- Red Hat
	* https://wiki.qemu.org/Documentation/vhost-user-ovs-dpdk
- Ubuntu server
	* https://help.ubuntu.com/lts/serverguide/DPDK.html
	* https://software.intel.com/en-us/articles/set-up-open-vswitch-with-dpdk-on-ubuntu-server

## Test
The test runs with multiple queue (MQ) support enabled, using 2 pairs of TX/RX queues defined for both OVS and the virtual machine. Here are the details on how the test can be run.

_Setup OVS_

`ovs_test.sh` is created to setup and start OVS. OVS will provide the `dpdkvhostuser` backend running in server mode.
```bash
mkdir -p /var/run/openvswitch
modprobe openvswitch
killall ovsdb-server ovs-vswitchd
rm -f /var/run/openvswitch/vhost-user*
rm -f /etc/openvswitch/conf.db
export DB_SOCK=/var/run/openvswitch/db.sock
ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
ovsdb-server --remote=punix:$DB_SOCK --remote=db:Open_vSwitch,Open_vSwitch,manager_options --pidfile --detach
ovs-vsctl --no-wait init
ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-lcore-mask=0xf
ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-socket-mem=1024
ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
ovs-vsctl --no-wait set Open_vSwitch . other_config:pmd-cpu-mask=0xf
ovs-vswitchd unix:$DB_SOCK --pidfile --detach --log-file=/var/log/openvswitch/ovs-vswitchd.log
ovs-vsctl add-br ovsbr0 -- set bridge ovsbr0 datapath_type=netdev
ovs-vsctl add-port ovsbr0 vhost-user1 -- set Interface vhost-user1 type=dpdkvhostuser
ovs-vsctl add-port ovsbr0 vhost-user2 -- set Interface vhost-user2 type=dpdkvhostuser
ovs-vsctl set Interface vhost-user1 options:n_rxq=2
ovs-vsctl set Interface vhost-user2 options:n_rxq=2
```
_Run ovs_test.sh_
```bash
./ovs_test.sh
```

_Launch the VMs_

VMs run in client mode. They connect to the socket created by the `dpdkvhostuser` backend.
```bash
# From one terminal. We need to give the cloud-hypervisor binary the NET_ADMIN capabilities for it to set TAP interfaces up on the host.
./cloud-hypervisor \
        --cpus boot=2 \
        --memory size=512M,hugepages=on,shared=true \
        --kernel vmlinux \
        --cmdline "console=ttyS0 console=hvc0 root=/dev/vda1 rw" \
        --disk path=focal-server-cloudimg-amd64.raw   \
        --net mac=52:54:00:02:d9:01,vhost_user=true,socket=/var/run/openvswitch/vhost-user1,num_queues=4

# From another terminal. We need to give the cloud-hypervisor binary the NET_ADMIN capabilities for it to set TAP interfaces up on the host.
./cloud-hypervisor \
        --cpus boot=2 \
        --memory size=512M,hugepages=on,shared=true \
        --kernel vmlinux \
        --cmdline "console=ttyS0 console=hvc0 root=/dev/vda1 rw" \
        --disk path=focal-server-cloudimg-amd64.raw   \
        --net "mac=52:54:20:11:C5:02,vhost_user=true,socket=/var/run/openvswitch/vhost-user2,num_queues=4"
```

_Setup VM1_
```bash
# From inside the guest
sudo ip addr add 172.100.0.1/24 dev enp0s3
```

_Setup VM2_
```bash
# From inside the guest
sudo ip addr add 172.100.0.2/24 dev enp0s3
```

_Ping VM1 from VM2_
```bash
# From inside the guest
sudo ping 172.100.0.1
```

_Ping VM2 from VM1_
```bash
# From inside the guest
sudo ping 172.100.0.2
```

__Result:__ At this point, VM1 and VM2 can ping each other successfully. We can now run `iperf3` test.

_Run VM1 as server_
```bash
# From inside the guest
iperf3 -s -p 4444
```

_Run VM2 as client_
```bash
# From inside the guest
iperf3 -c 172.100.0.1 -t 30 -p 4444 &
```

