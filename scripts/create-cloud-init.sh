#!/bin/bash
set -x

rm /tmp/clear-cloudinit.img
mkdosfs -n config-2 -C /tmp/clear-cloudinit.img 8192
mcopy -oi /tmp/clear-cloudinit.img -s test_data/cloud-init/clear/openstack ::

rm /tmp/ubuntu-cloudinit.img
mkdosfs -n cidata -C /tmp/ubuntu-cloudinit.img 8192
mcopy -oi /tmp/ubuntu-cloudinit.img -s test_data/cloud-init/ubuntu/user-data ::
mcopy -oi /tmp/ubuntu-cloudinit.img -s test_data/cloud-init/ubuntu/meta-data ::
mcopy -oi /tmp/ubuntu-cloudinit.img -s test_data/cloud-init/ubuntu/network-config ::

