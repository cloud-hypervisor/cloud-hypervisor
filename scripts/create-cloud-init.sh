#!/bin/bash
set -x

rm -f /tmp/ubuntu-cloudinit.img
mkdosfs -n CIDATA -C /tmp/ubuntu-cloudinit.img 8192
mcopy -oi /tmp/ubuntu-cloudinit.img -s test_data/cloud-init/ubuntu/local/user-data ::
mcopy -oi /tmp/ubuntu-cloudinit.img -s test_data/cloud-init/ubuntu/local/meta-data ::
mcopy -oi /tmp/ubuntu-cloudinit.img -s test_data/cloud-init/ubuntu/local/network-config ::

