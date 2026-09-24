#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$BENCHMARK_DIR/common.sh"

CLOUD_INIT_PATH=${CLOUD_INIT_PATH:-$RESULTS_DIR/cloud-init.img}
GUEST_IP=${GUEST_IP:-192.168.2.2}
GUEST_PREFIX=${GUEST_PREFIX:-25}
GUEST_GATEWAY=${GUEST_GATEWAY:-192.168.2.1}
GUEST_MAC=${GUEST_MAC:-12:34:56:78:90:ab}

for command_name in mkdosfs mcopy; do
    command -v "$command_name" >/dev/null || {
        echo "$command_name is required to create the cloud-init disk" >&2
        exit 1
    }
done

working_dir=$(mktemp -d)
trap 'rm -rf "$working_dir"' EXIT

cat >"$working_dir/meta-data" <<EOF
instance-id: ch-benchmark-$(date +%s%N)
local-hostname: cloud
EOF

cat >"$working_dir/user-data" <<'EOF'
#cloud-config
users:
  - name: cloud
    passwd: $6$7125787751a8d18a$sHwGySomUA1PawiNFWVCKYQN.Ec.Wzz0JtPPL1MvzFrkwmop2dq7.4CYf03A5oemPQ4pOFCCrtCelvFBEle/K.
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    shell: /bin/bash
ssh_pwauth: true
ssh_deletekeys: true
ssh_genkeytypes: [rsa, ecdsa, ed25519]
chpasswd:
  expire: false
EOF

cat >"$working_dir/network-config" <<EOF
version: 2
ethernets:
  benchmark0:
    match:
      macaddress: $GUEST_MAC
    addresses: [$GUEST_IP/$GUEST_PREFIX]
    gateway4: $GUEST_GATEWAY
EOF

mkdir -p "$(dirname -- "$CLOUD_INIT_PATH")"
rm -f -- "$CLOUD_INIT_PATH"
mkdosfs -n CIDATA -C "$CLOUD_INIT_PATH" 8192 >/dev/null
mcopy -o -i "$CLOUD_INIT_PATH" \
    "$working_dir/user-data" \
    "$working_dir/meta-data" \
    "$working_dir/network-config" ::

echo "Cloud-init disk created: $CLOUD_INIT_PATH"