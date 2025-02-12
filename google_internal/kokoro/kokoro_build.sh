#!/bin/bash
# Copyright 2024 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Fail on any error.
set -e

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
# export TZ=Etc/UTC
# export PS4='+\t $(basename ${BASH_SOURCE[0]}):${LINENO} ' # xtrace prompt
# set -x

KOKORO_CHV_DIR="${KOKORO_ARTIFACTS_DIR}/git/cloud-hypervisor"

cd "${KOKORO_CHV_DIR}/google_internal/kokoro"

#shellcheck disable=SC1091
source "${KOKORO_CHV_DIR}/google_internal/lib_build.sh"

lib_build::set_rbe_flags

# clang is needed for virtio-bindings 0.2.4+
apt-get update && apt-get install --no-install-recommends --yes clang

# Convert space delimited string to array for bash
IFS=" " read -r -a BAZEL_DIRECT_ARGS <<< "$BAZEL_DIRECT_ARGS"

args=(
  "${BAZEL_STARTUP_ARGS_ABSL}"
  test
  "${BAZEL_DIRECT_ARGS[@]}"
  --config=kokoro
  --verbose_failures=true
  --experimental_convenience_symlinks=ignore
  --build_tag_filters=-nopresubmit
  --test_tag_filters=-nopresubmit
  --
  //...
)
./bazel_wrapper.py "${args[@]}"
