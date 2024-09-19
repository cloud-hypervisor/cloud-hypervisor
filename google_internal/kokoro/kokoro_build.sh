#!/bin/bash
set -e

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
export TZ=Etc/UTC
export PS4='+\t $(basename ${BASH_SOURCE[0]}):${LINENO} ' # xtrace prompt
set -x

KOKORO_CHV_DIR="${KOKORO_ARTIFACTS_DIR}/git/cloud-hypervisor"

cd "${KOKORO_CHV_DIR}/google_internal/kokoro"

#shellcheck disable=SC1091
source "${KOKORO_CHV_DIR}/google_internal/lib_build.sh"

lib_build::set_rbe_flags

args=(
  test
  --verbose_failures=true
  # --test_output=all
  --symlink_prefix=/
  --build_tag_filters=-nopresubmit
  --test_tag_filters=-nopresubmit
  --
  //...
)
./bazel_wrapper.py "${args[@]}"