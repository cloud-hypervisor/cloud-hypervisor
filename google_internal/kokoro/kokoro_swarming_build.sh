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

## Set for debugging
set -e
# set -x

KOKORO_CHV_DIR="${KOKORO_ARTIFACTS_DIR}/git/cloud-hypervisor"
CHV_SWARMING_DIR="${KOKORO_CHV_DIR}/google_internal/swarming"

# Install latest bazel
# Despite the image having 7.4.1, it only seems to find 6.5.0
BAZEL_VERSION=bazel-7.4.1-linux-x86_64
BAZEL_TMP_DIR=/tmpfs/tmp/bazel-release
mkdir -p "${BAZEL_TMP_DIR}"
echo "Bazel file: ${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
ls "${KOKORO_GFILE_DIR}"
ln -fs "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}" "${BAZEL_TMP_DIR}/bazel"
chmod 755 "${KOKORO_GFILE_DIR}/${BAZEL_VERSION?}"
export PATH="${BAZEL_TMP_DIR}:${PATH}"

# This should show /tmpfs/tmp/bazel-release/bazel
# which bazel
KOKORO_LOCAL_DIR="${KOKORO_ARTIFACTS_DIR}/git/cloud-hypervisor/google-internal/kokoro"

cd "${KOKORO_CHV_DIR}/google_internal/kokoro"

# TODO (b/395680242): RBE Support for CHV
# source "${KOKORO_CHV_DIR}/google_internal/lib_build.sh"
# lib_build::set_rbe_flags

args=(
  build
  --verbose_failures=true
  # --test_output=all
  # --symlink_prefix=/
  # --build_tag_filters=-nopresubmit
  # --test_tag_filters=-nopresubmit
  --dynamic_mode=off
  --
  //...
)
./bazel_wrapper.py "${args[@]}"

# Hardcoded list of tests for now
# TODO(b/394357849): Create script to parse bazel-bin tests instead of hardcode
TESTS_LIST=(
  "arch"
  "block"
  "devices"
  "hypervisor"
  "option_parser"
  "pci"
  "rate_limiter"
  "tpm"
  "virtio-devices"
  "vm-allocator"
  "vm-device"
  "vmm"
)

SWARMING_TEST_DIR=${KOKORO_ARTIFACTS_DIR}/swarming_test
mkdir -p "${SWARMING_TEST_DIR}/tests"

for TEST_NAME in ${TESTS_LIST[@]}; do
  echo "Copying test: ${TEST_NAME}"
  mkdir -p "${SWARMING_TEST_DIR}/tests/${TEST_NAME}"
  cp "${KOKORO_CHV_DIR}/bazel-bin/${TEST_NAME}/test-"*"/${TEST_NAME}_test" "${SWARMING_TEST_DIR}/tests/${TEST_NAME}/${TEST_NAME}_test"
done

### Install and set up swarming/isolate
export LUCI_ROOT="`pwd`/luci"
mkdir -p ${LUCI_ROOT}

git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="`pwd`/depot_tools:$PATH"
(
  INFRA_GIT_REVISION=9ea28c0ad6f003d65a6e559e60f5f78029c4cf85
  echo 'infra/tools/luci/isolate/${platform} git_revision:'"${INFRA_GIT_REVISION}"
  echo 'infra/tools/luci/swarming/${platform} git_revision:'"${INFRA_GIT_REVISION}"
) > ${LUCI_ROOT}/ensure_file.txt
cipd ensure -ensure-file ${LUCI_ROOT}/ensure_file.txt -root ${LUCI_ROOT}

KOKORO_KEY_NAME="78411_swarming-service-key"
KOKORO_KEY_PATH="${KOKORO_KEYSTORE_DIR}/${KOKORO_KEY_NAME}"
export SWARMING_AUTH_FLAG="--service-account-json=${KOKORO_KEY_PATH}"
export SWARMING_TASK_PREFIX="Kokoro_PR${KOKORO_GITHUB_PULL_REQUEST_NUMBER}"

# Swarming environment

pushd "${SWARMING_TEST_DIR}"

# Trigger the tests. Record trigger failures, but continue to trigger other
# tests and collect their results, such that a single trigger failure does
# not ruin a whole Swarming run.
SWARMING_TRIGGER_ERROR=0

for TEST_DIR in tests/*; do
  TEST_BINARY=$(basename ${TEST_DIR})
  FULL_BINARY_PATH="${TEST_DIR}/${TEST_BINARY}_test"

  set +e
  "${CHV_SWARMING_DIR}/trigger.py" --prefix "${SWARMING_TASK_PREFIX}" "${TEST_DIR}" "${FULL_BINARY_PATH}"
  EXIT_CODE=$?
  set -e
  if [ ${EXIT_CODE} -ne 0 ] ; then
    echo "Swarming trigger error on test: ${TEST_NAME}"
    SWARMING_TRIGGER_ERROR=1
  fi
done

popd

##
## Collect swarming test results
##
pushd "${SWARMING_TEST_DIR}"

SWARMING_FAILURE=0
for TEST_NAME in triggered/*/*.json ; do
  echo "Collecting for test name: ${TEST_NAME}"
  set +e
  "${CHV_SWARMING_DIR}/collect.py" "${SWARMING_TIMESTAMP}" "${KOKORO_GIT_COMMIT}" "$(basename "${TEST_NAME}" .json)" "${TEST_NAME}"
  EXIT_CODE=$?
  set -e
  if [ ${EXIT_CODE} -eq 0 ] ; then
    echo "PASS ${TEST_NAME}"
  else
    echo "FAIL ${TEST_NAME}"
    SWARMING_FAILURE=1
  fi
done
popd

if [ ${SWARMING_FAILURE} -eq 1 ] ; then
  echo "Error: some Swarming test failed"
  exit 1
fi

if [ ${SWARMING_TRIGGER_ERROR} -eq 1 ] ; t  hen
  echo "Error: could not trigger some Swarming tests"
  exit 1
fi