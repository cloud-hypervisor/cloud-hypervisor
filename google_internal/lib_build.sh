#!/bin/bash
# Based on Kiwi KV's lib_build

#######################################
# Configure and export the WORKSPACE variable in kokoro
# If set, skips
# If Kokoro, uses that specific path
# If not set, use top level
#######################################
function lib_build::set_workspace() {
  export WORKSPACE
  if [[ -v WORKSPACE ]]; then
    return
  fi
  if [[ -n ${KOKORO_ARTIFACTS_DIR} ]]; then
    # NOTE: Update path as needed
    WORKSPACE="${KOKORO_ARTIFACTS_DIR}/git/cloud-hypervisor"
  elif [[ -z ${WORKSPACE} ]]; then
    WORKSPACE="$(git rev-parse --show-toplevel)"
  fi
}

#######################################
# Set up bazel flags for use with RBE
#
# Optionally also set credentials
#######################################
function lib_build::set_rbe_flags() {
  lib_build::set_workspace

  # Relative, for bazel_debian
  export BAZEL_STARTUP_ARGS="--bazelrc=google_internal/.bazelrc"
  # Absl for bazel_rbe to run in any sub-folder
  export BAZEL_STARTUP_ARGS_ABSL="--bazelrc=${WORKSPACE}/google_internal/.bazelrc"
  declare -a _BAZEL_ARGS=(
    "--config=rbecache"
  )

  # Cleaner as arrays, but needed this way for bazel-debian etc.
  export BAZEL_DIRECT_ARGS="${_BAZEL_ARGS[*]} --google_default_credentials"
  declare -a DOCKER_RUN_ARGS
  # optionally set credentials (likely useful only if executing this outside kokoro)
  declare -r HOST_CREDS_JSON="${HOME}/.config/gcloud/application_default_credentials.json"
  if [[ -s ${HOST_CREDS_JSON} ]]; then
    declare -r CREDS_JSON=/gcloud/application_default_credentials.json
    export BAZEL_EXTRA_ARGS="${_BAZEL_ARGS[*]} --google_credentials=${CREDS_JSON}"
    DOCKER_RUN_ARGS+=(
      "--volume ${HOST_CREDS_JSON}:${CREDS_JSON}"
    )
  else
    export BAZEL_EXTRA_ARGS="${BAZEL_DIRECT_ARGS}"
  fi
  export EXTRA_DOCKER_RUN_ARGS="${DOCKER_RUN_ARGS[*]}"
}
