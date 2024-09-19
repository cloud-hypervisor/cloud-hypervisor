#!/usr/bin/python3
"""bazel_wrapper.py helps user populate configs for BES and foundry.

This is a modified copy of google3/devtools/kokoro/scripts/bazel_wrapper.py

Currently, RBE is disabled, so this builds using local bazel.
"""

import os
import subprocess
import sys
import uuid


def BuildBazelCommand(argv, invocation_id):
  """Build bazel command that can be executed.

  Args:
    argv: string list that contains the command line argument.
    invocation_id: string invocation ID
  Returns:
    String list that contains bazel commands and flags.
  """
  cmd_flags = argv[1:]

  # Use the default bazel from $PATH
  cmd = ['bazel']
  # bazel use '--' to prevent the '-//foo' target be interpreted as an option.
  # any option added after '--' will treated as targets.
  if '--' not in cmd_flags:
    # Add all existing command line flags and options.
    cmd.extend(cmd_flags)
    cmd.append('--invocation_id=' + invocation_id)
  else:
    index = cmd_flags.index('--')
    bazel_flags = cmd_flags[:index]
    bazel_targets = cmd_flags[index:]
    cmd.extend(bazel_flags)
    cmd.append('--invocation_id=' + invocation_id)
    cmd.extend(bazel_targets)
  return cmd


def InjectInvocationId():
  """Create an invocation ID for the bazel, and write it as an artifact.

  Kokoro will later on use that to post the bazel invocation details.

  Returns:
    String UUID to be used as invocation ID.
  """
  invocation_id = str(uuid.uuid4())
  bazel_invocation_artifacts = os.path.join(
      os.environ.get('KOKORO_ARTIFACTS_DIR'), 'bazel_invocation_ids')
  with open(bazel_invocation_artifacts, 'a') as f:
    f.write(invocation_id + '\n')

  return invocation_id


def main(argv):
  invocation_id = InjectInvocationId()
  cmd = BuildBazelCommand(argv, invocation_id)
  print('executing following commands:')
  print(cmd)
  sys.exit(subprocess.call(cmd))


if __name__ == '__main__':
  main(sys.argv)