# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Test the coverage and update the threshold when coverage is increased."""

import os, re, shutil, subprocess
import pytest

def _get_current_coverage():
    """Helper function that returns the coverage computed with kcov."""
    kcov_ouput_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "kcov_output"
    )

    # By default the build output for kcov and unit tests are both in the debug
    # directory. This causes some linker errors that I haven't investigated.
    # Error: error: linking with `cc` failed: exit code: 1
    # An easy fix is to have separate build directories for kcov & unit tests.
    kcov_build_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "kcov_build"
    )

    # Remove kcov output and build directory to be sure we are always working
    # on a clean environment.
    shutil.rmtree(kcov_ouput_dir, ignore_errors=True)
    shutil.rmtree(kcov_build_dir, ignore_errors=True)

    exclude_pattern = (
        '${CARGO_HOME:-$HOME/.cargo/},'
        'usr/lib/,'
        'lib/'
    )
    exclude_region = "'mod tests {'"

    kcov_cmd = "CARGO_TARGET_DIR={} cargo kcov --all " \
               "--output {} -- " \
               "--exclude-region={} " \
               "--exclude-pattern={} " \
               "--verify".format(
        kcov_build_dir,
        kcov_ouput_dir,
        exclude_region,
        exclude_pattern
    )

    subprocess.run(kcov_cmd, shell=True, check=True)

    # Read the coverage reported by kcov.
    coverage_file = os.path.join(kcov_ouput_dir, 'index.js')
    with open(coverage_file) as cov_output:
        coverage = float(re.findall(
            r'"covered":"(\d+\.\d)"',
            cov_output.read()
        )[0])

    # Remove coverage related directories.
    shutil.rmtree(kcov_ouput_dir, ignore_errors=True)
    shutil.rmtree(kcov_build_dir, ignore_errors=True)

    return coverage


def _get_previous_coverage():
    """Helper function that returns the last reported coverage."""
    coverage_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'coverage'
    )

    # The first and only line of the file contains the coverage.
    with open(coverage_path) as f:
        coverage = f.readline()
    return float(coverage.strip())

def _update_coverage(cov_value):
    """Updates the coverage in the coverage file."""
    coverage_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'coverage'
    )

    with open(coverage_path, "w") as f:
        f.write(str(cov_value))

def test_coverage(profile):
    current_coverage = _get_current_coverage()
    previous_coverage = _get_previous_coverage()
    if previous_coverage < current_coverage:
        if profile == pytest.profile_ci:
            # In the CI Profile we expect the coverage to be manually updated.
            assert False, "Coverage is increased from {} to {}. " \
                          "Please update the coverage in " \
                          "tests/coverage.".format(
                previous_coverage,
                current_coverage
            )
        elif profile == pytest.profile_devel:
            _update_coverage(current_coverage)
        else:
            # This should never happen because pytest should only accept
            # the valid test profiles specified with `choices` in
            # `pytest_addoption`.
            assert False, "Invalid test profile."
    elif previous_coverage > current_coverage:
        diff = float(previous_coverage - current_coverage)
        assert False, "Coverage drops by {:.2f}%. Please add unit tests for" \
                      "the uncovered lines.".format(diff)
