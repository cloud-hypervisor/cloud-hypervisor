#!/bin/env python3
#
# Copyright © 2024 Institute of Software, CAS. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

import subprocess
import json
from argparse import ArgumentParser
from collections import defaultdict

def get_cargo_metadata():
    result = subprocess.run(
        ['cargo', 'metadata', '--format-version=1'],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        exit(1)

    metadata = json.loads(result.stdout)
    return metadata

def find_dependents_of_package(metadata, package_source):
    """Find dependencies based on the provided source identifier and return related package info."""
    packages = defaultdict(list)
    direct_dependents = defaultdict(list)

    # Identify packages from the given package source and record version
    for pkg in metadata['packages']:
        repository = pkg['repository'] or ''
        if package_source in repository:
            packages[pkg['name']].append(pkg['version'])

    # Find packages that immediately depend on the identified source packages
    for node in metadata['resolve']['nodes']:
        current_pkg = next(pkg for pkg in metadata['packages'] if pkg['id'] == node['id'])
        current_pkg_name = current_pkg['name']
        current_pkg_version = current_pkg['version']

        for dep_id in node['dependencies']:
            dep_pkg = next(pkg for pkg in metadata['packages'] if pkg['id'] == dep_id)
            dep_name = dep_pkg['name']
            dep_version = dep_pkg['version']

            if dep_name in packages:
                direct_dependents[(dep_name, dep_version)].append((current_pkg_name, current_pkg_version))

    return packages, direct_dependents

def check_for_version_conflicts(packages, direct_dependents):
    """Check if there are multiple versions of dependencies, and return True if conflicts are found."""
    has_conflicts = False

    for pkg_name, versions in packages.items():
        if len(set(versions)) > 1:
            has_conflicts = True
            print(f"Error: Multiple versions detected for {pkg_name}: {set(versions)}")
            for version in set(versions):
                print(f"  Version {version} used by:")
                for dependent, dep_version in direct_dependents[(pkg_name, version)]:
                    print(f"          - {dependent} v{dep_version}")

    return has_conflicts

if __name__ == '__main__':
    parser = ArgumentParser(description='Cargo dependency conflict checker.')
    parser.add_argument('package_source', type=str, help='A keyword used to match the repository URL field')
    args = parser.parse_args()

    metadata = get_cargo_metadata()
    if metadata is None:
        print("Error: Metadata is empty")
        exit(1)

    packages, direct_dependents = find_dependents_of_package(metadata, args.package_source)

    has_conflicts = check_for_version_conflicts(packages, direct_dependents)

    if has_conflicts:
        exit(1)

