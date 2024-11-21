#!/usr/bin/env python3

# This script triggers a Swarming task for a given test.

import argparse
import hashlib
import json
import os
import subprocess
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('test_dir', help='Path to a test directory')
    parser.add_argument('--prefix', help='Prefix for Swarming task name')
    parser.add_argument('test_script', help='Name of shell script to run in test_dir')
    args = parser.parse_args()

    assert 'LUCI_ROOT' in os.environ.keys()
    assert os.path.isdir(args.test_dir)
    test_dir = os.path.normpath(args.test_dir)
    prefix = ''
    if args.prefix:
        prefix = args.prefix + '_'

    swarming_params = {
        'test_dir': test_dir,
        'test_name': os.path.basename(test_dir),
        'task_prefix': prefix,
        'devices': ['sev-snp'],
        'priority': '100',
        'timeout': '300',
        'expiration': '600',
    }

    params_file = os.path.join(test_dir, 'params.json')
    if os.path.isfile(params_file):
        with open(params_file, 'r') as f:
            params = json.load(f)
        for key in params.keys():
            swarming_params[key] = params[key]
    swarming_params['task_name'] = swarming_params['task_prefix'] + swarming_params['test_name']

    isolate_file = swarming_params['test_name'] + '.isolate'
    isolate_body = """{
  'variables': {
    'files': [
""" + "'" + swarming_params['test_dir'] + "/'" + """,
    ]
  },
}
"""
    with open(isolate_file, 'w') as f:
        f.write(isolate_body)

    digest_file = swarming_params['test_name'] + '.digest.json'
    if os.path.exists(digest_file):
        os.remove(digest_file)
    cmd = [
        os.path.join(os.environ['LUCI_ROOT'], 'isolate'),
        'archive',
        '-cas-instance', 'chrome-swarming',
        '--isolate', isolate_file,
        '--dump-json', digest_file,
        ]
    if ('SWARMING_AUTH_FLAG' in os.environ.keys()) and (os.environ['SWARMING_AUTH_FLAG'] != ''):
        cmd += [ os.environ['SWARMING_AUTH_FLAG'] ]

    subprocess.run(cmd, check=True)
    assert os.path.isfile(digest_file)

    digest = ''
    with open(digest_file, 'r') as f:
        j = json.load(f)
        digest = j[swarming_params['test_name']]
    assert digest != ''

    for device in swarming_params['devices']:
        triggered_dir = os.path.join('triggered', device)
        os.makedirs(triggered_dir, exist_ok=True)
        task_json = os.path.join(triggered_dir, swarming_params['test_name'] + '.json')

        if os.path.exists(task_json):
            os.remove(task_json)
        cmd = [
            os.path.join(os.environ['LUCI_ROOT'], 'swarming'),
            'trigger',
            '--server=https://chrome-swarming.appspot.com',
            '--digest', digest,
            '--task-name', swarming_params['task_name'],
            '--dump-json', task_json,
            '--dimension', 'pool=chv-lab',
            '--priority', swarming_params['priority'],
            '--expiration', swarming_params['expiration'],
            '--hard-timeout', swarming_params['timeout'],
        ]
        if ('SWARMING_AUTH_FLAG' in os.environ.keys()) and (os.environ['SWARMING_AUTH_FLAG'] != ''):
            cmd += [ os.environ['SWARMING_AUTH_FLAG'] ]
        cmd += [
            '--',
            args.test_script,
        ]
        subprocess.run(cmd, check=True)
        assert os.path.isfile(task_json)


if __name__ == '__main__':
    sys.exit(main())