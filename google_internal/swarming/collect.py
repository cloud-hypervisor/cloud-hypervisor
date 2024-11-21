#!/usr/bin/env python3

# This script collects the results of a Swarming task for a given test, and add
# it to a result file.

import argparse
import json
import os
import subprocess
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build_timestamp', help='Build timestamp, prefer YYYYMMDD-HHMMSS format')
    parser.add_argument('commit', help='CHV Commit SHA')
    parser.add_argument('test_name', help='Test name to use when storing the test results.')
    parser.add_argument('task_json', help='Task json file produced by Swarming trigger. The name of the test is this obtained from this file name by removing the ".json" extension.')
    parser.add_argument('--results_json', help='Results json file to store result')
    args = parser.parse_args()

    assert 'LUCI_ROOT' in os.environ.keys()

    #### Collect swarming result
    summary = 'summary.json'
    if os.path.exists(summary):
        os.remove(summary)
    cmd = [
        os.path.join(os.environ['LUCI_ROOT'], 'swarming'),
        'collect',
        '--server=https://chrome-swarming.appspot.com',
        '--task-summary-python',
        '--json-output', summary,
        '--requests-json', args.task_json
    ]
    if args.results_json is not None:
        cmd += ['--task-output-stdout=json']
    else:
        cmd += ['--task-output-stdout=console']
    if ('SWARMING_AUTH_FLAG' in os.environ.keys()) and (os.environ['SWARMING_AUTH_FLAG'] != ''):
        cmd += [ os.environ['SWARMING_AUTH_FLAG'] ]
    subprocess.call(cmd)
    assert os.path.exists(summary)

    #### Extract test results
    with open(summary, 'r') as f:
        result = json.load(f)
    assert len(result['shards']) == 1
    task_result = result['shards'][0]
    # For now, there is only one device (SEV-SNP), but we will add more fields to this once we get TDX.
    device = ''
    task_id = task_result['task_id']
    status = 'fail'
    exit_code_ok = ('exit_code' not in task_result.keys()) or (task_result['exit_code'] == '0')
    failure = ('failure' in task_result.keys()) and task_result['failure']
    internal_failure = ('internal_failure' in task_result.keys()) and task_result['internal_failure']
    if internal_failure:
        status = 'internal_failure'
    elif task_result['state'] == 'TIMED_OUT':
        status = 'timeout'
    elif task_result['state'] == 'EXPIRED':
        status = 'expired'
    elif (task_result['state'] == 'COMPLETED') and exit_code_ok and not failure and not internal_failure:
        status = 'pass'
    if args.results_json is not None:
        write_to_results(args, device, task_result, status)
    #### Exit code
    if status == 'pass' or status == 'expired' or status == 'internal_failure':
        return 0
    else:
        return 1



def write_to_results(args, device, task_result, status):
  print("Saving to", args.results_json)
  # Read previous results in the same file
  if os.path.exists(args.results_json):
    with open(args.results_json, 'r') as f:
      results = json.load(f)
  else:
    print('Warning: results file "%s" does not exist, it will be created' % args.results_json)
    results = {}

  if args.build_timestamp in results.keys():
    assert results[args.build_timestamp]['commit'] == args.commit
  else:
    results[args.build_timestamp] = {
      'commit': args.commit,
      'tests': {}
    }

  if device not in results[args.build_timestamp]['tests'].keys():
    results[args.build_timestamp]['tests'][device] = {}
  results[args.build_timestamp]['tests'][device][args.test_name] = {
    'task_id': task_result['task_id'],
    'status': status,
    'output': task_result['output'],
  }

  #### Limit results logs to 90 runs (by timestamp)
  num_runs = 90
  # Reverse-sort to get highest (more recent) timestamps at the list head
  timestamps = sorted(results.keys(), reverse=True)[:num_runs]
  new_results = {}
  for t in timestamps:
    new_results[t] = results[t]
  results = new_results

  #### Write back result file, with extended results
  os.makedirs(os.path.dirname(args.results_json), exist_ok=True)
  with open(args.results_json, 'w') as f:
    f.write(json.dumps(results, sort_keys=True, indent=2))

if __name__ == '__main__':
    sys.exit(main())