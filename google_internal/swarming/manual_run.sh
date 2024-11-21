#!/bin/bash
# This script enables to run a Swarming test outside of the Kokoro workflow

set -e
set -x

SWARMING_TEST_DIR=$1
if [ -z "${SWARMING_TEST_DIR}" -o ! -d "${SWARMING_TEST_DIR}" ] ; then
  echo "Error: missing or invalid test directory argument."
  echo "Usage: `basename $0`"
  exit 1
fi


export SWARMING_AUTH_FLAG=""
export SWARMING_TIMESTAMP=`date '+%Y%m%d-%H%M%S'`
export SWARMING_TASK_PREFIX="Manual"

rm -rf triggered/

./trigger.py --prefix ${SWARMING_TASK_PREFIX} ${SWARMING_TEST_DIR}
set +e

for t in triggered/*/*.json; do
  ./collect.py ${SWARMING_TIMESTAMP} "manual" `basename ${t} .json` ${t} triggered/results.json
done