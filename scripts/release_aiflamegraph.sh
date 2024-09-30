#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function die() {
   echo $@
   exit 1
}

PROFILE_NAME="aiflamegraph-$(uname -n)-$(date '+%Y%m%d-%H%M')"

rm -f /tmp/${PROFILE_NAME}.stackcollapse

echo "Running profile... (ctrl-c when ready to stop)"
${DIR}/iaprof -q > /tmp/${PROFILE_NAME}.stackcollapse || die "Failed to run iaprof."
echo "Building flame graph..."
${DIR}/flamegraph.pl --colors=gpu < /tmp/${PROFILE_NAME}.stackcollapse > ${PROFILE_NAME}.svg || die "Error generating flame graph."
echo "  ${PROFILE_NAME}.svg"
rm -f /tmp/${PROFILE_NAME}.stackcollapse
