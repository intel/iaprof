#!/usr/bin/env bash

function die() {
   echo $@
   exit 1
}

readonly SCRIPT="${BASH_SOURCE[0]}"
readonly DIR="${SCRIPT%/*}"

FILTER_CPYTHON=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-filter-cpython ) FILTER_CPYTHON=false; shift;;
        -- ) shift; break;;
        * ) die "Unknown option '$1'"; break;;
    esac
done


PROFILE_NAME="aiflamegraph-$(uname -n)-$(date '+%Y%m%d-%H%M')"

rm -f /tmp/${PROFILE_NAME}.stackcollapse

for f in /sys/class/drm/card*/prelim_enable_eu_debug; do echo 1 | sudo tee "$f"; done
export ZET_ENABLE_PROGRAM_DEBUGGING=1
export NEOReadDebugKeys=1
export ONEDNN_JIT_PROFILE=6
sysctl kernel.perf_event_max_stack=512
sysctl kernel.perf_event_max_contexts_per_stack=64

printf "Running profile... (ctrl-c when ready to stop)\n"
${DIR}/iaprof -q > /tmp/${PROFILE_NAME}.stackcollapse || die "Failed to run iaprof."
printf "Building flame graph (this can take a minute)...\n"

SEDSTR=""
if [[ "${FILTER_CPYTHON}" == "true" ]]; then
    SEDSTR='s/_Py[^;]*;//g'
    SEDSTR+=';s/Py(Object|Eval|Number)_[^;]*;//g'
    SEDSTR+=';s/run_mod;//g'
    SEDSTR+=';s/run_eval_code_obj;//g'
    SEDSTR+=';s/cfunction_call;//g'
    SEDSTR+=';s/slot_nb_multiply;//g'
    SEDSTR+=';s/slot_tp_call;//g'
    SEDSTR+=';s/(method_)?vectorcall[^;]*;//g'
fi

sed -E "${SEDSTR}" < /tmp/${PROFILE_NAME}.stackcollapse |
    ${DIR}/deps/flamegraph/flamegraph.pl --colors=gpu > ${PROFILE_NAME}.svg || die "Error generating flame graph."

printf "  ${PROFILE_NAME}.svg\n"

rm -f /tmp/${PROFILE_NAME}.stackcollapse
