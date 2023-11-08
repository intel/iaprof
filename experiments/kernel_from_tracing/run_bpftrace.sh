#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# cd ${BASE_DIR}/../dummy_workload
# ./bude &
# WORKLOAD_PID=$!
# cd ${BASE_DIR}

IGT_DIR="${BASE_DIR}/../../reference/drivers.gpu.i915.igt-gpu-tools/build/benchmarks/"
cd ${IGT_DIR}
./gem_blt &
WORKLOAD_PID=$!
cd ${BASE_DIR}

bpftrace -v \
  -I /usr/include/libdrm -p ${WORKLOAD_PID} ${BASE_DIR}/get_kernels_tracepoint.bt &
BPFTRACE_PID="$!"

sleep 0.5
cat /proc/${WORKLOAD_PID}/maps &> maps.txt

wait ${WORKLOAD_PID}

kill -TERM ${BPFTRACE_PID}
wait ${BPFTRACE_PID}
