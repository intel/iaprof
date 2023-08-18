#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

bpftrace -v \
  -I /usr/include/libdrm ${BASE_DIR}/get_kernels.bt &
BPFTRACE_PID="$!"

echo "I just started bpftrace."
sleep 5

cd ${BASE_DIR}/../dummy_workload
./bude
cd ${BASE_DIR}

# IGT_DIR="${BASE_DIR}/../../reference/drivers.gpu.i915.igt-gpu-tools/build/benchmarks/"
# cd ${IGT_DIR}
# ./gem_blt
# WORKLOAD_PID=$!
# cd ${BASE_DIR}

kill -TERM ${BPFTRACE_PID}
wait ${BPFTRACE_PID}
