#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

sudo bpftrace -v \
  -I /usr/include/libdrm ${BASE_DIR}/get_kernels.bt \
  &>${BASE_DIR}/bpftrace.txt &
BPFTRACE_PID="$!"

sleep 2

cd ${BASE_DIR}/../dummy_workload
./bude
cd ${BASE_DIR}

# IGT_DIR="${BASE_DIR}/../../reference/drivers.gpu.i915.igt-gpu-tools/build/benchmarks/"
# cd ${IGT_DIR}
# sudo ./gem_blt &
# WORKLOAD_PID=$!
# cd ${BASE_DIR}

sleep 3
sudo cat /proc/${WORKLOAD_PID}/maps &> maps.txt

kill -TERM ${BPFTRACE_PID}
wait ${BPFTRACE_PID}
