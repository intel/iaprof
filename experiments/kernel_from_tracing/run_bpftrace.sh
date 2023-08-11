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

kill -TERM ${BPFTRACE_PID}
wait ${BPFTRACE_PID}
