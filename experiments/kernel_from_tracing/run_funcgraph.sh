#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start and suspend the workload
cd ${BASE_DIR}/../dummy_workload
./bude &
WORKLOAD_PID="$!"
kill -STOP ${WORKLOAD_PID}
cd ${BASE_DIR}

# Start funcgraph
sudo funcgraph -p ${WORKLOAD_PID} -m 10 i915_gem_execbuffer2_ioctl &>${BASE_DIR}/funcgraph.txt &
FUNCGRAPH_PID="$!"

sleep 2

# Wait for the workload to finish
kill -CONT ${WORKLOAD_PID}
wait ${WORKLOAD_PID}

# Kill and wait for funcgraph to finish
kill -TERM ${FUNCGRAPH_PID}
wait ${FUNCGRAPH_PID}
