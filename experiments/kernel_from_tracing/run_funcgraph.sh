#!/bin/bash

# Start and suspend the workload
./bude &
WORKLOAD_PID="$!"
kill -STOP ${WORKLOAD_PID}

# Start funcgraph
sudo funcgraph -p ${WORKLOAD_PID} -m 10 i915_gem_execbuffer2_ioctl &>test.txt &
FUNCGRAPH_PID="$!"

sleep 2

# Wait for the workload to finish
kill -CONT ${WORKLOAD_PID}
wait ${WORKLOAD_PID}

# Kill and wait for funcgraph to finish
kill -TERM ${FUNCGRAPH_PID}
wait ${FUNCGRAPH_PID}
