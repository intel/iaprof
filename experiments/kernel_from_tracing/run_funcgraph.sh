#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start and suspend the workload
# cd ${BASE_DIR}/../dummy_workload
# ./bude &
# WORKLOAD_PID="$!"
# kill -STOP ${WORKLOAD_PID}
# cd ${BASE_DIR}

IGT_DIR="${BASE_DIR}/../../reference/drivers.gpu.i915.igt-gpu-tools/build/benchmarks/"
cd ${IGT_DIR}
./gem_blt &
WORKLOAD_PID=$!
kill -STOP ${WORKLOAD_PID}
cd ${BASE_DIR}

# Start funcgraph
# sudo funcgraph -p ${WORKLOAD_PID} i915_gem_pwrite_ioctl &> ${BASE_DIR}/funcgraph_pwrite.txt &
# FUNCGRAPH_PWRITE_PID="$!"
# sudo funcgraph -p ${WORKLOAD_PID} i915_gem_mmap_ioctl &> ${BASE_DIR}/funcgraph_mmap.txt &
# FUNCGRAPH_MMAP_PID="$!"
# sudo funcgraph -p ${WORKLOAD_PID} i915_gem_mmap_offset_ioctl &> ${BASE_DIR}/funcgraph_mmap_offset.txt &
# FUNCGRAPH_MMAP_OFFSET_PID="$!"
sudo funcgraph -p ${WORKLOAD_PID} i915_gem_create_ioctl &> ${BASE_DIR}/funcgraph_gem_create.txt &
FUNCGRAPH_MMAP_OFFSET_PID="$!"

echo "I just started funcgraph, and the workload is paused."
sleep 3

# Wait for the workload to finish
kill -CONT ${WORKLOAD_PID}
wait ${WORKLOAD_PID}

# Kill and wait for funcgraph to finish
# kill -TERM ${FUNCGRAPH_PWRITE_PID}
# kill -TERM ${FUNCGRAPH_MMAP_PID}
kill -TERM ${FUNCGRAPH_MMAP_OFFSET_PID}
# wait ${FUNCGRAPH_PWRITE_PID}
# wait ${FUNCGRAPH_MMAP_PID}
wait ${FUNCGRAPH_MMAP_OFFSET_PID}
