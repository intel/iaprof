#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ${BASE_DIR}/dummy_workload/bude &
# WORKLOAD_PID="$!"

IGT_DIR="${BASE_DIR}/../../reference/drivers.gpu.i915.igt-gpu-tools/build/benchmarks/"
cd ${IGT_DIR}
./gem_blt &
WORKLOAD_PID=$!
cd ${BASE_DIR}

sleep 1
START=$(grep "anon_shmem:GPU KERNEL" /proc/${WORKLOAD_PID}/maps | awk '{printf $1}' | awk 'BEGIN{FS="-"}{printf $1}')
END=$(grep "anon_shmem:GPU KERNEL" /proc/${WORKLOAD_PID}/maps | awk '{printf $1}' | awk 'BEGIN{FS="-"}{printf $2}')

echo "START: ${START}"
echo "END: ${END}"
sudo xxd -s 0x${START} -l $(( 0x${END} - 0x${START} )) /proc/${WORKLOAD_PID}/mem &> xxd.txt

wait ${WORKLOAD_PID}
