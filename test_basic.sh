#!/bin/bash
# Run this as root

BENCHDNN_ARGS="--engine=gpu --mode=P --mode-modifier=PM --max-ms-per-prb=100 --matmul 20000x10000:10000x40000"

ulimit -c unlimited
ulimit -l unlimited
./bin/pvc_profile -d \
  1> profile.txt \
  2> profile_err.txt \
  &
PROFILER_PID=$!

sleep 5

# Workload
cd /home/macslayer/workloads/oneDNN/build/tests/benchdnn
./benchdnn ${BENCHDNN_ARGS} \
  &> workload1.txt &
WORKLOAD_PID1=$!
wait ${WORKLOAD_PID1}

kill -INT $PROFILER_PID
wait $PROFILER_PID
