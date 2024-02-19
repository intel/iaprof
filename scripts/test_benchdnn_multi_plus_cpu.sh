#!/bin/bash
# Run this as root

BENCHDNN_ARGS="--engine=gpu --mode=P --mode-modifier=M  --matmul --dt=bf16 20000x10000:10000x40000"
BENCHDNN2_ARGS="--engine=gpu --mode=P --mode-modifier=M  --matmul --dt=bf16 40000x10000:10000x40000"
BENCHDNN3_ARGS="--engine=gpu --mode=P --mode-modifier=M  --matmul --dt=bf16 80000x10000:10000x40000"

ulimit -c unlimited
ulimit -l unlimited
./bin/pvc_profile -d -v \
  1> profile.txt \
  2> profile_err.txt \
  &
PROFILER_PID=$!

perf record -F 99 -a -g &
PERF_PID=$!

sleep 5

# Workload
cd /home/macslayer/workloads/oneDNN/build/tests/benchdnn
cp benchdnn benchdnn2
cp benchdnn benchdnn3
./benchdnn ${BENCHDNN_ARGS} \
  &> workload1.txt
./benchdnn2 ${BENCHDNN2_ARGS} \
  &> workload2.txt
./benchdnn3 ${BENCHDNN3_ARGS} \
  &> workload3.txt
  
kill -INT $PROFILER_PID
kill -INT $PERF_PID
wait $PROFILER_PID
wait $PERF_PID
