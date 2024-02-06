#!/bin/bash
# Run this as root

ulimit -c unlimited
ulimit -l unlimited
./bin/pvc_profile -v -d &> profile.txt &
PROFILER_PID=$!

sleep 5

# Workload
cd /home/macslayer/workloads/matrix_multiply
./run.sh &> workload1.txt &
WORKLOAD_PID1=$!
./run.sh &> workload2.txt &
WORKLOAD_PID2=$!
wait ${WORKLOAD_PID1} ${WORKLOAD_PID2}

kill -INT $PROFILER_PID
wait $PROFILER_PID
