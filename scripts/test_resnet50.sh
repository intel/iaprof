#!/bin/bash

sudo ./run.sh &
PROFILER_PID=$!

sleep 5

# Workload
cd /home/macslayer/workloads/resnet50
./run.sh \
  &> workload1.txt &
WORKLOAD_PID1=$!
wait ${WORKLOAD_PID1}

sudo kill -INT $PROFILER_PID
wait $PROFILER_PID
