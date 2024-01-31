#!/bin/bash
# Run this as root

ulimit -c unlimited
ulimit -l unlimited
./bin/pvc_profile -v -d &> profile.txt &
PID=$!

sleep 5

# Workload
cd /home/macslayer/workloads/matrix_multiply
./run.sh &> workload.txt

kill -INT $PID
wait $PID
