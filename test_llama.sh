#!/bin/bash
# Run this as root

ulimit -c unlimited
ulimit -l unlimited
./bin/pvc_profile -d -v \
  1> profile.txt \
  2> profile_err.txt \
  &
PROFILER_PID=$!

sleep 5

# Workload
source /opt/intel/oneapi/setvars.sh
cd /home/macslayer/workloads/llama/llama.cpp
GGML_SYCL_DEVICE=0 ./build/bin/main \
  -m models/llama-2-7b.Q2_K.gguf \
  -p "Building a website can be done in 10 simple steps:" \
  -n 64 -e -ngl 10 \
  &> workload1.txt &
WORKLOAD_PID1=$!
wait ${WORKLOAD_PID1}

kill -INT $PROFILER_PID
wait $PROFILER_PID
