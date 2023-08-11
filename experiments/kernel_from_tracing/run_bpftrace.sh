#!/bin/bash

sudo bpftrace -v -I /usr/include/libdrm get_kernels.bt &>bpftrace.txt &
BPFTRACE_PID="$!"

sleep 2

./bude

kill -TERM ${BPFTRACE_PID}
wait ${BPFTRACE_PID}
