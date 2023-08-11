#!/bin/bash

./bude &
WORKLOAD_PID="$!"

sudo cat /proc/${WORKLOAD_PID}/maps
wait ${WORKLOAD_PID}
