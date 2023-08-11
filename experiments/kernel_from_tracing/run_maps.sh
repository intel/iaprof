#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

${BASE_DIR}/dummy_workload/bude &
WORKLOAD_PID="$!"

sudo cat /proc/${WORKLOAD_PID}/maps
wait ${WORKLOAD_PID}
