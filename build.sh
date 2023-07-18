#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

LIBDRM_HEADERS=${LIBDRM:-/usr/include/libdrm}
CC=${CC:-gcc}

gcc -I${LIBDRM_HEADERS} -ldrm ${BASE_DIR}/test.c
