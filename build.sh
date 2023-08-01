#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

KERN_HEADERS=${KERN_HEADERS:-/lib/modules/$(uname -r)/build/include/uapi}
LIBDRM_HEADERS=${LIBDRM:-/usr/include/libdrm}

CC=${CC:-gcc}
LDFLAGS=${LDFLAGS:-}

if [ -f /usr/lib/x86_64-linux-gnu/libdrm.so ]; then
  LDFLAGS="${LDFLAGS} -L/usr/lib/x86_64-linux-gnu"
fi

gcc -g -c -I${KERN_HEADERS} -I${LIBDRM_HEADERS} ${BASE_DIR}/drm_helper.c -o drm_helper.o
gcc -g -c -I${KERN_HEADERS} -I${LIBDRM_HEADERS} ${BASE_DIR}/pvc_profile.c -o pvc_profile.o
gcc -g -c -I${KERN_HEADERS} -I${LIBDRM_HEADERS} ${BASE_DIR}/gpgpu_fill.c -o gpgpu_fill.o
gcc ${LDFLAGS} ${BASE_DIR}/pvc_profile.o ${BASE_DIR}/drm_helper.o -ldrm -lpthread -o ${BASE_DIR}/pvc_profile
gcc ${LDFLAGS} ${BASE_DIR}/gpgpu_fill.o ${BASE_DIR}/drm_helper.o -ldrm -o ${BASE_DIR}/gpgpu_fill
