#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd ${DIR}

if ! [ -f blazesym/target/debug/libblazesym_c.a ]; then
    git clone https://github.com/libbpf/blazesym || exit $?
    cd blazesym
    git checkout v0.2.3 || exit $?
    cargo build -p blazesym-c || exit $?
fi
cd ${DIR}

rm -rf build
mkdir -p build/obj
mkdir -p build/bpf_obj
mkdir -p build/generated_headers


# DEBUG="yes"
CC=clang
CXX=clang++
BPFTOOL="deps/install/bpftool/bin/bpftool"


${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > build/generated_headers/vmlinux.h || exit $?
${BPFTOOL} btf dump file /sys/kernel/btf/xe      format c > build/generated_headers/xe.h      || exit $?

BPF_CFLAGS="-Wall -Werror -g -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -target bpf -D__TARGET_ARCH_x86 -Wno-pass-failed"
BPF_INC="-Ibuild/generated_headers -Ideps/install/libbpf/include"
BPF_OPT="-O2"

if [[ "${DEBUG}" == "yes" ]]; then
    BPF_CFLAGS+=" -DDEBUG"
fi

for f in src/bpf/*.bpf.c; do
    ${CC} -o build/bpf_obj/$(basename ${f} ".c").o -c ${f} ${BPF_CFLAGS} ${BPF_INC} ${BPF_OPT} || exit $?
    ${BPFTOOL} gen skeleton build/bpf_obj/$(basename ${f} ".c").o > build/generated_headers/$(basename ${f} ".bpf.c").skel.h || exit $?
done


CFLAGS="-std=c++23 -Wall -Werror -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer"
INC="-Isrc/bpf -Ibuild/generated_headers -Ideps/kernel_headers -Ideps/install/libbpf/include -Ideps/install/libelf/include -Iblazesym/capi/include -I$(llvm-config --includedir) -Ideps/install/igc/include"
OPT=""
LDFLAGS="deps/install/bpftool/lib/libbpf.a deps/install/libelf/lib/libdw.a deps/install/libelf/lib/libelf.a blazesym/target/debug/libblazesym_c.a deps/install/igc/lib/libiga64.a -ldl -lrt -lpthread -lm -lz -lzstd $(llvm-config --libs demangle)"

if [[ "${DEBUG}" == "yes" ]]; then
    OPT+="-g -O0"
    CFLAGS+=" -DDEBUG"
else
    OPT+="-O3 -march=native -mtune=native"
fi

pids=()
for f in src/*.cpp; do
    ${CXX} -c -o build/obj/$(basename ${f}).o ${f} ${CFLAGS} ${INC} ${OPT} &
    pids+=($!)
done

for pid in "${pids[@]}"; do
    wait ${pid} || exit $?
done

${CXX} -o build/iaprof build/obj/* ${LDFLAGS} || exit $?
