#!/bin/bash

SYCL_DUMP_IMAGES="1" ./nsg.exe
mv sycl_spir64.spv nsg.spv
SYCL_DUMP_IMAGES="1" ./nsg_g.exe
mv sycl_spir64.spv nsg_g.spv

SYCL_DUMP_IMAGES="1" ./sg.exe
if [ -f sycl_spir64_1.spv ]; then
  rm sycl_spir64.spv
  mv sycl_spir64_1.spv sg.spv
else
  mv sycl_spir64.spv sg.spv
fi
SYCL_DUMP_IMAGES="1" ./sg_g.exe
if [ -f sycl_spir64_1.spv ]; then
  rm sycl_spir64.spv
  mv sycl_spir64_1.spv sg_g.spv
else
  mv sycl_spir64.spv sg_g.spv
fi

~/src/SPIRV-Tools/build/tools/spirv-dis nsg.spv > nsg.txt
~/src/SPIRV-Tools/build/tools/spirv-dis nsg_g.spv > nsg_g.txt
~/src/SPIRV-Tools/build/tools/spirv-dis sg.spv > sg.txt
~/src/SPIRV-Tools/build/tools/spirv-dis sg_g.spv > sg_g.txt
