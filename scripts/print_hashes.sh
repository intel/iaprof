#!/bin/bash

dumps_dir="/tmp"
zebins_dir="${HOME}/.cache/neo_compiler_cache"

rm dumps.txt
for dump in `ls ${dumps_dir}/iaprof*`; do
  sha=$(sha512sum -b $dump | awk '{print $1}')
  echo "$sha" >> dumps.txt
done
sort -o dumps.txt dumps.txt

rm zebins.txt
for file in `ls ${zebins_dir}/*.cl_cache`; do
  header=$(objdump -h $file | grep .spv)
  size=$(echo $header | awk '{print $3}')
  start=$(echo $header | awk '{print $6}')
  dd if=$file of="${file}.spv" bs=1 count=$((0x${size})) skip=$((0x${start})) &> /dev/null
  sha=$(sha512sum -b ${file}.sec | awk '{print $1}')
  echo "$sha" >> zebins.txt
done
sort -o zebins.txt zebins.txt
