#!/bin/bash

IGA="/usr/local/bin/iga64"

mkdir -p disasm
for file in /tmp/kernel_*; do
  $IGA -d -p=12p72 $file &> disasm/$(basename $file)
  RETVAL="$?"
  echo "$file: $RETVAL"
done
