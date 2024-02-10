#!/bin/bash

ulimit -c unlimited
ulimit -l unlimited
./bin/pvc_profile -d \
  1> profile.txt \
  2> profile_err.txt
