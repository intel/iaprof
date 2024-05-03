#!/bin/bash

ulimit -c unlimited
ulimit -l unlimited
./iaprof -d \
  1> profile.txt \
  2> profile_err.txt
