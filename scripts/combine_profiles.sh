#!/bin/bash
#
# refactor GPU profile to be TARGET_GPU_SAMPLES of the CPU profile

GPU_SAMPLES=$(awk '{ sum+=$2; } END { print(sum); }' profile.txt)
CPU_SAMPLES=$(awk '{ sum+=$2; } END { print(sum); }' out.folded)

(( TARGET_GPU_SAMPLES = CPU_SAMPLES * 10 ))
(( GPU_REFACTOR = TARGET_GPU_SAMPLES / GPU_SAMPLES ))

awk -v refactor=$GPU_REFACTOR '{ printf "%s %d\n", $1, $2 * refactor }' profile.txt
cat out.folded
