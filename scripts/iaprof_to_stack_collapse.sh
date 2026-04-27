#!/usr/bin/env bash

awk -F'\t' '
    BEGIN{
        stall_reasons[0] = "active";
        stall_reasons[1] = "control";
        stall_reasons[2] = "pipestall";
        stall_reasons[3] = "send";
        stall_reasons[4] = "dist_acc";
        stall_reasons[5] = "sbid";
        stall_reasons[6] = "sync";
        stall_reasons[7] = "inst_fetch";
        stall_reasons[8] = "other";
        stall_reasons[9] = "tdr";
    }
    /^string/ { strings[$2] = $3; }
    /^kernel/ {
        current_kernel_stack = sprintf("%s;%d;%s;-;%s_[G];%s_[G]", strings[$3], $4, strings[$5], strings[$6], strings[$7]);
    }
    /^eustall/ {
        idx = 4;
        for (reason in stall_reasons) {
            if ($idx <= 0) { continue; }
            stack = sprintf("%s;%s_[g];%s_[g];%s_[g]", current_kernel_stack, strings[$3], reason, $2);
            stacks[stack] += $idx;
            idx++;
        }
    }
    END {
        for (stack in stacks) {
            printf("%s %d\n", stack, stacks[stack]);
        }
    }
'
