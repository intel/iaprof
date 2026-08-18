#!/usr/bin/env bash

SEDSTR='s/_Py[^;]*;//g'
SEDSTR+=';s/Py(Object|Eval|Number)_[^;]*;//g'
SEDSTR+=';s/run_mod;//g'
SEDSTR+=';s/run_eval_code_obj;//g'
SEDSTR+=';s/cfunction_call;//g'
SEDSTR+=';s/slot_nb_multiply;//g'
SEDSTR+=';s/slot_tp_call;//g'
SEDSTR+=';s/(method_)?vectorcall[^;]*;//g'

sed -E "${SEDSTR}"
