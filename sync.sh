#!/bin/bash

# scp -r -J guest@146.152.226.40 -oProxyCommand="ssh -L 10022:192.168.21.2:22" * devcloud@192.168.21.2:projects/i915_profiling/.
rsync -Pazv -e 'ssh -J guest@146.152.226.40 -L 10022:192.168.21.2:22' * devcloud@192.168.21.2:projects/i915_profiling/
