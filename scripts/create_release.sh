#!/usr/bin/env bash

set -eux

readonly SCRIPT="${BASH_SOURCE[0]}"
readonly SCRIPT_PATH="${SCRIPT%/*}"

: "${RELEASE_NAME=iaprof-$(date +%F)}"
readonly rel_dir="build/${RELEASE_NAME}"

if [[ -d build ]]; then
  rm -rf build
fi
install -d "${rel_dir}"/{bin,share}
install -d "${rel_dir}"/share/doc/{flamegraph,iaprof}
install -m 0755 "${SCRIPT_PATH}"/../iaprof "${rel_dir}/bin/"
install -m 0755 "${SCRIPT_PATH}"/release_aiflamegraph.sh "${rel_dir}/bin/aiflamegraph.sh"
install -m 0644 "${SCRIPT_PATH}"/license.txt "${rel_dir}/share/doc/iaprof/license.txt"
install -m 0755 "${SCRIPT_PATH}"/../deps/flamegraph/flamegraph.pl \
  "${rel_dir}/bin/flamegraph.pl"
install -m 0644 "${SCRIPT_PATH}"/../deps/flamegraph/docs/cddl1.txt \
  "${rel_dir}/share/doc/flamegraph/cddl1.txt"

cat > "${rel_dir}/share/doc/iaprof/README.md" << 'EOF'
# Intel AI Flame Graph

## Instructions
- Run the provided script to begin profiling:
        ```sudo ./aiflamegraph.sh```
- Interrupt the script with `ctrl-C` to stop profiling.
- Open the generated flame graph SVG file in a browser or other image viewer.
EOF
