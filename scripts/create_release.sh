#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd ${DIR}/..

RELEASE_NAME="iaprof-$(date +%F)"

rm -rf ${RELEASE_NAME}
mkdir -p ${RELEASE_NAME}

cp iaprof ${RELEASE_NAME}
cp scripts/release_aiflamegraph.sh ${RELEASE_NAME}/aiflamegraph.sh
cp scripts/release_flamegraph.pl ${RELEASE_NAME}/flamegraph.pl
cp scripts/license.txt ${RELEASE_NAME}/license.txt

cat > ${RELEASE_NAME}/README.md << 'EOF'
# Intel AI Flame Graph

## Instructions
- Run the provided script to begin profiling:
        ```sudo ./aiflamegraph.sh```
- Interrupt the script with `ctrl-C` to stop profiling.
- Open the generated flame graph SVG file in a browser or other image viewer.
EOF

tar czf ${RELEASE_NAME}.tar.gz ${RELEASE_NAME}
rm -rf ${RELEASE_NAME}
