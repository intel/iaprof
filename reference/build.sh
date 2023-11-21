#!/bin/bash
BASEDIR=$(cd "${BASH_SOURCE[0]%/*}" && pwd)

# WARNING: This script is not intended to just be run.
# Before you run it, please do the following:
#   1. Ensure you've cloned this repository recursively.
#   2. Install dependencies. On Ubuntu, that's:
#      sudo apt-get install libncurses-dev gawk flex bison \
#        openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev \
#        libiberty-dev autoconf llvm pahole dwarves
#   3. Configure the kernel in `drivers.gpu.i915.drm-intel`.
# After you run it, install the .deb files.

# Build the kernel
cd ${BASEDIR}/drivers.gpu.i915.drm-intel
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
make olddefconfig
git apply ${BASEDIR}/pahole_fix.diff
make -j $(getconf _NPROCESSORS_ONLN) bindeb-pkg LOCALVERSION=-internal &> ${BASEDIR}/kernel_build_log.txt

# Patch and install the firmware
cd ${BASEDIR}/linux-firmware
git am ${BASEDIR}/drivers.gpu.i915.internal-linux-firmware/0001-firmware*.patch
sudo cp ${BASEDIR}/linux-firmware/i915/*.bin /lib/firmware/i915/
