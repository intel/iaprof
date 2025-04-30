# Battlemage

This is difficult to set up - you'll need to be quite familiar with your system
and have a fair bit of patience.

## Kernel

You'll need a very recent Linux kernel - at least 6.15 - to get the commit that
includes [EU stall sampling](https://patchwork.freedesktop.org/series/145443/).

## Userspace Software

All software in your graphics stack will need to be recompiled with frame pointers
in order for `iaprof` to collect CPU stacks. Accomplishing this will depend on your
distribution.

### Arch Linux
On one particular system that we've tested this on, we were able to achieve this
by adding the following lines to `/etc/makepkg.conf`:

```
DEBUG_CFLAGS="-g -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer"
DEBUG_CXXFLAGS="$DEBUG_CFLAGS"
```

Then ensuring that the `OPTIONS` array includes the `debug` option, e.g.:

```
OPTIONS=(!strip docs !libtool !staticlibs emptydirs zipman purge debug lto)
```

You can then clone the corresponding Arch package's repository and recompile
it, which should now include frame pointers:

```
git clone https://gitlab.archlinux.org/archlinux/packaging/packages/mesa.git
cd mesa
makepkg -s
sudo pacman -U *.tar.zst
```

### Ubuntu Linux

Ubuntu 24.04 should include frame pointers in many packages
[by default](https://ubuntu.com/blog/ubuntu-performance-engineering-with-frame-pointers-by-default).

## Building iaprof

In general, the commands to build `iaprof` are:

```
git clone --recursive https://github.com/intel/iaprof
cd iaprof && make deps && make
```

### Arch Linux

In order to compile `iaprof` on Arch, you'll likely need to install some
packages in order to build dependencies.

IGC requires access to the `clang-14` executable, so you'll need to install
the `clang14` and `llvm14` AUR packages and add it to your PATH:

```
export PATH="/usr/lib/llvm14/bin:$PATH"
```

You should now be able to follow the general instructions.
