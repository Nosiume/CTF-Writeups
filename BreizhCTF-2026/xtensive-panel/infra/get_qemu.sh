#!/bin/bash
set -euo pipefail

build_dir="${1:-${BUILD_DIR:-$(pwd)/qemu}}"
qemu_tag="${QEMU_TAG:-esp-develop-9.2.2-20250817}"
qemu_url="https://github.com/espressif/qemu/archive/refs/tags/${qemu_tag}.tar.gz"

temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

mkdir -p "$build_dir"
cd "$temp"

wget -O qemu.tar.gz "$qemu_url"
tar xf qemu.tar.gz

src_dir="$(find "$temp" -mindepth 1 -maxdepth 1 -type d -name 'qemu*' | head -n 1)"
cd "$src_dir"

./configure --prefix="$build_dir" \
    --target-list=xtensa-softmmu \
    --enable-gcrypt \
    --enable-slirp \
    --enable-debug \
    --disable-sdl \
    --disable-strip --disable-user \
    --disable-capstone --disable-vnc \
    --disable-gtk

ninja -C build -j "$(nproc)"
make install
