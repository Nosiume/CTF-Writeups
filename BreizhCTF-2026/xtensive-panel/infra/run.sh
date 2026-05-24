#!/bin/bash
set -euo pipefail

APP_DIR=/home/ctf/app
QEMU_SHARE_DIR="$APP_DIR/qemu/share/qemu"

# eFuse needs a writable backing file, but we keep the base image immutable.
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cp "$APP_DIR/qemu_efuse.bin" "$TMPDIR/efuse.bin"
chmod u+w "$TMPDIR/efuse.bin"

"$APP_DIR/qemu-system-xtensa" \
    -L "$QEMU_SHARE_DIR" \
    -M esp32 \
    -m 4M \
    -drive "file=$APP_DIR/qemu_flash.bin,if=mtd,format=raw" \
    -drive "file=$TMPDIR/efuse.bin,if=none,format=raw,id=efuse" \
    -global driver=nvram.esp32.efuse,property=drive,value=efuse \
    -global driver=timer.esp32.timg,property=wdt_disable,value=true \
    -nic user,model=open_eth \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot
