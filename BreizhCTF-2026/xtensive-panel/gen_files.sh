#!/bin/bash

TMPDIR=$(mktemp -d)
PROJECT=${SRCS:-$(pwd)/src}
cp -r $PROJECT/* $TMPDIR

OUT=${OUTPUT:-$(pwd)/files}

echo 'BZHCTF{FAKE_FLAG}' > $TMPDIR/spiffs/flag.txt

# Build firmware & qemu_flash.bin for remote emulator
docker run --rm -v $TMPDIR:/project -w /project --user "$(id -u):$(id -g)" espressif/idf:v5.5.3 idf.py clean fullclean
docker run --rm -v $TMPDIR:/project -w /project --user "$(id -u):$(id -g)" espressif/idf:v5.5.3 idf.py build
docker run --rm -v $TMPDIR:/project -w /project/build --user "$(id -u):$(id -g)" espressif/idf:v5.5.3 python3 -m esptool --chip=esp32 merge_bin --output=/project/build/qemu_flash.bin --fill-flash-size=2MB --flash_mode dio --flash_freq 40m --flash_size 2MB 0x1000 bootloader/bootloader.bin 0x10000 main.bin 0x8000 partition_table/partition-table.bin 0x110000 storage.bin 

# Generate EFUSE
echo -ne 'AAAAAAAAAAAAAAAAAIAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==' \
    | base64 -d > $OUT/qemu_efuse.bin

# Copy files from docker build
cp $TMPDIR/build/qemu_flash.bin $OUT
cp $TMPDIR/build/main.elf $OUT/firmware.elf

(
    cd "$OUT"
    zip -r dist.zip run.sh get_qemu.sh Dockerfile docker-compose.yml qemu_efuse.bin qemu_flash.bin firmware.elf
    echo "[+] Generated zip for players at $OUT/dist.zip"
)

rm -rf $TMPDIR
