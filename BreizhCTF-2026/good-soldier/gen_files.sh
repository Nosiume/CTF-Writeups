#!/bin/bash

cp ./infra/ld-linux-x86-64.so.2 ./files
cp ./infra/libc.so.6 ./files
cp ./infra/good_soldier ./files
cp -r ./infra/res ./files
echo -ne 'BZHCTF{FAKE_FLAG}' > ./files/flag.txt

(
    cd files
    zip -r "dist.zip" ld-linux-x86-64.so.2 flag.txt libc.so.6 good_soldier res
)

rm ./files/ld-linux-x86-64.so.2
rm ./files/libc.so.6
rm ./files/good_soldier 
rm ./files/flag.txt
rm -rf ./files/res

echo "[+] Generated files/dist.zip for players"

