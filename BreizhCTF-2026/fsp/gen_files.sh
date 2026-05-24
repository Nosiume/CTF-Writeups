#!/bin/bash

# build module
(
    cd src/build
    rm -rf *
    cmake ..
    make -j$(nproc)
    cp ./cool_compress.so ../../infra/cool_compress.so
)

cp ./infra/Dockerfile ./files
cp ./infra/docker-compose.yml ./files
cp ./infra/flag.c ./files
cp ./infra/run.sh ./files
cp ./infra/chall.py ./files
cp ./infra/cool_compress.so ./files
echo -ne 'BZHCTF{fake_flag}' > ./files/flag.txt

(
    cd files
    zip -r "dist.zip" Dockerfile docker-compose.yml flag.c flag.txt run.sh chall.py cool_compress.so
)

rm ./files/Dockerfile
rm ./files/docker-compose.yml
rm ./files/flag.c
rm ./files/flag.txt
rm ./files/run.sh
rm ./files/chall.py
rm ./files/cool_compress.so

echo "[+] Generated files/dist.zip for players"

