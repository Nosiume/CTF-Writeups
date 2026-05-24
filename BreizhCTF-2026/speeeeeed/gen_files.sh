#!/bin/bash

# build binary
(
    cd src
    rm -rf build 
    mkdir build
    cd build
    cmake ..
    make -j$(nproc)
    cp speeeeeed ../../infra/
)

cp -r ./src/src files
cp ./infra/docker-compose.yml files
cp ./infra/Dockerfile files
cp ./infra/run.sh files
cp ./infra/speeeeeed files
cp ./infra/index.html files
cp ./infra/flag.c files
echo -ne 'BZHCTF{FAKE_FLAG}' > files/flag.txt

(
    cd files
    zip -r "dist.zip" src docker-compose.yml Dockerfile run.sh speeeeeed flag.c flag.txt index.html
)

rm -rf files/src
rm files/docker-compose.yml
rm files/Dockerfile
rm files/run.sh
rm files/speeeeeed
rm files/index.html
rm files/flag.c
rm files/flag.txt

echo "[+] Generated files/dist.zip for players"

