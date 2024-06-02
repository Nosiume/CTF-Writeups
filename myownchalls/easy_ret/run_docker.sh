#!/bin/bash

sudo docker build -t easy_ret .
sudo docker run -d -p 9000:9000 --rm -it easy_ret
