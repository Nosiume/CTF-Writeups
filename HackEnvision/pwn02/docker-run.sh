#!/bin/bash

/usr/bin/docker rmi --force pwn02:latest

/usr/bin/docker build -t  pwn02:latest .

/usr/bin/docker run -p 0.0.0.0:1337:1337  pwn02:latest
