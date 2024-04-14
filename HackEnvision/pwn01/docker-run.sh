#!/bin/bash

/usr/bin/docker rmi --force pwn01:latest

/usr/bin/docker build -t  pwn01:latest .

/usr/bin/docker run -p 0.0.0.0:1337:1337  pwn01:latest
