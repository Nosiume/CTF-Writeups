#!/bin/bash
python server.py &
sleep 3
cd bot && node bot.js

