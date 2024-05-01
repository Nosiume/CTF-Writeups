#!/usr/bin/env python3

from pwn import *
from math import factorial
from tqdm import trange
import re
import threading

context.log_level = 'error'

left = 100
success_io = None
def attempt(i):
    io = remote("84.201.137.163", 10137)
    
    try:
        for _ in range(999):
            io.recvuntil(b'Solve: ')
            equation = io.recvuntil(b' [')[:-2].decode()
            io.recvline()

            numbers = re.findall(r"\d+!", equation)
            for n in numbers:
                equation = equation.replace(n, str(factorial(int(n[:-1]))), 1)

            res = eval(equation)
            if isinstance(res, float):
                if res.is_integer() and "e" not in str(res):
                    res = int(res)
            io.sendline(str(res).encode()) 
        global success_io
        success_io = io
    except:
        global left
        left -= 1
        print(f"{left} threads left !")

for i in range(100):
    print(f"booting thread {i}")
    thread = threading.Thread(target=attempt, args=(i, ))
    thread.start()

while success_io == None:
    sleep(0.1)
success_io.interactive()

