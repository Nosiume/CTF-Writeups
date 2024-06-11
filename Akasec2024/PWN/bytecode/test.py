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
    PRT 0x48656c6c6f2c20776f726c6420210as
    """)
    r.sendlineafter(b'>> ', bytecode)

    r.interactive()


if __name__ == "__main__":
    main()
