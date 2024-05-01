# biglo1337 

Category: PWN
Points: 880
Solves: 17

Challenge Description:
another russian test i couldn't understand

Artifact Files:
[chall](./chall)

## Quick overview

This challenge asks for a bunch of numbers to read and once that is done
... prints "not lucky..."

Let's see what lies under the hood

## The code

This code just generates a bunch of random numbers after setting the random seed
to time(NULL). This numbers are compared with the ones you put in and ONLY if they
all match it'll print the flag.

We can understand this with the following assembly code from the binary :

```asm
           0x00400816      bf00000000     mov edi, 0                  ; time_t *timer
│           0x0040081b      e860feffff     call sym.imp.time           ; time_t time(time_t *timer)
│           0x00400820      89c7           mov edi, eax                ; int seed
│           0x00400822      e839feffff     call sym.imp.srand          ; void srand(int seed)
│           0x00400827      bfc0126000     mov edi, obj.banner         ; 0x6012c0 ; "\n ... 
│           0x0040082c      e8fffdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400831      be10000000     mov esi, 0x10               ; 16
│           0x00400836      bf88094000     mov edi, str.Its_time_to_check_your_luck__nEnter__d_numbers: ; 0x400988 ; "It's time to check your luck!\nEnter %d numbers: " ; const char *format
│           0x0040083b      b800000000     mov eax, 0
│           0x00400840      e8fbfdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00400845      c745ec0000..   mov dword [var_14h], 0
│       ┌─< 0x0040084c      eb22           jmp 0x400870
│       │   ; CODE XREF from main @ 0x400874(x)
│      ┌──> 0x0040084e      488d55d0       lea rdx, [var_30h]
│      ╎│   0x00400852      8b45ec         mov eax, dword [var_14h]
│      ╎│   0x00400855      4898           cdqe
│      ╎│   0x00400857      4801d0         add rax, rdx
│      ╎│   0x0040085a      4889c6         mov rsi, rax
│      ╎│   0x0040085d      bfb9094000     mov edi, str._hhu           ; 0x4009b9 ; "%hhu" ; const char *format
│      ╎│   0x00400862      b800000000     mov eax, 0
│      ╎│   0x00400867      e834feffff     call sym.imp.scanf          ; int scanf(const char *format)
│      ╎│   0x0040086c      8345ec01       add dword [var_14h], 1
│      ╎│   ; CODE XREF from main @ 0x40084c(x)
│      ╎└─> 0x00400870      837dec0f       cmp dword [var_14h], 0xf
│      └──< 0x00400874      7ed8           jle 0x40084e
│           0x00400876      c745e80000..   mov dword [var_18h], 0
│       ┌─< 0x0040087d      eb46           jmp 0x4008c5
│       │   ; CODE XREF from main @ 0x4008c9(x)
│      ┌──> 0x0040087f      8b45e8         mov eax, dword [var_18h]
│      ╎│   0x00400882      4898           cdqe
│      ╎│   0x00400884      0fb64405d0     movzx eax, byte [rbp + rax - 0x30]
│      ╎│   0x00400889      0fb6d8         movzx ebx, al
│      ╎│   0x0040088c      e82ffeffff     call sym.imp.rand           ; int rand(void)
│      ╎│   0x00400891      89c2           mov edx, eax
│      ╎│   0x00400893      89d0           mov eax, edx
│      ╎│   0x00400895      c1f81f         sar eax, 0x1f
│      ╎│   0x00400898      c1e818         shr eax, 0x18
│      ╎│   0x0040089b      01c2           add edx, eax
│      ╎│   0x0040089d      0fb6d2         movzx edx, dl
│      ╎│   0x004008a0      29c2           sub edx, eax
│      ╎│   0x004008a2      89d0           mov eax, edx
│      ╎│   0x004008a4      39c3           cmp ebx, eax
│      ╎│   0x004008a6      0f95c0         setne al
│      ╎│   0x004008a9      84c0           test al, al
│     ┌───< 0x004008ab      7414           je 0x4008c1
│     │╎│   0x004008ad      bfbe094000     mov edi, str.not_lucky...   ; 0x4009be ; "not lucky..." ; const char *s
│     │╎│   0x004008b2      e879fdffff     call sym.imp.puts           ; int puts(const char *s)
│     │╎│   0x004008b7      bf01000000     mov edi, 1                  ; int status
│     │╎│   0x004008bc      e8effdffff     call sym.imp.exit           ; void exit(int status)
│     │╎│   ; CODE XREF from main @ 0x4008ab(x)
│     └───> 0x004008c1      8345e801       add dword [var_18h], 1
│      ╎│   ; CODE XREF from main @ 0x40087d(x)
│      ╎└─> 0x004008c5      837de80f       cmp dword [var_18h], 0xf
│      └──< 0x004008c9      7eb4           jle 0x40087f
│           0x004008cb      bfcb094000     mov edi, str.FLAG           ; 0x4009cb ; "FLAG" ; const char *name
│           0x004008d0      e84bfdffff     call sym.imp.getenv         ; char *getenv(const char *name)
│           0x004008d5      4889c6         mov rsi, rax
│           0x004008d8      bfd0094000     mov edi, str.BINGOO____I_think_you_spent_all_of_your_luck..._s_n ; 0x4009d0 ; "BINGOO!!!..."
│           0x004008dd      b800000000     mov eax, 0
│           0x004008e2      e859fdffff     call sym.imp.printf         ; int printf(const char *format)
```

Now an idea that can be exploited here is that since the program takes the seed instantly after starting. We could 
start our exploit at the same time and obtain the same numbers from that seed.

### Exploitation

Now unluckily for us the python random number generator is implemented differently than C so I had to use 
a little trick to get C-style random number generation in python.

I used the **ctypes** module to import a C shared object containing the following functions
```c
#include <stdlib.h>

void setseed(int seed) {
    srand(seed);
}

int generate() {
    return rand() & 0xff;
}
```

Now in python we can use the following code to call the functions
```py
from ctypes import CDLL

lib = CDLL('./random_lib.so')
lib.setseed(seed)
number = lib.generate()
```

Note that sometimes we will have to add some offset to the seed since the program
can have delay at startup on the remote.

```py
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL
from time import time

context.log_level = 'info'
context.binary = elf = ELF('./chall')
context.terminal = ['alacritty', '-e']

lib = CDLL('./random_lib.so')
seed = int(time()) + 2
print("Seed : " + str(seed))
lib.setseed(int(time()) + 1)
data = [ lib.generate() for _ in range(16) ]

gs = """
b *main+132
continue
"""
if args.REMOTE:
    io = remote("84.201.137.163", 10160)
elif args.GDB:
    io = gdb.debug('./chall', gdbscript=gs)
else:
    io = process()

for n in data:
    io.sendline(str(n).encode())

io.interactive()
io.close()
```

Running this (not 100% success rate) gives us the flag after a couple tries.

[Back to home](../../README.md)
