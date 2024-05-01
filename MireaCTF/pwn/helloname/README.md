# helloname 

Category: PWN
Points: 100
Solves: 76

Challenge Description:
another russian test i couldn't understand

Artifact Files:
[chall](./chall)

## Quick overview

This is just a basic program that seems to take our input and terminate ! Let's see 
how it works under the hood and if we have potential vulnerabilities

## Running the binary

This binary just asks for our name aaaand closes. Alright not much of a target here
let's look at what may be hidden in our code.

```asm
            0x004006ab      e850feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x004006b0      488d45e0       lea rax, [s]
│           0x004006b4      4889c7         mov rdi, rax                ; char *s
│           0x004006b7      e874feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x004006bc      837dfc00       cmp dword [var_4h], 0
│       ┌─< 0x004006c0      741c           je 0x4006de
│       │   0x004006c2      bf96074000     mov edi, str.FLAG           ; 0x400796 ; "FLAG" ; const char *name
│       │   0x004006c7      e824feffff     call sym.imp.getenv         ; char *getenv(const char *name)
│       │   0x004006cc      4889c6         mov rsi, rax
│       │   0x004006cf      bf9b074000     mov edi, str.Debug_flag:__s_n ; 0x40079b ; "Debug flag: %s\n" ; const char *format
│       │   0x004006d4      b800000000     mov eax, 0
│       │   0x004006d9      e822feffff     call sym.imp.printf         ; int printf(const char *format)
```

Interesting... We seem to have a call to the **gets** function (mmm free hacker candy)
and a little variable on the stack storing an int and containing 0.

If this variable stays 0 it jumps to the "Hello, <name>" print and otherwise it'll straight up
print the flag !

So this is pretty easy... Just send a bunch of As (more than 24 specifically) and you've got
your flag :D

[Back to home](../../README.md)
