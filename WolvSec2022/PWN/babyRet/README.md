## Challenge Name: babyRet
Category: PWN
Points: 244
Solves: 107

Challenge Description: 
As promised a pwn challenge...

Artifact Files:
* [ret0](ret0)
* [ret0.c](ret0.c)

### Approach

**1. Observations**

The challenge gives us direct access to the source code of the program, so let's take a look at it !

![img](images/source.png)

We see that a **print_flag()** function is defined in the program but never used which is pretty peculliar let's say...

Looking at **main()** we can see that a **char[16]** buffer is created on the stack before the program prints *What is your favorite food?* to the user. It then takes input using **scanf("%s", buffer);** to load user input into our buffer.

The important thing to notice here is that there is absolutely no size check for the user input, while our buffer is limited to **16** chars of length. 

This program is an ELF x64 bits and does not seem to have a lot of securities activated as shown here:

![img](images/checksec.png)

So our hypothesis is that any input longer than **16** of length might cause a Stack Buffer Overflow and lead to potential manipulation of **RIP** (instruction pointer).

We can test that out by inputing a bunch of As into our program and see if we get a **SEGFAULT**

![img](images/test_bof.png)

And we do ! Let's check in gdb if we can overwrite **RIP** and control the program's execution flow.

![img](images/overflow_rip.png)

Perfect ! Now we just have to manipulate rip to return to that **print_flag()** function which should print us the flag when executed on the remote.

### Reflections
<reflections ...>
  

---
[Back to home](<link>)