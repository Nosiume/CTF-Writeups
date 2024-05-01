## Challenge Name: CyberCalc
Category: PPC 
Points: ~980
Solves: ~9

Challenge Description: 
(insert some russian text i don't remember lmao)

### Observations

This challenge is your typical programming question type of challenge.
We have to connect to a remote and answer a bunch of mathematical questions.

For this one specifically we don't have the source code but we can guess what
happens on this remote very easily.

It asks us for input of the type 

```
a ∈ ℕ, b ∈ ℕ, c ∈ ℕ

And an operator such that ∈ {+, -, /, *, %}

E = a! (+,/,-,*,%) b! (...) c!
```

Notice that all the given numbers are always passed inside of the factorial function.
Now this isn't too hard to compute fast for a computer and we have 1000 questions
like this to solve. The problem is this challenge takes pretty strict input
on int calculation and a single floating point error can be the end...

Since this challenge was one I attempted at the end of the event I had to rush
my script and upon running into the floating point problems. I decided to take the...
lazy approach ????

Let's just say instead of fixing the one edge case I had, I decided to just run it a bunch
of times until one of the executions ended up reaching the last case :')

### Solve

Ahhh the magic of multi threading, saves us from actually thinking :D

```py
#!/usr/bin/env python3

from pwn import *
from math import factorial
from tqdm import trange
import re
import threading

context.log_level = 'error'

left = 100
success_io = None
def attempt(i):
    io = remote("84.201.137.163", 10137)
    
    try:
        for _ in range(999):
            io.recvuntil(b'Solve: ')
            equation = io.recvuntil(b' [')[:-2].decode()
            io.recvline()

            numbers = re.findall(r"\d+!", equation)
            for n in numbers:
                equation = equation.replace(n, str(factorial(int(n[:-1]))), 1)

            res = eval(equation)
            if isinstance(res, float):
                if res.is_integer() and "e" not in str(res):
                    res = int(res)
            io.sendline(str(res).encode()) 
        global success_io
        success_io = io
    except:
        global left
        left -= 1
        print(f"{left} threads left !")

for i in range(100):
    print(f"booting thread {i}")
    thread = threading.Thread(target=attempt, args=(i, ))
    thread.start()

while success_io == None:
    sleep(0.1)
success_io.interactive()

```

Now the challenge authors added a little check question with the last question
asking us to type the name of the challenge.

After this it just prints out the flag for us :D

---
[Back to home](../../README.md)
