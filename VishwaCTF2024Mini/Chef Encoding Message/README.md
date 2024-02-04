## Challenge Name: Chef's Encoding Message
Category: Cryptography
Points: 100
Solves: 19
Author: Ankush Kaudi (@itsbunny07)

Challenge Description: 
My CHEF friend who loves to CODE, once tried to explore cryptography.
After exploring he developed his own encoding and was happy to try something new.
He wants you to find out what he has encoded to test the algorithm. Help him with it....

Encoded text : sxu3o_e05v3_xmbigk01_m4ztoi0g1ns!5

Artifact Files:
None

### Observations

The main interest of this challenge when we start is obviously the description. All we have is 
the encoded flag with some "lore" of the challenge. Let's look at the description first.

Some words are written in UPPER case trying to make us notice them out of the rest:
- CHEF
- CODE

The description then talks about a chef who wanted to learn crypto and developped his own algorithm.
Since at first I couldn't think of any "Chef's encoding" out of memory I simply googled the name of the challenge and 
CHEF and CODE as keywords.

This brought me to an interesting page : https://www.codechef.com/practice/course/1-star-difficulty-problems/DIFF1200/problems/ENCMSG

Now it all makes a whole lot of sense, the words **code** and **chef** were pointing us to the website codechef
commonly used to learn about various programming concepts through given exercises. This exercise here seems like an intro to
basic crypto concepts and thus prompts the user to make a basic encoding algorithm with the following logic : 

Chef has a message, which is a string *S* with length *N* containing only lowercase English letters. 
It should be encoded in two steps as follows:
- Swap the first and second character of the string *S*, then swap the 3rd and 4th character, then the 5th and 6th character and so on. If the length of *S* is odd, the last character should not be swapped with any other.
- Replace each occurrence of the letter 'a' in the message obtained after the first step by the letter 'z', each occurrence of 'b' by 'y', each occurrence of 'c' by 'x', etc, and each occurrence of 'z' in the message obtained after the first step by 'a'.

### Let's solve it !
Now all we have to do is build an algorithm that does the same steps but backwards in order to reverse the encoding
Here is my script in python:

```py
#!/usr/bin/env python3

enc = "sxu3o_e05v3_xmbigk01_m4ztoi0g1ns!5"
alphabet = [chr(ord('a') + x) for x in range(26)]
transposition = dict(zip(alphabet, alphabet[::-1]))

def decode(data):
    data = list(map(lambda x: transposition[x] if x in alphabet else x, data))
    for i in range(len(data) // 2):
        data[i*2], data[i*2+1] = data[i*2+1], data[i*2]
    return ''.join(data)

print("VishwaCTF{%s}" % decode(enc))
```

As you can see in the decode function, I first applied the transposition from a -> z, b -> y, etc...
And then flipped every letter pair. Thus forming the original string from the encoded version.

Running the program we get : 
`VishwaCTF{ch3f_l0ve5_3ncrypt10n_a4lg0r1thm5!}`

And that is the solution of this first Crypto Challenge and a first blood in the CTF :D

---
[Back to home](../../README.md)
