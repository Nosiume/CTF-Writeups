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
