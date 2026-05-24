#!/usr/bin/env python3

import cool_compress as cc
import socket
import signal
import os
import sys
from abc import ABC, abstractmethod
import subprocess
import base64
from pathlib import Path

PORT = 1337
ROOT_DIR = "/opt/fsp/"

class FSPCommand(ABC):
    def __init__(self, mnemonic: bytes, nargs: int):
        self.mnemonic = mnemonic
        self.nargs = nargs

    @abstractmethod
    def execute(self, client: socket.socket, args: list[bytes]):
        pass

class NOOPCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'NOOP', 0)

    def execute(self, client: socket.socket, args: list[bytes]):
        client.send(b'200 OK\n')

class QUITCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'QUIT', 0)

    def execute(self, client: socket.socket, args: list[bytes]):
        client.send(b'CLOSING\n')
        client.close()

class LSTCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'LST', 0)

    def execute(self, client:socket.socket, args: list[bytes]):
        process = subprocess.Popen(['ls', '-la', ROOT_DIR], stdout=subprocess.PIPE)
        out = process.stdout.read()
        client.send(out)

class RETRCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'RETR', 1)

    def execute(self, client:socket.socket, args: list[bytes]):
        try:
            path = Path(ROOT_DIR + args[0].decode("utf-8"))
        except UnicodeDecodeError:
            client.send(b'501 Internal Server Error\n')
            return

        real_path = str(path.resolve())
        if not os.path.exists(real_path):
            client.send(b'404 Not Found\n')
            return

        if not real_path.startswith(ROOT_DIR):
            client.send(b'404 Not Found\n')

        client.send(b'200 OK\n')
        with open(real_path, "rb") as f:
            client.send(base64.b64encode(f.read()) + b'\n')

class PUTCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'PUT', 2)

    def execute(self, client: socket.socket, args: list[bytes]):
        try:
            path = Path(ROOT_DIR + args[0].decode("utf-8"))
        except UnicodeDecodeError:
            client.send(b'501 Internal Server Error\n')
            return

        try:
            data = base64.b64decode(args[1])
        except:
            client.send(b'501 Internal Server Error\n')
            return

        real_path = str(path.resolve())
        if not real_path.startswith(ROOT_DIR):
            client.send(b'404 Not Found\n')
            return

        with open(real_path, "wb") as f:
            f.write(data)

        client.send(b'200 OK\n')

class CMPRCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'CMPR', 1)

    def execute(self, client: socket.socket, args: list[bytes]):
        try:
            path = Path(ROOT_DIR + args[0].decode("utf-8"))
        except UnicodeDecodeError:
            client.send(b'501 Internal Server Error\n')
            return

        real_path = str(path.resolve())
        if not real_path.startswith(ROOT_DIR):
            client.send(b'404 Not Found\n')
            return

        with open(real_path, "rb") as f:
            res = cc.compress(f.read())

        basename = os.path.basename(real_path)
        out_path = os.path.join(ROOT_DIR, basename + ".cc")
        with open(out_path, "wb") as f:
            f.write(res)

        client.send(b'200 OK\n')

class DCMPRCommand(FSPCommand):
    def __init__(self):
        super().__init__(b'DCMPR', 1)

    def execute(self, client: socket.socket, args: list[bytes]):
        try:
            path = Path(ROOT_DIR + args[0].decode("utf-8"))
        except UnicodeDecodeError:
            client.send(b'501 Internal Server Error\n')
            return

        real_path = str(path.resolve())
        if not real_path.startswith(ROOT_DIR):
            client.send(b'404 Not Found\n')
            return

        if not real_path.endswith(".cc"):
            client.send(b'402 Bad Extension\n')
            return

        with open(real_path, "rb") as f:
            res = cc.decompress(f.read())

        basename = os.path.basename(real_path)[:-3]
        out_path = os.path.join(ROOT_DIR, basename)
        with open(out_path, "wb") as f:
            f.write(res)

        client.send(b'200 OK\n')

server_commands : list[FSPCommand] = [
    NOOPCommand(),
    QUITCommand(),
    LSTCommand(),
    RETRCommand(),
    PUTCommand(),
    CMPRCommand(),
    DCMPRCommand()
]


def sigint_handler(sig, frame):
    print("Quitting...")
    sys.exit(0)

def error_callback(msg):
    print("[ERR] Got an error in compression module :", msg)

def get_server_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.listen(5)
    return sock

def parse_command(command: bytes):
    parts = command.split(b' ')
    for cmd_obj in server_commands:
        if parts[0] == cmd_obj.mnemonic and len(parts) == cmd_obj.nargs + 1:
            return cmd_obj, parts[1:]
    return (None, None)

def connection_handler(client, addr):
    print(f"Connection received from {addr[0]}:{addr[1]}")
    client.settimeout(1.0)

    buffer = b''
    running = True
    while running:
        if client.fileno() == -1:
            break

        try:
            chunk = client.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            print("Something went wrong while handling client !")
            break

        if not chunk:
            break

        buffer += chunk

        while b"\n" in buffer and running:
            command, buffer = buffer.split(b"\n", 1)

            parsed_cmd, args = parse_command(command)
            if not parsed_cmd:
                try:
                    client.sendall(b"404 UNKNOWN COMMAND\n")
                except OSError:
                    running = False
                except Exception:
                    # just in case
                    continue
                finally:
                    continue

            try:
                parsed_cmd.execute(client, args)
            except OSError:
                print("Something went wrong while executing command !")
                running = False

            if client.fileno() == -1:
                running = False

    client.close()

def main():
    signal.signal(signal.SIGINT, sigint_handler)
    server = get_server_socket(PORT) 
    cc.set_err_callback(error_callback)

    while True:
        client, addr = server.accept()
        client.send(b'FSP v1.0\n')
        connection_handler(client, addr)

if __name__ == "__main__":
    main()
