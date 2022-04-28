# Jamiel Impoy
# HW5
# CS 468

import sys
import paramiko
from paramiko.py3compat import b, u, decodebytes
import os
from os import chdir
import socket
import threading
from binascii import hexlify
from pathlib import Path

attempts = 0
running = True
in_dir = False

def ssh_command_handler(command, channel):
    # Checks if we are in ssh directory, if not, checks if it exists, if it doesn't, creates it and changes to it
    global in_dir
    print(Path.cwd())
    if not in_dir:  
        path = Path('./dir')
        if Path.cwd() != path:
            if not path.exists():
                path = Path.cwd() / 'dir'
                path.mkdir()
            chdir(path)
            in_dir = True
    
    # Commands
    if "ls" in command:
        path = Path(Path.cwd())
        contents = [x for x in path.iterdir() if x.is_dir() or x.is_file()]
        print(contents)
    elif "echo" in command:
        parts = command.split(" ")
        print(parts)
        print("echo")
    elif"cat" in command:
        print("cat")
    elif "cp" in command:
        print("cp")
    else:
        print("Invalid command")

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        global attempts
        attempts += 1
        # if (attempts < 5):
        #     print(attempts)
        #     return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def init():
    if "-p" in sys.argv:
        try:
            port = sys.argv[sys.argv.index("-p") + 1]

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            sock.bind(("127.0.0.1", int(port)))

            while True:
                sock.listen(100)
                client, addr = sock.accept()

                t = paramiko.Transport(client)
                if os.path.exists('./honeypot.key'):
                    t.add_server_key(paramiko.RSAKey.from_private_key_file('./honeypot.key'))        
                else:
                    key = paramiko.RSAKey.generate(2048)
                    key.write_private_key_file('./honeypot.key')
                    t.add_server_key(key)
                server = Server()
                t.start_server(server=server)
                
                # accept the connection and set its idle timeout
                chan = t.accept(20)
                chan.settimeout(60)
                
                # Get the user of the connection
                username = t.get_username()

                if chan is None:
                    print('Timeout waiting for channel')
                    continue
                print(username + " connected")

                chan.send("Welcome to the Honeypot!\n")     
                run = True
                while run:
                    chan.send("\r")
                    chan.send(username + "@" + addr[0] +"$ ")
                    command = ""
                    while not command.endswith("\r"):
                        transport = chan.recv(1024)
                        command += transport.decode("utf-8")
                        print(transport)
                        if transport == b'\x7f':
                            command = command[:-2]
                            print(command)
                        chan.send(command)
                    chan.send("\r\n")
                    command = command.rstrip()
                    print(command)
                    if command == "exit":
                        run = False
                    else:
                        ssh_command_handler(command, chan)

                chan.close()
                t.close()
                print("Closed connection")
        except KeyboardInterrupt:
            print("\nInterrupt received, exiting...")
            sys.exit(1)
        except Exception as e:
            print(e)
            print("user is inactive")
            sys.exit(1)
    else:   
        print("Please specify a port with -p")

if __name__ == "__main__":
    init()