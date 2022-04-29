# Jamiel Impoy
# HW5
# CS 468

import shutil
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
        for x in contents:
            parts = x.parts
            file = parts[-1]
            channel.send(file + " ")
        if contents:
            print("not empty")
            channel.send("\r\n")
    elif "echo" in command:
        parts = command.split(" ")
        text = command.split("\"")
        string = text[1]
        file = parts[-1]
        if '.txt' in file:
            path = Path(file)
            path.touch()
            path.write_text(string)
        else:
            channel.send("Uknown file extension\r\n")
    elif "cat" in command:
        print("cat")
        parts = command.split(" ")
        print(parts)
        file = parts[-1]
        if '.txt' in file:
            path = Path(file)
            if path.is_file():
                text = path.read_text()
                channel.send(text)
                channel.send("\r\n")
            else:
                channel.send("File " + file + " not found\r\n")
        else:
            channel.send("Uknown file extension\r\n")
    elif "cp" in command:
        print("cp")
        parts = command.split(" ")
        source = Path(parts[-2])
        dest = Path(parts[-1])
        if '.txt' in parts[-2] and '.txt' in parts[-1]:
            shutil.copyfile(source, dest)
        else:
            channel.send("Uknown file extension\r\n")
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
    path = Path('dir')
    shutil.rmtree(path)
    
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
                        # If client presses ctrl+c, exit
                        if transport == b'\x03':
                            chan.send("\n")
                            print("Keyboard Interrupt... Exiting")
                            sys.exit(1)

                        # If client presses backspace, remove last character
                        if transport == b'\x7f':
                            if command == "":
                                continue
                            else:
                                command = command[:-1]
                                chan.send('\b \b')
                        else:
                            command += transport.decode("utf-8")
                            chan.send(transport)
                        
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