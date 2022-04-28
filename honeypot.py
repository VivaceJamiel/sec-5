# Jamiel Impoy
# HW5
# CS 468

import sys
import paramiko
from paramiko.py3compat import b, u, decodebytes
import os
import socket
import threading
from binascii import hexlify
from pathlib import Path

attempts = 0
running = True

def ssh_command_handler(command):
    print('default: ', command)

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
                        chan.send(transport)
                        command += transport.decode("utf-8")
                    chan.send("\r\n")
                    command = command.rstrip()
                    print(command)
                    if command == "exit":
                        run = False
                    else:
                        print("other command")

                chan.close()
                t.close()
                print("Closed connection")
        except KeyboardInterrupt:
            print("\nInterrupt received, exiting...")
            sys.exit(1)
        except Exception as e:
            print("user is inactive")
            sys.exit(1)
    else:   
        print("Please specify a port with -p")

if __name__ == "__main__":
    init()