# Jamiel Impoy
# HW5
# CS 468

import sys
import socketserver
import paramiko
import os
import socket
import threading
import pathlib

attempts = 0

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chan_id):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        global attempts
        attempts += 1
        if (attempts < 5):
            print(attempts)
            return paramiko.AUTH_FAILED
        print(attempts)
        return paramiko.AUTH_SUCCESSFUL


if __name__ == "__main__":
    if "-p" in sys.argv:
        port = sys.argv[sys.argv.index("-p") + 1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", int(port)))

        sock.listen(5)


        client, addr = sock.accept()
        t = paramiko.Transport(client)
        if os.path.exists('./honeypot.key'):
            t.load_server_moduli()
            t.add_server_key(paramiko.RSAKey.from_private_key_file('./honeypot.key'))        
        else:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file('./honeypot.key')
            t.add_server_key(key)
        t.start_server(server=Server())
        chan = t.accept(60)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", int(port)))

        sock.listen(5)


        client, addr = sock.accept()
        t = paramiko.Transport(client)
        if os.path.exists('./honeypot.key'):
            t.load_server_moduli()
            t.add_server_key(paramiko.RSAKey.from_private_key_file('./honeypot.key'))        
        else:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file('./honeypot.key')
            t.add_server_key(key)
        t.start_server(server=Server())
        chan = t.accept(60)
        if chan is None:
            print("could not accept channel")
            sys.exit(1)
        print("accepted channel")

        chan.close()
        t.close()
        client.close()
        sock.close()
    else:
        print("No port specified")
        sys.exit(1)