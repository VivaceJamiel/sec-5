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

class SubSystemHandler(paramiko.SubsystemHandler):
    def start_subsystem(self, name, transport, channel):
        self.event.set()
        return super().start_subsystem(name, transport, channel)        

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        global attempts
        attempts += 1
        if (attempts < 5):
            return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL


# class Server(paramiko.ServerInterface):
#     def __init__(self):
#         self.event = threading.Event()

#     def check_channel_request(self, kind, chan_id):
#         if kind == "session":
#             return paramiko.OPEN_SUCCEEDED
#         return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

#     def check_auth_password(self, username, password):
#         global attempts
#         attempts += 1
#         if (attempts < 5):
#             print(attempts)
#             return paramiko.AUTH_FAILED
#         print(attempts)
#         return paramiko.AUTH_SUCCESSFUL

#     def check_auth_publickey(self, username, key):
#         print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
#         if (username == "robey") and (key == self.good_pub_key):
#             return paramiko.AUTH_SUCCESSFUL
#         return paramiko.AUTH_FAILED

#     def check_auth_gssapi_with_mic(self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None):
#         if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
#             return paramiko.AUTH_SUCCESSFUL
#         return paramiko.AUTH_FAILED

#     def check_channel_shell_request(self, channel):
#         self.event.set()
#         return True


if __name__ == "__main__":
    if "-p" in sys.argv:
        port = sys.argv[sys.argv.index("-p") + 1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", int(port)))
        sock.listen(100)
        print("Listening for connection...")
        client, addr = sock.accept()
        print("Got a connection!")
        t = paramiko.Transport(client)        
        if os.path.exists('./honeypot.key'):
            t.add_server_key(paramiko.RSAKey.from_private_key_file('./honeypot.key'))        
        else:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file('./honeypot.key')
            t.add_server_key(key)

        server = Server()

        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print("*** SSH negotiation failed.")
            sys.exit(1)
        
    else:
        print("No port specified")
        sys.exit(1)