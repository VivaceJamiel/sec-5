import logging
import socket
import sys
import threading

import paramiko

logging.basicConfig()
logger = logging.getLogger()

running = True
host_key = paramiko.RSAKey(filename='id_rsa')


def ssh_command_handler(command):
    print('default : ', command)


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_channel_exec_request(self, channel, command):
        global running
        # This is the command we need to parse
        if command == 'exit':
            running = False
        ssh_command_handler(command)
        self.event.set()
        return True


def listener():
    print('listener')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 2222))

    sock.listen(100)
    client, addr = sock.accept()

    t = paramiko.Transport(client)
    t.set_gss_host(socket.getfqdn(""))
    t.load_server_moduli()
    t.add_server_key(host_key)
    server = Server()
    t.start_server(server=server)

    # Wait 30 seconds for a command
    server.event.wait(30)
    t.close()
    print('end listener')


def run_server(command_handler):
    global running
    global ssh_command_handler
    ssh_command_handler = command_handler
    while running:
        try:
            listener()
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as exc:
            logger.error(exc)


def run_in_thread(command_handler):
    thread = threading.Thread(target=run_server, args=(command_handler,))
    thread.start()


if __name__ == '__main__':
    run_in_thread(ssh_command_handler)