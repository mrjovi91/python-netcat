#!/usr/local/bin/python3

# from settings.settings import Settings

import argparse
import base64
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
import traceback


# settings = Settings()

def execute_command(command):
    command = command.strip()
    if not command:
        return
    result = subprocess.check_output(shlex.split(command), stderr=subprocess.STDOUT)
    return result.decode()

class CustomNetCat:
    def __init__(self, args, buffer=None, header_size=8):
        self.args = args
        self.buffer = buffer
        self._header_size = header_size
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows socket in time_wait state to be resued

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        self._sock.connect((self.args.target, self.args.port))
        if self.buffer:
            self.send_msg(self._sock, self.buffer, base64encoded=True)
        
        try:
            while True:
                try:
                    response = self.receive_msg(self._sock)
                    if response:
                        print(response)
                        msg = input('> ')
                        self.send_msg(self._sock, msg)
                except EOFError:
                    continue
        except KeyboardInterrupt:
            print('Program Manually Terminated')
            self._sock.close()
            sys.exit()

    def listen(self):
        self._sock.bind((self.args.target, self.args.port))
        self._sock.listen(5)
        while True:
            client_sock, _ = self._sock.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_sock,))
            client_thread.start()

    def _file_upload(self, sock):
        file_buffer = self.receive_msg(sock)
        with open(self.args.upload, 'wb') as uploaded_file:
            uploaded_file.write(file_buffer)
        msg = f'File {self.args.upload} uploaded successfully!'
        self.send_msg(sock, msg)

    def _spawn_shell(self, sock):
        try:
            self.send_msg(sock, 'Shell > ')
            while True:
                request = self.receive_msg(sock)
                if request.strip() == 'exit':
                    break
                result = execute_command(request)
                self.send_msg(sock, f'{result}\nShell > ')
        except:
            error = traceback.format_exc()
            print(error)
            self._sock.close()
            sys.exit()

    def _interaction_mode(self, sock):
        response = self.receive_msg(sock)
        print(response)
        if response:
            msg = input('> ')
            self.send_msg(sock, msg)

    def handle(self, client_sock):
        if self.args.execute:
            output = execute_command(self.args.execute)
            self.send_msg(client_sock, output)
        
        elif self.args.upload:
            self._file_upload(client_sock)

        elif self.args.command:
            self._spawn_shell(client_sock)

        try:
            self.send_msg(client_sock, 'Connected.')
            while True:
                self._interaction_mode(client_sock)
        except KeyboardInterrupt:
            self._sock.close()
            sys.exit()
        
                

    def send_msg(self, sock, raw_msg, base64encoded=False):
        if base64encoded:
            msg = f"{str(base64.b64encode(raw_msg.encode('utf-8')), 'utf-8')}\r\n"
        else:
            msg = f'{raw_msg}\r\n'
        msglen = len(msg)
        flag = 'T' if base64encoded else 'F'
        msg = f'{flag:<{self._header_size}}'+ msg
        payload = f'{msglen:<{self._header_size}}'+ msg
        sock.send(payload.encode('utf-8'))

    def receive_msg(self, sock):
        buffer = ""
        new_msg = True
        while True:
            raw_request = sock.recv(self._header_size)
            if new_msg:
                msglen = int(raw_request.decode("utf-8"))
                raw_request = sock.recv(self._header_size)
                base64encoded = raw_request.decode("utf-8").strip() == 'T'
                new_msg = False
                continue
            buffer += raw_request.decode("utf-8")
            if len(buffer) >= msglen:
                break

        result = buffer.strip()
        if base64encoded:
            payload =  base64.b64decode(result.encode('utf-8'))
            if self.args.upload:
                return payload
            return payload.decode('utf-8')
        return result


def main():
    help_msg = '''Example:
    netcat.py -t 10.1.1.1 -p 4321 -l # Interactive listening mode
    netcat.py -t 10.1.1.1 -p 4321 -l -c # command shell
    netcat.py -t 10.1.1.1 -p 4321 -l -u=payload.py # upload file
    netcat.py -t 10.1.1.1 -p 4321 -l -e=\"python payload.py\" # execute command
    echo \"Hello World\" | netcat.py -t 10.1.1.1 -p 4321 -s # Echo text to server port 4321 through stdin
    netcat.py -t 10.1.1.1 -p 4321 # Connect to server
    '''

    parser = argparse.ArgumentParser(
        description = 'Python Netcat Tool',
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(help_msg)
    )

    parser.add_argument('-c', '--command', action='store_true', help="Spawns a command shell")
    parser.add_argument('-e', '--execute', help="Execute specified command")
    parser.add_argument('-l', '--listen', action='store_true', help="Set mode to listen")
    parser.add_argument('-p', '--port', type=int, default=4321, help="Port to listen on")
    parser.add_argument('-t', '--target', default="127.0.0.1", help="Target IP")
    parser.add_argument('-u', '--upload', help="upload file")
    parser.add_argument('-s', '--stdin', action='store_true', help="Specified when input is taken from stdin")

    args = parser.parse_args()
    if args.stdin:
        buffer = sys.stdin.read()
    else:
        buffer = ''

    nc = CustomNetCat(args, buffer)
    nc.run()

if __name__ == "__main__":
    main()