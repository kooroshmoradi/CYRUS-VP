import socket
import threading
import select
import sys
import time
import getopt

# Configuration
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 80
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 200 Connection established\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threads_lock = threading.Lock()
        self.log_lock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        try:
            self.soc.bind((self.host, self.port))
            self.soc.listen(5)  # Reasonable backlog
            self.running = True
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.add_conn(conn)
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.running = False
            self.soc.close()

    def print_log(self, log):
        with self.log_lock:
            print(log)

    def add_conn(self, conn):
        with self.threads_lock:
            if self.running:
                self.threads.append(conn)

    def remove_conn(self, conn):
        with self.threads_lock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threads_lock:
            for c in list(self.threads):
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, soc_client, server, addr):
        super().__init__()
        self.client_closed = False
        self.target_closed = True
        self.client = soc_client
        self.client_buffer = ''
        self.server = server
        self.log = f'Connection: {addr}'
        self.method = None  # Initialize method

    def close(self):
        if not self.client_closed:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except socket.error:
                pass
            finally:
                self.client_closed = True
        if not self.target_closed and hasattr(self, 'target'):
            try:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
            except socket.error:
                pass
            finally:
                self.target_closed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            host_port = self.find_header(self.client_buffer, 'X-Real-Host')
            if not host_port:
                host_port = DEFAULT_HOST
            split = self.find_header(self.client_buffer, 'X-Split')
            if split:
                self.client.recv(BUFLEN)
            if host_port:
                passwd = self.find_header(self.client_buffer, 'X-Pass')
                if host_port.startswith(('127.0.0.1', 'localhost')):
                    self.method = 'CONNECT'
                    self.method_connect(host_port)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')
        except socket.error as e:
            self.log += f' - error: {e}'
            self.server.print_log(self.log)
        finally:
            self.close()
            self.server.remove_conn(self)

    def find_header(self, head, header):
        aux = head.find(header + ': ')
        if aux == -1:
            return ''
        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')
        if aux == -1:
            return ''
        return head[:aux]

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 22  # Default for CONNECT
        try:
            (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]
            self.target = socket.socket(soc_family, soc_type, proto)
            self.target_closed = False
            self.target.connect(address)
        except socket.error:
            self.target_closed = True
            raise

    def method_connect(self, path):
        self.log += f' - CONNECT {path}'
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''
        self.server.print_log(self.log)
        self.do_connect()

    def do_connect(self):
        socs = [self.client, self.target]
        count = 0
        while True:
            count += 1
            try:
                (recv, _, err) = select.select(socs, [], socs, 3)
                if err:
                    break
                for in_ in recv:
                    data = in_.recv(BUFLEN)
                    if not data:
                        break
                    if in_ is self.target:
                        self.client.sendall(data)
                    else:
                        self.target.sendall(data)
                    count = 0
            except socket.error:
                break
            if count >= TIMEOUT:
                break

def print_usage():
    print('Usage: proxy.py -p <port>')
    print('       proxy.py -b <bindAddr> -p <port>')
    print('       proxy.py -b 0.0.0.0 -p 80')

def parse_args(argv):
    global LISTENING_ADDR, LISTENING_PORT
    try:
        opts, _ = getopt.getopt(argv, "hb:p:", ["bind=", "port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print("\n:-------PythonProxy-------:\n")
    print(f"Listening addr: {host}")
    print(f"Listening port: {port}\n")
    print(":-------------------------:\n")
    try:
        server = Server(host, port)
        server.start()
        while True:
            try:
                time.sleep(2)
            except KeyboardInterrupt:
                print('Stopping...')
                server.close()
                break
    except socket.error as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()