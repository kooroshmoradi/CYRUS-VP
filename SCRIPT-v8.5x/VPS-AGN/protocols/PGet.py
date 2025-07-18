import sys
import time
import getopt
import socket
import threading
import base64

# CONFIG
CONFIG_LISTENING = "0.0.0.0:8799"
CONFIG_PASS = "pwd.pwd"


class Logger:
    logLock = threading.Lock()
    LOG_INFO = 1
    LOG_WARN = 2
    LOG_ERROR = 3

    def printWarn(self, log):
        self.log(log, self.LOG_WARN)

    def printInfo(self, log):
        self.log(log, self.LOG_INFO)

    def printError(self, log):
        self.log(log, self.LOG_ERROR)

    def printLog(self, log, logLevel):
        if logLevel == self.LOG_INFO:
            self.printInfo(f"<-> {log}")
        elif logLevel == self.LOG_WARN:
            self.printWarn(f"<!> {log}")
        elif logLevel == self.LOG_ERROR:
            self.printError(f"<#> {log}")

    def log(self, log, logLevel):
        with self.logLock:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {log}")


class PasswordSet:
    FILE_EXEMPLE = "master=passwd123\n127.0.0.1:22=pwd321;321pawd\n1.23.45.67:443=pass123"

    def __init__(self, masterKey=None):
        self.masterKey = masterKey
        self.map = {}

    def parseFile(self, fileName):
        isValid = False

        try:
            with open(fileName, "r") as f:
                content = f.readlines()
        except IOError:
            return False

        content = [x.strip() for x in content if x.strip() and not x.startswith("#")]

        if content:
            masterKey = content[0]
            if masterKey.startswith("master"):
                parts = self.splitParam(masterKey, "=")
                if parts:
                    self.masterKey = parts[1]
                    isValid = True

            for line in content[1:]:
                hostAndPass = self.splitParam(line, "=")
                if hostAndPass:
                    self.map[hostAndPass[0]] = hostAndPass[1].split(";")

        return isValid

    def isValidKey(self, key, target):
        if self.masterKey == key:
            return True
        if hasattr(self, "map") and target in self.map:
            return key in self.map[target]
        return False

    def splitParam(self, param, c):
        index = param.find(c)
        if index != -1:
            return [param[:index], param[index + 1 :]]
        return None


class ClientRequest:
    MAX_LEN_CLIENT_REQUEST = 1024 * 100
    HEADER_CONTENT_LENGTH = "Content-Length"
    HEADER_ACTION = "X-Action"
    ACTION_CLOSE = "close"
    ACTION_DATA = "data"

    def __init__(self, socket):
        self.socket = socket
        self.readContent = False

    def parse(self):
        line = ""
        count = 0
        self.isValid = False
        self.data = None
        self.contentLength = None
        self.action = None

        while line != "\r\n" and count < self.MAX_LEN_CLIENT_REQUEST:
            line = self.readHttpLine()
            if line is None:
                break

            if line.startswith(self.HEADER_ACTION):
                self.action = self.getHeaderVal(line)
                if self.action in (self.ACTION_CLOSE, self.ACTION_DATA):
                    self.isValid = True

            count += len(line)

        if self.readContent and self.contentLength:
            if 0 < self.contentLength < self.MAX_LEN_CLIENT_REQUEST:
                self.data = self.readFully(self.contentLength)

        return self.isValid

    def readHttpLine(self):
        line = ""
        count = 0

        try:
            b = self.socket.recv(1)
            if not b:
                return None

            while count < self.MAX_LEN_CLIENT_REQUEST:
                count += 1
                line += b.decode("utf-8", errors="ignore")

                if b == b"\r":
                    b = self.socket.recv(1)
                    count += 1
                    if not b:
                        break
                    line += b.decode("utf-8", errors="ignore")
                    if b == b"\n":
                        break

                b = self.socket.recv(1)
                if not b:
                    break
        except socket.error:
            return None

        return line

    def getHeaderVal(self, header):
        ini = header.find(":")
        if ini == -1:
            return None
        ini += 2
        fim = header.find("\r\n")
        return header[ini:fim] if fim != -1 else header[ini:]

    def readFully(self, n):
        count = 0
        data = bytearray()

        try:
            while count < n:
                packet = self.socket.recv(n - count)
                if not packet:
                    break
                count += len(packet)
                data.extend(packet)
            return bytes(data)
        except socket.error:
            return None


class Client(threading.Thread):
    ACTION_DATA = "data"
    BUFFER_SIZE = 4096

    def __init__(self, id, readSocket, target):
        super().__init__()
        self.targetHostPort = target
        self.id = id
        self.readSocket = readSocket
        self.logger = Logger()
        self.isStopped = False
        self.onCloseFunction = None
        self.closeLock = threading.Lock()
        self.threadEndCount = 0
        self.writeSocket = None

    def connectTarget(self):
        aux = self.targetHostPort.find(":")
        host = self.targetHostPort[:aux]
        port = int(self.targetHostPort[aux + 1 :])
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((host, port))

    def run(self):
        try:
            self.connectTarget()
            request = ClientRequest(self.readSocket)
            request.readContent = False

            if not request.parse() or request.action != self.ACTION_DATA:
                raise ValueError("client sends invalid request")

            threadRead = ThreadRelay(self.readSocket, self.target, self.finallyClose)
            threadRead.logFunction = self.log
            threadRead.start()

            threadWrite = ThreadRelay(self.target, self.writeSocket, self.finallyClose)
            threadWrite.logFunction = self.log
            threadWrite.start()
        except Exception as e:
            self.log(f"connection error - {type(e).__name__} - {e}", Logger.LOG_ERROR)
            self.close()

    def finallyClose(self):
        with self.closeLock:
            self.threadEndCount += 1
            if self.threadEndCount == 2:
                self.close()

    def close(self):
        with self.closeLock:
            if not self.isStopped:
                self.isStopped = True
                for sock in (self.target, self.writeSocket, self.readSocket):
                    if hasattr(self, sock.__name__) and sock:
                        try:
                            sock.close()
                        except:
                            pass
                self.onClose()
                self.log("closed", Logger.LOG_INFO)

    def onClose(self):
        if self.onCloseFunction:
            self.onCloseFunction(self)

    def log(self, msg, logLevel):
        msg = f"Client {self.id}: {msg}"
        self.logger.printLog(msg, logLevel)


class ThreadRelay(threading.Thread):
    def __init__(self, readSocket, writeSocket, closeFunction=None):
        super().__init__()
        self.readSocket = readSocket
        self.writeSocket = writeSocket
        self.logFunction = None
        self.closeFunction = closeFunction

    def run(self):
        try:
            while True:
                data = self.readSocket.recv(Client.BUFFER_SIZE)
                if not data:
                    break
                self.writeSocket.sendall(data)
            self.writeSocket.shutdown(socket.SHUT_WR)
        except Exception as e:
            if self.logFunction:
                self.logFunction(f"threadRelay error: {type(e).__name__} - {e}", Logger.LOG_ERROR)
        finally:
            if self.closeFunction:
                self.closeFunction()


class AcceptClient(threading.Thread):
    MAX_QTD_BYTES = 5000
    HEADER_BODY = "X-Body"
    HEADER_ACTION = "X-Action"
    HEADER_TARGET = "X-Target"
    HEADER_PASS = "X-Pass"
    HEADER_ID = "X-Id"
    ACTION_CREATE = "create"
    ACTION_COMPLETE = "complete"
    MSG_CONNECTION_CREATED = "Created"
    MSG_CONNECTION_COMPLETED = "Completed"

    ID_COUNT = 0
    ID_LOCK = threading.Lock()

    def __init__(self, socket, server, passwdSet=None):
        super().__init__()
        self.server = server
        self.passwdSet = passwdSet
        self.socket = socket

    def run(self):
        needClose = True
        try:
            head = self.readHttpRequest()
            bodyLen = self.getHeaderVal(head, self.HEADER_BODY)
            if bodyLen:
                try:
                    self.readFully(int(bodyLen))
                except ValueError:
                    pass

            action = self.getHeaderVal(head, self.HEADER_ACTION)
            if action is None:
                self.log("client sends no action header", Logger.LOG_WARN)
                self.socket.sendall(b"HTTP/1.1 400 NoActionHeader!\r\nServer: GetTunnelServer\r\n\r\n")
                return

            if action == self.ACTION_CREATE:
                target = self.getHeaderVal(head, self.HEADER_TARGET)
                if self.passwdSet:
                    passwd = self.getHeaderVal(head, self.HEADER_PASS)
                    try:
                        passwd = base64.b64decode(passwd).decode("utf-8")
                    except:
                        passwd = None

                    if passwd is None or not self.passwdSet.isValidKey(passwd, target):
                        self.log("client sends wrong key", Logger.LOG_WARN)
                        self.socket.sendall(b"HTTP/1.1 403 Forbidden\r\nServer: GetTunnelServer\r\n\r\n")
                        return

                if target and self.isValidHostPort(target):
                    id = self.generateId()
                    client = Client(id, self.socket, target)
                    client.onCloseFunction = self.server.removeClient
                    self.server.addClient(client)
                    response = f"HTTP/1.1 200 {self.MSG_CONNECTION_CREATED}\r\nServer: GetTunnelServer\r\nX-Id: {id}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: Keep-Alive\r\n\r\n"
                    self.socket.sendall(response.encode("utf-8"))
                    self.log(f"connection created - {id}", Logger.LOG_INFO)
                    needClose = False
                else:
                    self.log("client sends no valid target", Logger.LOG_WARN)
                    self.socket.sendall(b"HTTP/1.1 400 Target!\r\nServer: GetTunnelServer\r\n\r\n")

            elif action == self.ACTION_COMPLETE:
                id = self.getHeaderVal(head, self.HEADER_ID)
                if id:
                    client = self.server.getClient(id)
                    if client:
                        client.writeSocket = self.socket
                        self.log(f"connection completed - {id}", Logger.LOG_INFO)
                        self.socket.sendall(
                            f"HTTP/1.1 200 {self.MSG_CONNECTION_COMPLETED}\r\nServer: GetTunnelServer\r\nConnection: Keep-Alive\r\n\r\n".encode(
                                "utf-8"
                            )
                        )
                        client.start()
                        needClose = False
                    else:
                        self.log("client try to complete non existing connection", Logger.LOG_WARN)
                        self.socket.sendall(b"HTTP/1.1 400 CreateFirst!\r\nServer: GetTunnelServer\r\n\r\n")
                else:
                    self.log("client sends no id header", Logger.LOG_WARN)
                    self.socket.sendall(b"HTTP/1.1 400 NoID!\r\nServer: GetTunnelServer\r\n\r\n")
            else:
                self.log("client sends invalid action", Logger.LOG_WARN)
                self.socket.sendall(b"HTTP/1.1 400 InvalidAction!\r\nServer: GetTunnelServer\r\n\r\n")

        except Exception as e:
            self.log(f"connection error - {type(e).__name__} - {e}", Logger.LOG_ERROR)
        finally:
            if needClose:
                try:
                    self.socket.close()
                except:
                    pass

    def log(self, msg, logLevel):
        self.server.log(msg, logLevel)

    def readHttpRequest(self):
        request = ""
        linha = ""
        count = 0

        while linha != "\r\n" and count < self.MAX_QTD_BYTES:
            linha = self.readHttpLine()
            if linha is None:
                break
            request += linha
            count += len(linha)
        return request

    def readHttpLine(self):
        line = ""
        count = 0
        try:
            b = self.socket.recv(1)
            if not b:
                return None
            while count < self.MAX_QTD_BYTES:
                count += 1
                line += b.decode("utf-8", errors="ignore")
                if b == b"\r":
                    b = self.socket.recv(1)
                    count += 1
                    if not b:
                        break
                    line += b.decode("utf-8", errors="ignore")
                    if b == b"\n":
                        break
                b = self.socket.recv(1)
                if not b:
                    break
        except socket.error:
            return None
        return line

    def getHeaderVal(self, head, header):
        if not head.startswith("\r\n"):
            header = f"\r\n{header}"
        if not header.endswith(": "):
            header = f"{header}: "
        ini = head.find(header)
        if ini == -1:
            return None
        end = head.find("\r\n", ini + 2)
        ini += len(header)
        if end == -1 or ini > end or ini >= len(head):
            return None
        return head[ini:end]

    def readFully(self, n):
        count = 0
        while count < n:
            packet = self.socket.recv(n - count)
            if not packet:
                break
            count += len(packet)

    def isValidHostPort(self, hostPort):
        aux = hostPort.find(":")
        if aux == -1 or aux >= len(hostPort) - 1:
            return False
        try:
            int(hostPort[aux + 1 :])
            return True
        except ValueError:
            return False

    def generateId(self):
        with self.ID_LOCK:
            self.ID_COUNT += 1
            return self.ID_COUNT


class Server(threading.Thread):
    def __init__(self, listening, passwdSet=None):
        super().__init__()
        self.listening = listening
        self.passwdSet = passwdSet
        self.running = False
        self.logger = Logger()
        self.isStopped = False
        self.clientsLock = threading.Lock()
        self.clients = []

    def run(self):
        try:
            self.soc = socket.socket(socket.AF_INET)
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.soc.settimeout(5)  # Increased timeout
            host, port = self.listening.split(":")
            self.soc.bind((host, int(port)))
            self.soc.listen(0)

            self.log(f"running on {self.listening}", Logger.LOG_INFO)
            self.running = True
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                    self.log(f"opening connection - {addr}", Logger.LOG_INFO)
                    self.acceptClient(c)
                except socket.timeout:
                    continue
        except Exception as e:
            self.log(f"connection error - {type(e).__name__} - {e}", Logger.LOG_ERROR)
        finally:
            self.close()

    def acceptClient(self, socket):
        accept = AcceptClient(socket, self, self.passwdSet)
        accept.start()

    def addClient(self, client):
        with self.clientsLock:
            self.clients.append(client)

    def removeClient(self, client):
        with self.clientsLock:
            if client in self.clients:
                self.clients.remove(client)

    def getClient(self, id):
        with self.clientsLock:
            for c in self.clients:
                if str(c.id) == str(id):
                    return c
        return None

    def close(self):
        with self.clientsLock:
            if not self.isStopped:
                self.isStopped = True
                if hasattr(self, "soc") and self.soc:
                    try:
                        self.soc.close()
                    except:
                        pass
                clientsCopy = self.clients[:]
                for c in clientsCopy:
                    c.close()
                self.log("closed", Logger.LOG_INFO)

    def log(self, msg, logLevel):
        msg = f"Server: {msg}"
        self.logger.printLog(msg, logLevel)


def print_usage():
    print("\nUsage: python get.py -b listening -p pass")
    print("Ex.: python get.py -b 0.0.0.0:80 -p pass123")
    print("   : python get.py -b 0.0.0.0:80 -p passFile.pwd\n")
    print("___Password file ex.:___")
    print(PasswordSet.FILE_EXEMPLE)


def parse_args(argv):
    global CONFIG_LISTENING, CONFIG_PASS
    try:
        opts, args = getopt.getopt(argv, "hb:p:", ["bind=", "pass="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            CONFIG_LISTENING = arg
        elif opt in ("-p", "--pass"):
            CONFIG_PASS = arg


def main():
    print(f"\n-->GetTunnelPy - Server v.25/06/2017\n")
    print(f"-->Listening: {CONFIG_LISTENING}")

    pwdSet = None
    if CONFIG_PASS:
        if CONFIG_PASS.endswith(".pwd"):
            pwdSet = PasswordSet()
            try:
                isValidFile = pwdSet.parseFile(CONFIG_PASS)
            except IOError as e:
                print(f"--#Error reading file: {type(e).__name__} - {e}")
                sys.exit(1)
            if not isValidFile:
                print("--#Error on parsing file!\n")
                print_usage()
                sys.exit(1)
            print(f"-->Pass file: {CONFIG_PASS}\n")
        else:
            if len(CONFIG_PASS) > 0:
                print("-->Pass     : yes\n")
                pwdSet = PasswordSet(CONFIG_PASS)
            else:
                print("-->Pass     : no\n")

    server = Server(CONFIG_LISTENING, pwdSet)
    server.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("<-> Stopping server...")
        server.running = False
        server.close()


if __name__ == "__main__":
    parse_args(sys.argv[1:])
    main()