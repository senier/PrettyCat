import socket
import threading

from Crypto.Cipher import AES

class SPG_base:

    def __init__ (self, name, config, recvmethods, needconfig = False):

        if needconfig and config == None:
            raise Exception ("Missing config for " + name)

        self.recvmethods = recvmethods
        self.name        = name
        self.config      = config

    def start (self): pass
    def join (self): pass
    def setDaemon (self, dummy): pass

class comp (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)
        self.data1  = None
        self.data2 = None

    def recv_data1 (self, data):

        if self.data1 == None:
            self.data1 = data
        else:
            self.recvmethods['result'](self.data2 == data)
            self.data2 = None

    def recv_data2 (self, data):

        if self.data1 == None:
            self.data2 = data
        else:
            self.recvmethods['result'](self.data1 == data)
            self.data1 = None

class encrypt (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        if not 'keylen' in config.attrib:
            raise Exception ("No keylen set for encrypt")

        keylen = int(config.attrib['keylen'])

        if (keylen == 128):
            self.keylen = 16
        elif (keylen == 192):
            self.keylen = 24
        elif (keylen == 256):
            self.keylen = 32
        else:
            raise Exception ("Invalid keylen: " + keylen)

        self.ctr = None
        self.key = None

        print ("Encrypt for " + name)

    def recv_plaintext (self, pt):

        if not self.ctr:
            raise Exception ("Encryption while no counter set")

        if not self.key:
            raise Exception ("Encryption while no key set")

        if len(pt) != AES.block_size:
            raise Exception ("Encryption with invalid blocksize (expected " + str (AES.blocksize) + ")")

        cipher = AES.new (self.key, AES.MODE_CBC, self.ctr)
        self.recvmethods['ciphertext'](cipher.encrypt (pt))
        print ("Encryption done")

    def recv_ctr (self, ctr):
        if len(ctr) != AES.block_size:
            raise Exception ("Counter length != " + str (AES.block_size))
        self.ctr = ctr
        print ("Ctr set")

    def recv_key (self, key):
        if len(key) != self.keylen:
            raise Exception ("Keylen != " + str(self.keylen))
        self.key = key
        print ("Key set")

class output (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.port    = int(config.attrib['port'])
        self.host    = config.attrib['host'] if 'host' in config.attrib else "127.0.0.1"
        self.bufsize = config.attrib['bufsize'] if 'bufsize' in config.attrib else 1024

        print ("   Output init: " + self.host + ":" + str(self.port))

        self.socket  = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect ((self.host, self.port))

    def recv_data (self, data):
        self.socket.send (data)
    
class input (threading.Thread):

    def __init__ (self, name, config, recvmethods):
        super().__init__ ()

        print ("   Input init: " + str(recvmethods))

        self.recvmethods = recvmethods
        self.name        = name
        self.config      = config
        self.port        = int(config.attrib['port'])
        self.host        = config.attrib['host'] if 'host' in config.attrib else "127.0.0.1"
        self.bufsize     = config.attrib['bufsize'] if 'bufsize' in config.attrib else 1024

        self.socket  = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind ((self.host, self.port))
        self.socket.listen (1)

        print ("   Waiting: TCP for " + name + " on " + self.host + ": " + str(self.port))
        (self.conn, addr) = self.socket.accept()
        print ("   Connect: " + str(addr[0]) + ":" + str(addr[1]))
        message = name + ": ";
        self.conn.send (message.encode())

    def run (self):

        while True:
            if 'data' in self.recvmethods:
                data = self.conn.recv (self.bufsize)
                self.recvmethods['data'](data)

class const (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods, needconfig = True)

        if not 'value' in config.attrib:
            raise Exception ("No value set for const")

        self.value = self.config.attrib['value']

    def start (self):
        self.recvmethods['const'](self.value)
