import socket
import threading

from Crypto.Cipher import AES

class SPG_base:

    def __init__ (self, name, config, recvmethods):
        print ("   Base init: " + str(recvmethods))
        self.recvmethods = recvmethods
        self.name        = name
        self.config      = config

    def start (self): pass
    def join (self): pass

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
            raise Exception ("Encryption with invalid blocksize")

        cipher = AES.new (self.key, AES.MODE_CBC, self.ctr)
        self.send_ct (cipher.encrypt (pt))
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
    
class env (threading.Thread):

    def __init__ (self, name, config, recvmethods):
        super(env, self).__init__ ()

        print ("   Env init: " + str(recvmethods))

        self.recvmethods = recvmethods
        self.name        = name
        self.config      = config
        self.port        = int(config.attrib['port'])
        self.host        = config.attrib['host'] if 'host' in config.attrib else "127.0.0.1"
        self.bufsize     = config.attrib['bufsize'] if 'bufsize' in config.attrib else 1024

        print ("   Default TCP for " + name + ", on " + self.host + ": " + str(self.port))

    def run (self):

        self.socket  = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind ((self.host, self.port))
        self.socket.listen (1)

        while True:
            (conn, addr) = self.socket.accept()
            print ("Connected with " + str(addr[0]) + ": " + str(addr[1]))
            data = conn.recv (self.bufsize)
            if not data: break
            self.recvmethods['data'](data)
            conn.close()

    def recv_data (self, data):
        self.conn (data)
