import socket
import threading

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA, SHA256
from Crypto.PublicKey import DSA

exitval = 0
quiet = 0

def warn (message):
    print ("[1m[35mWARNING: [2m" + str(message) + "[0m")

def info (message):
    if not quiet:
        print ("[1m[34mINFO: [2m" + str(message) + "[0m")

def err (message):
    print ("[1m[31mERROR: [2m" + str(message) + "[0m")

def decode_mpi (mpi):
    length = int.from_bytes (mpi[0:4], byteorder='big')
    return (int.from_bytes (mpi[4:4+length], byteorder='big'), mpi[4+length:])

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
        self.data1 = None
        self.data2 = None

    def recv_data1 (self, data):

        if self.data2 == None:
            self.data1 = data
        else:
            result = 'True' if self.data2 == data else 'False'
            self.recvmethods['result'](result.encode())
            self.data1 = None
            self.data2 = None

    def recv_data2 (self, data):

        if self.data1 == None:
            self.data2 = data
        else:
            result = 'True' if self.data1 == data else 'False'
            self.recvmethods['result'](result.encode())
            self.data1 = None
            self.data2 = None

class counter_mode (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        if config == None:
            raise Exception ("Counter mode encryption not configured for '" + name + "'")

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

class encrypt (counter_mode):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.pt          = None
        self.key_changed = False

    def recv_ctr (self, ctr):

        # IV must only be set once
        if self.ctr != None: return

        self.ctr = int.from_bytes (ctr, byteorder='big')
        self.encrypt_if_valid ()

    def recv_key (self, key):
        if len(key) != self.keylen:
            raise Exception ("Keylen != " + str(self.keylen))

        self.key = bytes(key)
        self.key_changed = True
        self.encrypt_if_valid ()

    def recv_plaintext (self, pt):

        if len(pt) != AES.block_size:
            raise Exception ("Encryption with invalid blocksize (expected " + str (AES.block_size) + ")")

        self.pt = bytes(pt)
        self.encrypt_if_valid ()

    def send_ctr(self, ctr): pass

    def encrypt_if_valid (self):

        if self.ctr and self.key and self.pt:
            if not self.key_changed:
                self.ctr = self.ctr + 1
            ctr = self.ctr.to_bytes (AES.block_size, byteorder='big')
            cipher = AES.new (self.key, AES.MODE_CBC, ctr)
            self.key_changed = False
            self.recvmethods['ciphertext'](cipher.encrypt (self.pt))
            self.send_ctr(ctr)

class encrypt_ctr (encrypt):

    def send_ctr(self, ctr):
        self.recvmethods['ctr'](ctr)

class decrypt (counter_mode):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)
        self.ct = None

    def recv_ctr (self, ctr):

        self.ctr = int.from_bytes (ctr, byteorder='big')
        self.decrypt_if_valid ()

    def recv_key (self, key):
        if len(key) != self.keylen:
            raise Exception ("Keylen != " + str(self.keylen))

        self.key = bytes(key)
        self.decrypt_if_valid ()

    def recv_ciphertext (self, ct):

        if len(ct) != AES.block_size:
            raise Exception ("Decryption with invalid blocksize (expected " + str (AES.block_size) + ")")

        self.ct = bytes(ct)
        self.decrypt_if_valid()

    def decrypt_if_valid (self):
        if self.ctr and self.key and self.ct:
            cipher = AES.new (self.key, AES.MODE_CBC, self.ctr.to_bytes (AES.block_size, byteorder='big'))
            self.recvmethods['plaintext'](cipher.decrypt (self.ct))
            self.ctr = None

class output (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods, needconfig = True)

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

    def __init__ (self, name, config, recvmethods, needconfig = True):
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

        if 'string' in config.attrib:
            self.value = self.config.attrib['string']
        elif 'bytes' in config.attrib:
            self.value = bytearray (self.config.attrib['bytes'], 'utf-8')
        elif 'hexbytes' in config.attrib:
            try:
                self.value = bytearray.fromhex(self.config.attrib['hexbytes'])
            except ValueError:
                warn ("Invalid hex value for " + name)
                raise
        elif 'int' in config.attrib:
            self.value = int(self.config.attrib['int'])
        elif 'hex' in config.attrib:
            self.value = int(self.config.attrib['hex'], 16)
        elif 'bool' in config.attrib:
            attrib = self.config.attrib['bool'].lower()
            if attrib == "true":
                self.value = True
            elif attrib == "false":
                self.value = False
            else:
                self.value = None
        else:
            raise Exception ("No value set for const '" + name + "'")

    def start (self):
        self.recvmethods['const'](self.value)

class branch (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

    def recv_data (self, data):
        for send_data in self.recvmethods:
            self.recvmethods[send_data] (data)

class dh (SPG_base):
    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)
        self.generator = None
        self.modulus   = None
        self.psec      = None

    def recv_generator (self, generator):
        self.generator = generator
        self.calculate_if_valid ()

    def recv_modulus (self, modulus):
        self.modulus = modulus
        self.calculate_if_valid ()

    def recv_psec (self, psec):
        self.psec = psec
        self.calculate_if_valid ()

class dhpub (dh):

    def calculate_if_valid (self):
        if self.generator and self.modulus and self.psec:
            self.recvmethods['pub'] (pow(self.generator, self.psec, self.modulus))

class dhsec (dh):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)
        self.pub = None

    def calculate_if_valid (self):
        if self.generator and self.modulus and self.pub and self.psec:
            # Checks as per NIST Special Publication 800-56A, rev 2
            # (1) 2 <= pub <= (modulus-1)
            # (2) 1 == pub^q mod modulus for q = (modulus-1)/2
            if 2 <= self.pub and self.pub <= self.modulus - 2:
                if pow (self.pub, (self.modulus - 1) // 2, self.modulus) == 1:
                    self.recvmethods['ssec'] (pow(self.pub, self.psec, self.modulus))

    def recv_pub (self, pub):
        self.pub = pub
        self.calculate_if_valid ()

class hmac (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.key = None
        self.msg = None

    def calculate_if_valid (self):

        if self.key and self.msg:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            self.recvmethods['auth'](hmac.digest())

    def recv_msg (self, msg):
        self.msg = bytes(msg)
        self.calculate_if_valid ()

    def recv_key (self, key):
        self.key = bytes(key)
        self.calculate_if_valid ()

class hmac_out (hmac):

    def calculate_if_valid (self):

        if self.key and self.msg:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            self.recvmethods['auth'](hmac.digest())
            self.recvmethods['msg'](self.msg)

class verify_hmac (hmac):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.auth = None

    def calculate_if_valid (self):

        if self.key and self.msg and self.auth:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            self.recvmethods['result'](hmac.digest() == self.auth)

    def recv_auth (self, auth):
        self.key = auth
        self.calculate_if_valid ()

class verify_hmac_out (verify_hmac):

    def calculate_if_valid (self):

        if self.key and self.msg and self.auth:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            self.recvmethods['result'](hmac.digest() == self.auth)
            self.recvmethods['msg'](self.msg)

class __sig_base (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.pubkey = None
        self.msg    = None

    def recv_msg (self, msg):

        self.msg = int.from_bytes (msg, byteorder='big')

    def recv_pubkey (self, pubkey):

        (p, pubkey) = decode_mpi (pubkey)
        (q, pubkey) = decode_mpi (pubkey)
        (g, pubkey) = decode_mpi (pubkey)
        (y, pubkey) = decode_mpi (pubkey)
        self.pubkey = DSA.construct ((y, g, p, q))

class sign (__sig_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.privkey = None
        self.rand    = None

    def sign_if_valid (self):
        if self.privkey and self.pubkey and self.msg and self.rand:
            key = DSA.construct ((self.pubkey.y, self.pubkey.g, self.pubkey.p, self.pubkey.q, self.privkey))
            self.recvmethods['auth'](key.sign (self.msg, self.rand))

    def recv_privkey (self, privkey):
        self.privkey = int.from_bytes (privkey, byteorder='big')

    def recv_msg (self, msg):
        super().recv_msg (msg)
        self.sign_if_valid ()

    def recv_pubkey (self, pubkey):
        super().recv_pubkey (pubkey)
        self.sign_if_valid ()

    def recv_rand (self, rand):
        self.rand = int.from_bytes(rand, byteorder='big')
        self.sign_if_valid ()

class verify_sig (__sig_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.auth = None

    def verify_if_valid (self):

        if self.pubkey and self.auth and self.msg:
            result = 'True' if self.pubkey.verify (self.msg, self.auth) else 'False'
            self.recvmethods['result'](result.encode())

    def recv_msg (self, msg):
        super().recv_msg (msg)
        self.verify_if_valid ()

    def recv_pubkey (self, pubkey):
        super().recv_pubkey (pubkey)
        self.verify_if_valid ()

    def recv_auth (self, auth):

        siglen = int(len(auth)/2)
        r = int.from_bytes(auth[0:siglen], byteorder='big')
        s = int.from_bytes(auth[siglen:], byteorder='big')
        self.auth = (r, s)
        self.verify_if_valid()

class hash (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods, needconfig=True)

        if not 'algo' in config.attrib:
            raise Exception ("No hash algorithm configured")

        algo = config.attrib['algo']
        if algo == "SHA":
            self.hash = SHA.new ()
        elif algo == "SHA256":
            self.hash = SHA256.new ()

    def recv_data (self, data):
        self.hash.update (data)
        self.recvmethods['hash'](self.hash.digest())

class guard (SPG_base):

    def __init__ (self, name, config, recvmethods):
        super().__init__ (name, config, recvmethods)

        self.cond = None
        self.data = None

    def recv_data (self, data):
        self.data = data
        if self.cond:
            self.recvmethods['data'](self.data)

    def recv_cond (self, cond):
        self.cond = cond
        if self.data:
            self.recvmethods['data'](self.data)

class release (SPG_base):

    def recv_data (self, data):
        self.recvmethods['data'](data)
