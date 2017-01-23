import socket
import threading

from potr import AESCTR, Counter

from Crypto.Hash import HMAC, SHA, SHA256
from Crypto.PublicKey import DSA
from Crypto import Random

exitval = 0
quiet = 0

class NotImplemented (Exception):
    def __init__ (self, text):
        Exception.__init__(self, "Not implemented: " + text)

class InvalidConfiguration (Exception):
    def __init__ (self, text):
        Exception.__init__(self, "Invalid configuration: " + text)

class InvalidArgument (Exception):
    def __init__ (self, text):
        Exception.__init__(self, "Invalid argument: " + text)

class InvalidData (Exception):
    def __init__ (self, text):
        Exception.__init__(self, text)

def warn (message):
    print ("[1m[35mWARNING: [2m" + str(message) + "[0m")

def info (message):
    if not quiet:
        print ("[1m[34mINFO: [2m" + str(message) + "[0m")

def err (message):
    print ("[1m[31mERROR: [2m" + str(message) + "[0m")

def decode_data (data):
    length = int.from_bytes (data[0:4], byteorder='big')
    if length > len(data) - 4:
        raise InvalidData ("Data length header exceeds buffer size: hdr=" + str(length) + " len=" + str(len(data)))
    return (data[4:4+length], data[4+length:])

def decode_mpi (mpi):
    (data, remainder) = decode_data (mpi)
    return (int.from_bytes (data, byteorder='big'), remainder)

def encode_data (data):
    length = len(data)
    return length.to_bytes (4, byteorder='big') + data

def encode_mpi (num):
    length = (num.bit_length() // 8) + 1
    return length.to_bytes (4, byteorder='big') + num.to_bytes (length, byteorder='big')

def decode_pubkey (pubkey):

    keytype = pubkey[0:2]
    if keytype != b'\x00\x00':
        raise InvalidData ("Key has invalid type: " + str(keytype))

    (p, pubkey) = decode_mpi (pubkey[2:])
    (q, pubkey) = decode_mpi (pubkey)
    (g, pubkey) = decode_mpi (pubkey)
    (y, pubkey) = decode_mpi (pubkey)
    return (p, q, g, y, pubkey)

def dump (data):
    if not type(data) is bytes and not type(data) is bytearray:
        return str(data)
    hexstring = ''
    for item in data: hexstring += '%02x' % int(item)
    return "[" + str(len(data)) + "] " + str(hexstring)

class SPG_base:

    def __init__ (self, name, config, attributes, needconfig = False):

        if needconfig and config == None:
            raise Exception ("Missing config for " + name)

        self.name       = name
        self.config     = config
        self.attributes = attributes
        self.arguments  = attributes['inputs']

        self.__sendmethods = None

    # def recvmethods (self, recvmethods):
    #     self.recv = recvmethods

    def set_sendmethods (self, sendmethods):
        self.__sendmethods = sendmethods

    def sendmethods (self):
        return self.__sendmethods

    def send (self, argument, data):
        info ("S: " + self.name + "/" + argument)
        info ("      " + dump(data))
        self.__sendmethods[argument] (data)

    def start (self): pass
    def join (self): pass
    def setDaemon (self, dummy): pass

class SPG_thread (threading.Thread):

    def __init__ (self, name, config, attributes, needconfig = False):

        if needconfig and config == None:
            raise Exception ("Missing config for " + name)

        super().__init__ ()
        self.name       = name
        self.config     = config
        self.attributes = attributes
        self.arguments  = attributes['inputs']

    # def recvmethods (self, recvmethods):
    #     self.recv = recvmethods

    def set_sendmethods (self, sendmethods):
        self.__sendmethods = sendmethods

    def sendmethods (self):
        return self.__sendmethods

    def send (self, argument, data):
        info ("T: " + self.name + "/" + argument)
        info ("      " + dump(data))
        self.__sendmethods[argument] (data)

class SPG_xform (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.args = {}
        for a in self.arguments:
            self.args["recv_" + a] = None

    def __update_arg (self, name, value):
        self.args[name] = value
        if not {k: v for k, v in self.args.items() if not v != None}:
            self.finish()

    def __getattr__ (self, name):
        if not name in [("recv_" + a) for a in self.arguments]:
            raise InvalidArgument (name)
        return lambda value: (self.__update_arg(name, value))

class comp (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)
        self.data1 = None
        self.data2 = None

    def recv_data1 (self, data):

        if self.data2 == None:
            self.data1 = data
        else:
            result = 'True' if self.data2 == data else 'False'
            #print ("Comp: " + str(self.data2) + " vs. " + str(data))
            self.send ('result', result.encode())
            self.data1 = None
            self.data2 = None

    def recv_data2 (self, data):

        if self.data1 == None:
            self.data2 = data
        else:
            result = 'True' if self.data1 == data else 'False'
            #print ("Comp: " + str(self.data1) + " vs. " + str(data))
            self.send ('result', result.encode())
            self.data1 = None
            self.data2 = None

class counter_mode (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

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

def pad (data, blocksize):
    return data + (blocksize - len (data) % blocksize) * b'0'

class encrypt (counter_mode):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.pt          = None
        self.key_changed = False

    def recv_ctr (self, ctr):

        # IV must only be set once
        if self.ctr != None: return

        self.ctr = Counter(ctr)
        self.encrypt_if_valid ()

    def recv_key (self, key):
        if len(key) != self.keylen:
            raise Exception ("Keylen is " + str(len(key)*8) + " while " + str(self.keylen*8) + " is configured for " + self.name)

        self.key = bytes(key)
        self.key_changed = True
        self.encrypt_if_valid ()

    def recv_plaintext (self, pt):

        self.pt = bytes(pt)
        self.encrypt_if_valid ()

    def send_ctr(self, ctr): pass

    def encrypt_if_valid (self):

        if self.ctr != None and self.key != None and self.pt != None: 

            if not self.key_changed:
                self.ctr.inc()

            self.send_ctr(self.ctr.prefix_bytes())
            self.send ('ciphertext', AESCTR(self.key, self.ctr).encrypt(self.pt))

            self.pt = None
            self.key_changed = False

class encrypt_ctr (encrypt):

    def send_ctr(self, ctr):
        self.send ('ctr', ctr)

class decrypt (counter_mode):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)
        self.ct = None

    def recv_ctr (self, ctr):

        self.ctr = Counter(ctr)
        self.decrypt_if_valid ()

    def recv_key (self, key):
        if len(key) != self.keylen:
            raise Exception ("Keylen != " + str(self.keylen))

        self.key = bytes(key)
        self.decrypt_if_valid ()

    def recv_ciphertext (self, ct):

        self.ct = bytes(ct)
        self.decrypt_if_valid()

    def decrypt_if_valid (self):

        if self.ctr != None and self.key != None and self.ct != None:

            self.send ('plaintext', AESCTR(self.key, self.ctr).decrypt(self.ct))
            self.ct = None

class env (SPG_thread):

    def __init__ (self, name, config, attributes, needconfig = True):

        if not 'mode' in config.attrib:
            raise InvalidConfiguration ("'mode' not configured for env")

        super().__init__ (name, config, attributes, needconfig)
        self.port        = int(config.attrib['port'])
        self.host        = config.attrib['host'] if 'host' in config.attrib else "127.0.0.1"
        self.bufsize     = config.attrib['bufsize'] if 'bufsize' in config.attrib else 1024
        self.mode        = config.attrib['mode']
        self.conn        = None
        self.ready       = threading.Semaphore(0)

    def recv_data (self, data):

        data_len = len(data)
        self.ready.acquire()
        self.conn.send (data_len.to_bytes (2, byteorder='big') + data + b'\0')
        self.ready.release()

    def __forward (self):

        info ("FORWARD: " + self.name)
        header = self.conn.recv (self.bufsize)

        # End of transmission
        if len(header) == 0:
            info ("FORWARD: " + self.name + " EOT")
            return False

        if len(header) < 2:
            warn ("Invalid data received (too short: " + str(len(header)) + ")")
            return True

        length = int.from_bytes (header[0:2], byteorder='big')
        print (str(header))
        warn ("FORWARD: " + self.name + ", length (" + str(length) + ")")

        data = header[2:]
        length -= len(data)

        while length > 0:
            data += self.conn.recv (length)
            length -= len(data)

        self.send ('data', data)
        return True
    
    def run (self):

        if not 'data' in self.sendmethods():
            raise InvalidArgument (self.name + " needs missing output argument 'data'")

        if self.mode == 'server':
            self.socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind ((self.host, self.port))
            self.socket.listen (1)

            print ("   Waiting: TCP for " + self.name + " on " + self.host + ": " + str(self.port))
            (self.conn, addr) = self.socket.accept()
            print ("   Connect from: " + str(addr[0]) + ":" + str(addr[1]))

        elif self.mode == 'client':

            self.conn = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            self.conn.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.conn.connect ((self.host, self.port))
            print ("   Connected to: " + self.host + ":" + str(self.port))

        self.ready.release()

        # Forward all messages until channel is closed
        while self.__forward (): pass

class const (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes, needconfig = True)

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
        elif 'uint8' in config.attrib:
            self.value = int(self.config.attrib['uint8']).to_bytes(1, byteorder='big')
        elif 'uint16' in config.attrib:
            self.value = int(self.config.attrib['uint16']).to_bytes(2, byteorder='big')
        elif 'uint32' in config.attrib:
            self.value = int(self.config.attrib['uint32']).to_bytes(4, byteorder='big')
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
        self.send ('const', self.value)

class branch (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

    def recv_data (self, data):
        for send_data in self.sendmethods():
            self.send (send_data, data)

class dh (SPG_base):
    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)
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
        if self.generator != None and self.modulus != None and self.psec != None:
            try:
                self.send ('pub', pow(self.generator, int.from_bytes (self.psec, byteorder='big'), self.modulus))
            except TypeError:
                err ("Type error in " + self.name)
                raise
            finally:
                self.psec = None

class dhsec (dh):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)
        self.pub = None

    def calculate_if_valid (self):
        if self.generator != None and self.modulus != None and self.pub != None and self.psec != None:
            # Checks as per NIST Special Publication 800-56A, rev 2
            # (1) 2 <= pub <= (modulus-1)
            # (2) 1 == pub^q mod modulus for q = (modulus-1)/2
            if 2 <= self.pub and self.pub <= self.modulus - 2:
                if pow (self.pub, (self.modulus - 1) // 2, self.modulus) == 1:
                    psec = int.from_bytes (self.psec, byteorder='big')
                    self.send ('ssec', pow(self.pub, psec, self.modulus))
            self.psec = None

    def recv_pub (self, pub):
        self.pub = pub
        self.calculate_if_valid ()

class hmac (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.key = None
        self.msg = None

    def calculate_if_valid (self):

        if self.key != None and self.msg != None:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            self.send ('auth', hmac.digest())
            self.msg = None

    def recv_msg (self, msg):
        self.msg = bytes(msg)
        self.calculate_if_valid ()

    def recv_key (self, key):
        self.key = bytes(key)
        self.calculate_if_valid ()

class hmac_out (hmac):

    def calculate_if_valid (self):

        if self.key != None and self.msg != None:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            self.send ('auth', hmac.digest())
            self.send ('msg', self.msg)
            self.msg = None

class verify_hmac (hmac):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.auth = None

    def calculate_if_valid (self):

        if self.key != None and self.msg != None and self.auth != None:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            result = 'True' if hmac.digest() == self.auth else 'False'
            self.send ('result', result.encode())
            self.msg  = None
            self.auth = None

    def recv_auth (self, auth):
        self.auth = auth
        self.calculate_if_valid ()

class verify_hmac_out (verify_hmac):

    def calculate_if_valid (self):

        if self.key != None and self.msg != None and self.auth != None:
            hmac = HMAC.new (self.key, msg=self.msg, digestmod=SHA256.new())
            if hmac.digest() == self.auth:
                self.send ('msg', self.msg)
            self.msg  = None
            self.auth = None

class __sig_base (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.pubkey = None
        self.msg    = None

    def recv_msg (self, msg):

        self.msg = int.from_bytes (msg, byteorder='big')

    def recv_pubkey (self, pubkey):

        (p, q, g, y, dummy) = decode_pubkey (pubkey)
        if not p or not q or not g or not y:
            raise Exception ("Invalid pubkey")

        self.pubkey = DSA.construct ((y, g, p, q))

class sign (__sig_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.privkey = None
        self.pubkey  = None
        self.rand    = None

    def sign_if_valid (self):
        if self.privkey != None and self.pubkey and self.msg != None and self.rand != None:
            key = DSA.construct ((self.pubkey.y, self.pubkey.g, self.pubkey.p, self.pubkey.q, self.privkey))

            K = int.from_bytes (self.rand, byteorder='big')
            if K < 2 or K > key.q:
                warn ("Invalid K")
                return

            (intr, ints) = key.sign (self.msg, self.rand)
            r = intr.to_bytes(20, byteorder='big')
            s = ints.to_bytes(20, byteorder='big')
            self.send ('auth', r + s)
            self.msg  = None
            self.rand = None

    def recv_privkey (self, privkey):
        self.privkey = int.from_bytes (privkey, byteorder='big')
        self.sign_if_valid ()

    def recv_msg (self, msg):
        super().recv_msg (msg)
        self.sign_if_valid ()

    def recv_pubkey (self, pubkey):
        super().recv_pubkey (pubkey)
        self.sign_if_valid ()

    def recv_rand (self, rand):
        self.rand = bytes(rand)
        self.sign_if_valid ()

class verify_sig (__sig_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.auth = None

    def verify_if_valid (self):
        if self.pubkey and self.auth != None and self.msg != None:
            result = 'True' if self.pubkey.verify (self.msg, self.auth) else 'False'
            self.send ('result', result.encode())
            self.auth = None
            self.msg  = None

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
        self.verify_if_valid ()

class hash (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes, needconfig=True)

        if not 'algo' in config.attrib:
            raise Exception ("No hash algorithm configured")

        algo = config.attrib['algo']
        if algo == "SHA":
            self.hashalgo = SHA
        elif algo == "SHA256":
            self.hashalgo = SHA256

    def recv_data (self, data):
        h = self.hashalgo.new(data)
        self.send ('hash', h.digest())

class guard (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.cond = None
        self.data = None

    def recv_data (self, data):
        self.data = data
        if self.cond:
            self.send ('data', self.data)
            self.cond = None
            self.data = None

    def recv_cond (self, cond):
        self.cond = cond
        if self.data:
            self.send ('data', self.data)
            self.cond = None
            self.data = None

class release (SPG_base):

    def recv_data (self, data):
        self.send ('data', data)

class latch (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        self.data = None

    def recv_data (self, data):
        if self.data == None:
            self.data = data
            self.send ('trigger', 'True'.encode())
        self.send ('data', self.data)

class rng (SPG_base):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

    def recv_len (self, length):
        self.send ('data', Random.get_random_bytes(int(length)//8))

class verify_commit (hash):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)
        self.hash = None

    def recv_hash (self, data):
        self.hash = data

    def recv_data (self, data):
        if self.hash != None:
            h = self.hashalgo.new(data)
            if h.digest() == self.hash:
                self.send ('data', data)
            self.hash = None
            self.data = None

class xform_concat (SPG_xform):

    def __init__ (self, name, config, attributes):
        super().__init__ (name, config, attributes)

        if len(self.attributes['outputs']) != 1 or not 'result' in self.attributes['outputs']:
            raise InvalidConfiguration ("Single flow with source argument 'result' expected for " + self.name)

    def finish (self):
        result = bytearray()
        for a in self.attributes['arguments']:
            result.extend(bytearray(self.args["recv_" + a]))
        self.send ('result', result)

class xform_prefix (SPG_xform):
    def finish (self):
        if len(self.args) != 1:
            raise Exception ("Prefix must only have one input argument")

        if not 'length_in_bits' in self.config.attrib:
            raise Exception ("No length configured for " + self.name)

        length_in_bits = int(self.config.attrib['length_in_bits'])
        if length_in_bits % 8 != 0:
            raise Exception ("Length is not divisible by 8: " + str(length_in_bits))
        length = length_in_bits//8;

        for send_data in self.sendmethods():
            self.send (send_data, bytes(self.args['recv_data'])[0:length])

class xform_mpi (SPG_base):

    def recv_data (self, data):
        for output in self.attributes['outputs']:
            self.send (output, encode_mpi (data))

class xform_data (SPG_base):

    def recv_data (self, data):
        length = len(data)
        for output in self.attributes['outputs']:
            self.send (output, length.to_bytes (4, byteorder='big') + data)

class xform_split (SPG_xform):

    def finish (self):

        if len(self.args) != 1:
            raise Exception ("Split expects only one input")

        data   = self.args['recv_data']
        length = len(data)

        if length % 2 != 0:
            raise Exception ("Split expects even number of input bytes")

        middle = length // 2
        self.send ('left', data[0:middle])
        self.send ('right', data[middle:])

class xform_unmpi (SPG_base):

    def recv_data (self, data):
        (mpi, unused) = decode_mpi (data)
        self.send ('data', mpi)

class xform_serialize (SPG_base):

    def recv_data (self, data):
        self.send ('data', encode_data (data))

class env_print (SPG_base):

    def recv_data (self, data):
        print (self.name + ": " + str (data))
