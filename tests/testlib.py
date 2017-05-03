from Crypto.Cipher import AES
import sys
from libspg import info, warn, err, SPG_base, SPG_xform, hexstring
import libspg
import time
from subprocess import call

class env_static (libspg.SPG_thread):

    def __init__ (self, name, arguments):
        super().__init__ (name, arguments)

        if not 'hexbytes' in self.config.attrib:
            raise Exception ("No hexbytes configured")

        self.value = bytearray.fromhex(self.config.attrib['hexbytes'])

    def run (self):
        self.send ('data', self.value)

class env_list (libspg.SPG_thread):

    def __init__ (self, name, arguments):
        super().__init__ (name, arguments)

        if not 'data' in self.config.attrib:
            raise Exception ("No input data configured")

        self.delay = 0
        if 'delay' in self.config.attrib:
            self.delay = float(self.config.attrib['delay'])

        self.values = [x.strip() for x in self.config.attrib['data'].split(',')]

    def run (self):

        time.sleep(self.delay)
        for v in self.values:
            self.send ('data', v.encode())

class env_check_fixed (SPG_base):

    def __init__ (self, name, arguments):
        super().__init__ (name, arguments, needconfig = True)

        if 'result' in self.config.attrib:
            self.values = [x.strip().encode() for x in self.config.attrib['result'].split(',')]
        elif 'hexresult' in self.config.attrib:
            self.values = [bytearray.fromhex (x.strip()) for x in self.config.attrib['hexresult'].split(',')]
        elif 'intresult' in self.config.attrib:
            self.values = [int(x.strip()) for x in self.config.attrib['intresult'].split(',')]
        else:
            raise Exception ("No result set for output check")

        libspg.exitval = 1

    def recv_data (self, data):
        value = self.values.pop()
        if data == value:
            libspg.exitval = 0
        else:
            err ("[" + self.name + "] Output '" + str(data) + "' did not match expected value '" + str(value) + "'")

class xform_get_random (SPG_base):

    def start (self):
        self.request_length = 528
        self.send ('len', self.request_length)

    def recv_random (self, data):
        recvlen = len(data)
        if (8 * recvlen != self.request_length):
            warn ("Received length (" + str(recvlen) + \
                ") did not match requested length (" + str(self.request_length) + ")")
            libspg.exitval = 1

class xform_aes_pad (SPG_base):

    def recv_data (self, data):
        self.send ('data', libspg.pad (data, AES.block_size))

class xform_order (SPG_xform):

    def finish (self):
        self.send ('hash', self.args['recv_hash'])
        self.send ('data', self.args['recv_data'])

class env_verify_sig_ext (SPG_xform, libspg.MPI):

    def finish (self):

        libspg.exitval = 0
        datfile = 'tmp-dat.dat'
        sigfile = 'tmp-sig.dat'
        pubfile = 'tmp-pub.dat'

        # dump message
        with open(datfile, 'w') as f:
            f.write ('(data(flags raw)(value #%s#))' % hexstring(self.args['recv_msg']))

        # dump authenticator
        with open(sigfile, 'w') as f:
            auth = self.args['recv_auth']
            f.write ('(sig-val(dsa(r#%s#)(s#%s#)))' % (hexstring(auth[0:20]), hexstring(auth[20:])))

        # dump pubkey
        with open(pubfile, 'w') as f:
            pub = self.args['recv_pubkey']
            (p, rest) = self.decode_data (pub[2:])
            (q, rest) = self.decode_data (rest)
            (g, rest) = self.decode_data (rest)
            (y, rest) = self.decode_data (rest)
            f.write ("(public-key (dsa (p #%s#)(q #%s#)(g #%s#)(y #%s#)))" % (hexstring(p), hexstring(q), hexstring(g), hexstring(y)))

        args = ['tools/dsavrfy', pubfile, datfile, sigfile]
        rv = call (args)
        if rv != 0:
            libspg.exitval = 1
