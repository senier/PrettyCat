from Crypto.Cipher import AES
import sys
from libspg import info, warn, err, SPG_base, SPG_xform
import libspg
import time

class env_static (libspg.SPG_thread):

    def __init__ (self, name, config, arguments):

        super().__init__ (name, config, arguments)

        if not 'hexbytes' in config.attrib:
            raise Exception ("No hexbytes configured")

        self.value = bytearray.fromhex(config.attrib['hexbytes'])

    def run (self):
        self.send ('data', self.value)

class env_list (libspg.SPG_thread):

    def __init__ (self, name, config, arguments):

        super().__init__ (name, config, arguments)

        if not 'data' in config.attrib:
            raise Exception ("No input data configured")

        self.delay = 0
        if 'delay' in config.attrib:
            self.delay = float(config.attrib['delay'])

        self.values = [x.strip() for x in config.attrib['data'].split(',')]

    def run (self):

        time.sleep(self.delay)
        for v in self.values:
            self.send ('data', v.encode())

class env_check_fixed (SPG_base):

    def __init__ (self, name, config, arguments):

        super().__init__ (name, config, arguments, needconfig = True)

        if 'result' in config.attrib:
            self.values = [x.strip().encode() for x in config.attrib['result'].split(',')]
        elif 'hexresult' in config.attrib:
            self.values = [bytearray.fromhex (x.strip()) for x in config.attrib['hexresult'].split(',')]
        else:
            raise Exception ("No result set for output check")

        libspg.exitval = 1

    def recv_data (self, data):
        value = self.values.pop()
        if data == value:
            libspg.exitval = 0
        else:
            info ("[" + self.name + "] Output '" + str(data) + "' did not match expected value '" + str(value) + "'")

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
