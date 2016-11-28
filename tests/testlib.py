import sys
from libspg import info, warn, err, SPG_base
import libspg
import time

class input_list (libspg.SPG_thread):

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
            self.send['data'](v.encode())

class output_check_fixed (SPG_base):

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
            warn ("[" + self.name + "] Output '" + str(data) + "' did not match expected value '" + str(value) + "'")

class xform_get_random (SPG_base):

    def start (self):
        self.request_length = 597
        self.send['len'](self.request_length)

    def recv_random (self, data):
        recvlen = len(data)
        if (recvlen != self.request_length):
            libspg.exitval = 1
