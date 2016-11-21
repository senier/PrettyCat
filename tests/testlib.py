import sys
from libspg import info, warn, err, SPG_base
import libspg
import time
import threading

class input_list (threading.Thread):

    def __init__ (self, name, config, recvmethods):

        super().__init__ ()

        self.recvmethods = recvmethods
        self.name        = name
        self.config      = config

        if not 'data' in config.attrib:
            raise Exception ("No input data configured")

        self.delay = 0
        if 'delay' in config.attrib:
            self.delay = float(config.attrib['delay'])

        self.values = [x.strip() for x in config.attrib['data'].split(',')]

    def run (self):

        time.sleep(self.delay)
        for v in self.values:
            self.recvmethods['data'](v.encode())

class output_check_fixed (SPG_base):

    def __init__ (self, name, config, recvmethods):

        super().__init__ (name, config, recvmethods, needconfig = True)

        if not 'result' in config.attrib:
            raise Exception ("No result set for output check")

        self.values = [x.strip() for x in config.attrib['result'].split(',')]

    def recv_data (self, data):
        value = self.values.pop()
        if str(data) != value:
            warn ("Output '" + str(data) + "' did not match expected value '" + str(value) + "'")
            libspg.exitval = 1
