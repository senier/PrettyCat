import sys
from libspg import info, warn, err, SPG_base
import libspg

class output_check_fixed (SPG_base):

    def __init__ (self, name, config, recvmethods):

        super().__init__ (name, config, recvmethods, needconfig = True)

        if not 'result' in config.attrib:
            raise Exception ("No result set for output check")

        self.value = str(config.attrib['result'])

    def recv_data (self, data):
        if str(data) != self.value:
            warn ("Output '" + str(data) + "' did not match expected value '" + str(self.value) + "'")
            libspg.exitval = 1
