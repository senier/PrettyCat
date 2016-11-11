import sys
import libspg

class output_check_fixed (libspg.SPG_base):

    def __init__ (self, name, config, recvmethods):

        super().__init__ (name, config, recvmethods, needconfig = True)

        if not 'result' in config.attrib:
            raise Exception ("No result set for output check")

        self.value = str(config.attrib['result'])

    def recv_data (self, data):
        if str(data) != self.value:
            libspg.exitval = 1
