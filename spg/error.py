def warn (message):
    print ("[1m[35mWARNING: [2m" + str(message) + "[0m")

def info (message):
    if not quiet:
        print ("[1m[34mINFO: [2m" + str(message) + "[0m")

def err (message):
    print ("[1m[31mERROR: [2m" + str(message) + "[0m")

def hexstring (data):
    hexstring = ''
    for item in data: hexstring += '%02x' % int(item)
    return hexstring
    
def dump (data):
    if not type(data) is bytes and not type(data) is bytearray:
        return str(data)
    return "[" + str(len(data)) + "] " + str(hexstring(data))

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

class InternalError (Exception): pass
