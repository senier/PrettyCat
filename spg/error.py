quiet = False

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

class MissingOutgoingEdges (Exception):
    def __init__ (self, name, edges):
        Exception.__init__(self, "Node '" + name + "' has missing outgoing edges: " + str(edges))

class ExcessOutgoingEdges (Exception):
    def __init__ (self, name, edges):
        Exception.__init__(self, "Node '" + name + "' has excess outgoing edges: " + str(edges))

class MissingAndExcessOutgoingEdges (Exception):
    def __init__ (self, name, missing, excess):
        Exception.__init__(self, "Node '" + name + "' has missing outgoing edges " + str(missing) + " and excess edges " + str(excess))

class MissingIncomingEdges (Exception):
    def __init__ (self, name, edges):
        Exception.__init__(self, "Node '" + name + "' has missing incoming edges: " + str(edges))

class ExcessIncomingEdges (Exception):
    def __init__ (self, name, edges):
        Exception.__init__(self, "Node '" + name + "' has excess incoming edges: " + str(edges))

class MissingAndExcessIncomingEdges (Exception):
    def __init__ (self, name, missing, excess):
        Exception.__init__(self, "Node '" + name + "' has missing incoming edges " + str(missing) + " and excess edges " + str(excess))

class PrimitiveDuplicateRule (Exception):
    def __init__ (self, name):
        Exception.__init__(self, "Duplicate rule for '" + name + "'")

class PrimitiveMissingRule (Exception):
    def __init__ (self, name):
        Exception.__init__(self, "Primitive '" + name + "' has not rule")

class PrimitiveInvalidRule (Exception):
    def __init__ (self, kind, name):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") has contradicting rule")

class PrimitiveMissing (Exception):
    def __init__ (self, kind, name):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") not implemented")

class PrimitiveInvalidAttributes (Exception):
    def __init__ (self, name, kind, text):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") has invalid attributes: " + text)

class InconsistentRule(Exception):
    def __init__ (self, rule, text):
        Exception.__init__(self, "Rule '" + rule + "': " + text)

class PrimitiveNotImplemented (Exception):
    def __init__ (self, kind):
        Exception.__init__(self, "No implementation for primitive '" + kind + "'")

class InternalError (Exception): pass

