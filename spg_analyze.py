#!/usr/bin/python

import xml.etree.ElementTree as ET
import networkx as nx
import sys

def sec_empty():
    return set(())

def sec_f():
    return set(("f"))

def sec_c():
    return set(("c"))

def sec_i():
    return set(("i"))

def sec_a():
    return set(("a"))

def sec_ci():
    return set(("c", "i"))

def sec_ca():
    return set(("c", "a"))

def sec_cia():
    return set(("c", "i", "a"))

def sec_cif():
    return set(("c", "i", "f"))

def sec_max():
    return set(("f", "c", "i", "a"))

def fmtsec(sec):
    if not sec:
        return "&empty;"
    else:
        result = ""
        if "c" in sec:
            result += "c"
        if "i" in sec:
            if result:
                result += ","
            result += "i"
        if "f" in sec:
            if result:
                result += ","
            result += "f"
    return "{" + result + "}";

def get_outputs(G, node, arglist):
    result = {}

    # retrieve output security sets from out edges
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        sarg = data['sarg']
        if not sarg in arglist:
            raise Exception, "Node '" + node + "' has invalid output parameter '" + sarg + "'"
        result[sarg] = data['sec']

    # is something missing
    for arg in arglist:
        if not arg in result.keys():
            raise Exception, "Argument '" + arg + "' not found for node '" + node + "'"

    return result

def set_outputs (G, node, argmap):

    seen = {}

    # retrieve output security sets from out edges
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        sarg = data['sarg']
        if not sarg in argmap:
            raise Exception, "Node '" + current + "' passes invalid output parameter '" + sarg + "' to '" + child + "'"
        if argmap[sarg] > data['sec']:
            print "ERROR: Node '" + current + "' has input '" + data['sarg'] + \
                "' which exceeds security guarantees (" + fmtsec(argmap[sarg]) + " > " + fmtsec(data['sec']) + ")"
            data['color'] = "red"
        data['sec'] = argmap[sarg]
        seen[sarg] = True

    for s in seen:
        del argmap[s]

    if argmap:
        raise Exception, "Node '" + node + "' has no arguments " + list(argmap.keys())

def get_inputs(G, node, arglist):
    result = {}

    # retrieve security sets from in edges
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']
        if not darg in arglist:
            raise Exception, "Node '" + node + "' has invalid input parameter '" + darg + "'"
        if darg in result:
            raise Exception, "Duplicate input for node '" + node + "', argument '" + darg + "'"
        result[darg] = data['sec']

    # is something missing
    for arg in arglist:
        if not arg in result.keys():
            raise Exception, "Argument '" + arg + "' not found for node '" + node + "'"

    return result

def set_inputs (G, node, argmap):

    seen = {}

    # retrieve input security sets from in edges
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']
        if darg in seen:
            raise Exception, "Node '" + current + "' receives duplicate input parameter '" + darg + "'"
        if not darg in argmap:
            raise Exception, "Node '" + current + "' receives invalid input parameter '" + darg + "' from '" + parent + "'"
        data['sec'] = argmap[darg]
        del argmap[darg]
        seen[darg] = True

    if argmap:
        raise Exception, "Node '" + node + "' has no arguments " + list(argmap.keys())

def analyze(G, start):

    # Get node attribute set
    node = G.node[start]

    # Only continue if node was not processed yet
    if "processed" in node:
        return

    # Only continue if all children have be processed already
    for (parent, child, data) in G.out_edges(nbunch=start, data=True):
        if not 'processed' in G.node[child]:
            return

    # Mark current node as processed
    node["processed"] = True;

    kind = node['kind']

    if kind == "send":
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            G.node[parent]['sec'] = node['sec']

    elif kind == "xform":
        sec = sec_cif()
        for (parent, child, data) in G.out_edges(nbunch=start, data=True):
            sec &= data['sec']
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            data['sec'] = sec

    elif kind == "guard":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'data': out['data'], 'cond': sec_empty()})

    elif kind == "sign":
        out = get_outputs (G, start, ['auth'])
        set_inputs (G, start, {'skey': sec_cif(), 'pkey': sec_i(), 'msg': out['auth'] | sec_a()})

    elif kind == "verify_sig":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'pkey': sec_i(), 'auth': sec_empty(), 'msg': out['msg'] - sec_a()})

    elif kind == "hmac":
        out = get_outputs (G, start, ['auth'])
        set_inputs (G, start, {'key': sec_ci(), 'msg': out['auth'] | sec_i()})

    elif kind == "verify_hmac":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'key': sec_ci(), 'auth': sec_empty(), 'msg': out['msg'] - sec_i()})

    elif kind == "encrypt":
        out = get_outputs (G, start, ['ciphertext'])
        set_inputs (G, start, {'key': sec_ci(), 'iv': sec_i(), 'plaintext': out['ciphertext'] | sec_c()})

    elif kind == "decrypt":
        out = get_outputs (G, start, ['plaintext'])
        key = set(("c", "i")) if set(("c")) <= out['plaintext'] else set(())
        set_inputs (G, start, {'key': key, 'iv': set(("i")), 'ciphertext': out['plaintext'] - set(("c"))})

    elif kind == "hash":
        out = get_outputs (G, start, ['hash'])
        set_inputs (G, start, {'msg': out['hash'] | sec_c()})

    elif kind == "verify_hash":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'hash': sec_empty(), 'msg': out['msg']})

    elif kind == "dhsec":
        out = get_outputs (G, start, ['ssec'])
        set_inputs (G, start, {'pub': sec_empty(), 'psec': sec_empty()})

    elif kind == "dhpub":
        out = get_outputs (G, start, ['pub'])
        set_inputs (G, start, {'gen': sec_i(), 'psec': sec_cif()})

    elif kind == "rand":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'len': sec_i()})

    elif kind == "const" or kind == "receive":
        pass

    else:
        raise Exeception, "Unknown kind: " + str(kind)

    for (parent, current, data) in G.in_edges(nbunch=start, data=True):
        analyze(G, parent);

def convert_setset (attrib):
    result = sec_empty()
    if "confidentiality" in attrib and attrib["confidentiality"] == "True":
        result |= sec_c()
    if "integrity" in attrib and attrib["integrity"] == "True":
        result |= sec_i()
    if "freshness" in attrib and attrib["freshness"] == "True":
        result |= sec_f()
    return result

def forward_adjust (G, node):

    n = G.node[node]
    kind = n['kind']

    if kind == "receive":
        for (parent, current, data) in G.out_edges (nbunch=node, data=True):
            if n['sec'] > data['sec']:
                print "ERROR: Node '" + node + "' has input '" + data['sarg'] + \
                    "' which exceeds security guarantees (" + fmtsec(n['sec']) + " > " + fmtsec(data['sec']) + ")"
                data['color'] = "red"
            data['sec'] = n['sec']

    elif kind == "xform":
        sec = sec_empty()
        for (parent, current, data) in G.in_edges (nbunch=node, data=True):
            sec |= data['sec']
        for (parent, current, data) in G.out_edges (nbunch=node, data=True):
            if sec > data['sec']:
                print "ERROR: Node '" + node + "' has input '" + data['sarg'] + \
                    "' which exceeds security guarantees (" + fmtsec(sec) + " > " + fmtsec(data['sec']) + ")"
                data['color'] = "red"
            data['sec'] = sec

    elif kind == "decrypt":
        inputs = get_inputs (G, node, ['iv', 'key', 'ciphertext'])
        delta = set(("c")) if set(("c", "i")) <= inputs['key'] else set(())
        set_outputs (G, node, { 'plaintext': inputs['ciphertext'] | delta }) 

    elif kind == "encrypt":
        inputs = get_inputs (G, node, ['iv', 'key', 'plaintext'])
        delta = sec_c() if sec_ci() <= inputs['key'] else sec_empty()
        set_outputs (G, node, { 'ciphertext': inputs['plaintext'] - delta })

    elif kind == "sign":
        inputs = get_inputs (G, node, ['pkey', 'skey', 'msg'])
        set_outputs (G, node, { 'auth': inputs['msg'] - sec_a()})

    elif kind == "verify_sig":
        inputs = get_inputs (G, node, ['pkey', 'auth', 'msg'])
        set_outputs (G, node, { 'msg': inputs['msg'] | sec_a()})

    elif kind == "hmac":
        inputs = get_inputs (G, node, ['key', 'msg'])
        set_outputs (G, node, { 'auth': inputs['msg'] - sec_i()})

    elif kind == "verify_hmac":
        inputs = get_inputs (G, node, ['key', 'auth', 'msg'])
        set_outputs (G, node, { 'msg': inputs['msg'] | sec_i()})

    elif kind == "hash":
        inputs = get_inputs (G, node, ['msg'])
        set_outputs (G, node, { 'msg': inputs['msg'] - sec_c()})

    elif kind == "verify_hash":
        inputs = get_inputs (G, node, ['hash', 'msg'])
        set_outputs (G, node, { 'msg': inputs['msg']})

    elif kind == "guard":
        inputs = get_inputs (G, node, ['data', 'cond'])
        set_outputs (G, node, { 'data': inputs['data'] | inputs['cond']})

    elif kind == "send":
        sec = G.node[node]['sec']
        for (parent, current, data) in G.in_edges (nbunch=node, data=True):
            if data['sec'] > sec:
                print "ERROR: Node '" + node + "' has input '" + data['sarg'] + \
                    "' which exceeds security guarantees (" + fmtsec(data['sec']) + " > " + fmtsec(sec) + ")"
                G.node[node]['color'] = "red"

    elif kind == "dhpub" or kind == "dhsec":
        pass

    else:
        raise Exception, "Unhandled node kind: " + kind

def analyze_forward (G, start, edgelist):
    forward_adjust (G, start)
    for (parent, child) in edgelist:
        forward_adjust (G, child)

try:
    root = ET.parse(sys.argv[1]).getroot()
except IOError as e:
    print("Error opening XML file: " + str(e))
    sys.exit(1)

G = nx.MultiDiGraph();

# read in graph
for child in root:

    sec = None

    if child.tag == "send" or child.tag == "receive":
        sec = convert_setset(child.attrib)

    label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"

    G.add_node \
        (child.attrib["id"], \
         kind=child.tag, \
         sec=sec, \
         label = label, \
         shape = "rectangle", \
         width = "2.5", \
         height = "0.6")

    for element in child.findall('flow'):
        source = element.attrib['sarg'] if 'sarg' in element.attrib else None;
        darg   = element.attrib['darg']
        G.add_edge (child.attrib['id'], element.attrib['sink'], darg = darg, sarg = source, sec = set(()), labelangle = "180", labelfontsize = "8")

nx.drawing.nx_pydot.write_dot(G, sys.argv[2]);

# Analyze all source nodes
for node in G.nodes():
    if not G.out_edges(nbunch=node):
        analyze(G, node)

# Backward analysis
for node in G.nodes():
    if not G.in_edges(nbunch=node) and G.node[node]['kind'] != 'const':
        analyze_forward(G, node, nx.bfs_edges (G, node))

for (parent, child, data) in G.edges(data=True):
    data['label']     = fmtsec(data['sec'])
    data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
    data['headlabel'] = data['darg']

nx.drawing.nx_pydot.write_dot(G, sys.argv[2]);
