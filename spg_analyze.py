#!/usr/bin/python

import xml.etree.ElementTree as ET
import networkx as nx
import sys

sec_e   = set(())
sec_c   = set(("c"))
sec_i   = set(("i"))
sec_ci  = set(("c", "i"))
sec_cif = set(("c", "i", "f"))

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

def set_inputs (G, node, argmap):

    # retrieve output security sets from out edges
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']
        if not darg in argmap:
            raise Exception, "Node '" + current + "' receives invalid input parameter '" + darg + "' from '" + parent + "'"
        data['sec'] = argmap[darg]
        del argmap[darg]

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
        sec = set(("c", "i", "f"))
        for (parent, child, data) in G.out_edges(nbunch=start, data=True):
            sec &= data['sec']
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            data['sec'] = sec

    elif kind == "guard":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'data': out['data'], 'cond': sec_i})

    elif kind == "sign":
        out = get_outputs (G, start, ['auth'])
        set_inputs (G, start, {'skey': sec_ci, 'pkey': sec_i, 'msg': out['auth'] | sec_i})

    elif kind == "hmac":
        out = get_outputs (G, start, ['auth'])
        set_inputs (G, start, {'key': sec_ci, 'msg': out['auth'] | sec_i})

    elif kind == "verify_hmac" or kind == "verify_sig":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'key': sec_ci, 'auth': sec_e, 'msg': out['msg'] - sec_i})

    elif kind == "encrypt":
        out = get_outputs (G, start, ['ciphertext'])
        set_inputs (G, start, {'key': sec_ci, 'iv': sec_i, 'plaintext': out['ciphertext'] | sec_c})

    elif kind == "decrypt":
        out = get_outputs (G, start, ['plaintext'])
        key = sec_ci if sec_c <= out['plaintext'] else sec_e
        set_inputs (G, start, {'key': key, 'iv': sec_i, 'ciphertext': out['plaintext'] - sec_c})

    elif kind == "hash":
        out = get_outputs (G, start, ['hash'])
        set_inputs (G, start, {'msg': out['hash'] | sec_c})

    elif kind == "verify_hash":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'hash': sec_e, 'msg': out['msg']})

    elif kind == "dhsec":
        out = get_outputs (G, start, ['ssec'])
        set_inputs (G, start, {'pub': sec_e, 'psec': sec_ci})

    elif kind == "dhpub":
        out = get_outputs (G, start, ['pub'])
        set_inputs (G, start, {'gen': sec_i, 'psec': sec_ci})

    elif kind == "rand":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'len': sec_i})

    elif kind == "const" or kind == "receive":
        pass

    else:
        raise Exeception, "Unknown kind: " + str(kind)

    for (parent, current, data) in G.in_edges(nbunch=start, data=True):
        analyze(G, parent);

def convert_setset (attrib):
    result = set()
    if "confidentiality" in attrib and attrib["confidentiality"] == "True":
        result |= set(("c"))
    if "integrity" in attrib and attrib["integrity"] == "True":
        result |= set(("i"))
    if "freshness" in attrib and attrib["freshness"] == "True":
        result |= set(("f"))
    return result

try:
    root = ET.parse(sys.argv[1]).getroot()
except IOError as e:
    print("Error opening XML file: " + str(e))
    sys.exit(1)

G = nx.MultiDiGraph();

# read in graph
for child in root:

    sec = None

    if child.tag == "send" or child.tag == "receiver":
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

# Find some node to start with
for i in G.nodes():
    if not G.out_edges(nbunch=i):
        analyze(G, i)

for (parent, child, data) in G.edges(data=True):
    data['label']     = fmtsec(data['sec'])
    data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
    data['headlabel'] = data['darg']

nx.drawing.nx_pydot.write_dot(G, sys.argv[2]);
