#!/usr/bin/python

# TODO:
#   Check for nodes with unassigned arguments
#   Check for incompatible sec sets between argument source/dest

import xml.etree.ElementTree as ET
import networkx as nx
import sys

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

    # Calculate sec set for note itself
    kind = node["kind"]

    if kind == "xform" or kind == "const":
        sec = out_sec_intersection (G, start)
        for s in node['sec']:
            node['sec'][s] = sec
    elif kind == "hash":
        sec = out_sec_union (G, start)
        node['sec']['msg'] = sec | set(("c"))
    elif kind == "verify_hmac" or kind == "verify_sig":
        sec = out_sec_union (G, start)
        node['sec']['msg'] = sec - set(("i"))
    elif kind == "hmac" or kind == "sign":
        sec = out_sec_union (G, start)
        node['sec']['msg'] = sec | set(("i"))
    elif kind == "encrypt":
        sec = out_sec_union (G, start)
        node['sec']['plaintext'] = sec | set(("c"))
    elif kind == "decrypt":
        sec = out_sec_union (G, start)
        node['sec']['ciphertext'] = sec - set(("c"))
    elif kind == "verify_hash":
        sec = out_sec_union (G, start)
        node['sec']['msg'] = sec
    elif kind == "send" or kind == "receive" or kind == "rand" or kind == "dhpub" or kind == "dhsec":
        sec = set(("c", "i"))
        pass
    else:
        raise Exception, "Unknown kind: " + str(kind)

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

def out_sec_union (G, start):
    sec = set(())
    for (parent, child, data) in G.out_edges(nbunch=start, data=True):
        dest = data['dest']
        try:
            sec = sec | G.node[child]['sec'][dest]
        except (TypeError, KeyError):
            print "Node '" + child + "/" + str(dest) + "' has no sec set"
            sys.exit(1)
    return sec;

def out_sec_intersection (G, start):
    sec = set(("c", "i", "f"))
    for (parent, child, data) in G.out_edges(nbunch=start, data=True):
        dest = data['dest']
        try:
            sec = sec & G.node[child]['sec'][dest]
        except (TypeError, KeyError):
            print "Node '" + child + "/" + str(dest) + "' has no sec set"
            sys.exit(1)
    return sec;

try:
    root = ET.parse(sys.argv[1]).getroot()
except IOError as e:
    print("Error opening XML file: " + str(e))
    sys.exit(1)

G = nx.MultiDiGraph();

# read in graph
for child in root:

    sec = {}

    if child.tag == "receive" or child.tag == "send":
        sec['msg'] = convert_setset(child.attrib)
    elif child.tag == "const":
        sec['const'] = None
    elif child.tag == "xform":
        for arg in child.findall('arg'):
            sec[arg.attrib['name']] = None
    elif child.tag == "rand":
        sec['len'] = set(("i"))
    elif child.tag == "hash":
        sec['msg'] = None
    elif child.tag == "verify_hash":
        sec['hash'] = set(())
        sec['msg']  = None
    elif child.tag == "hmac":
        sec['key'] = set(("c", "i"))
        sec['msg']  = None
    elif child.tag == "verify_hmac":
        sec['key']  = set(("c", "i"))
        sec['auth'] = set(())
        sec['msg']  = None
    elif child.tag == "sign":
        sec['skey'] = set(("c", "i"))
        sec['pkey'] = set(("i"))
        sec['msg']  = None
    elif child.tag == "verify_sig":
        sec['pkey'] = set(("i"))
        sec['auth'] = set(())
        sec['msg']  = None
    elif child.tag == "dhpub":
        sec['gen'] = set(("i"))
        sec['sec'] = set(("c", "i"))
    elif child.tag == "dhsec":
        sec['pub'] = set(())
        sec['sec'] = set(("c", "i"))
    elif child.tag == "encrypt":
        sec['iv']  = set(("f", "i"))
        sec['key'] = set(("c", "i"))
        sec['plaintext'] = None
    elif child.tag == "decrypt":
        sec['iv']  = set(("i"))
        sec['key'] = set(("c", "i"))
        sec['ciphertext'] = None
    else:
        raise Exception, "Unknown tag: " + child.tag

    label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"

    G.add_node \
        (child.attrib["id"], \
         kind=child.tag, \
         sec=sec, \
         label = label, \
         shape = "rectangle", \
         width = "2.5", \
         height = "0.8")

    for element in child.findall('flow'):

        if child.tag == "const":
            source = None
        else:
            source = element.attrib["sarg"]

        darg = element.attrib["darg"]

        if source == None:
            slabel = ""
        else:
            slabel = source

        G.add_edge \
            (child.attrib["id"], \
             element.attrib["sink"], \
             source = source, \
             dest = darg,
             labelfontsize = 8,
             labelangle = 180,
             taillabel = slabel,
             headlabel = darg)

# Find some node to start with
for i in G.nodes():
    if not G.out_edges(nbunch=i):
        analyze(G, i)

# create all edge labels
for (parent, child, data) in G.out_edges(data=True):
    try:
        sec = G.node[child]['sec'][data['dest']]
    except KeyError:
        print "Node '" + str(child) + "' does not have paramter '" + data['dest'] + "' as referenced by node '" + str(parent) + "'"
        raise
    data['label'] = fmtsec(sec)

nx.drawing.nx_pydot.write_dot(G, sys.argv[2]);
