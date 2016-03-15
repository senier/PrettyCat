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

    kind = node['kind']

    # Calculate sec set for note itself
    if kind == "send":
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            G.node[parent]['sec'] = node['sec']

    elif kind == "xform":
        sec = out_sec_intersection (G, start)
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            G.node[parent]['sec'] = sec

    elif kind == "arg":
        if not 'sec' in node:
            node['sec'] = set(())

    elif kind == "sign":
        (parent, auth) = G.out_edges(nbunch=start)[0]
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "skey":
                G.node[parent]['sec'] = set(("c", "i"))
            if G.node[parent]['darg'] == "pkey":
                G.node[parent]['sec'] = set(("i"))
            elif G.node[parent]['darg'] == "msg":
                G.node[parent]['sec'] = G.node[auth]['sec'] | set(("i"))

    elif kind == "hmac":
        (parent, auth) = G.out_edges(nbunch=start)[0]
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "key":
                G.node[parent]['sec'] = set(("c", "i"))
            elif G.node[parent]['darg'] == "msg":
                G.node[parent]['sec'] = G.node[auth]['sec'] | set(("i"))

    elif kind == "encrypt":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "key":
                G.node[parent]['sec'] = set(("c", "i"))
            elif G.node[parent]['darg'] == "iv":
                G.node[parent]['sec'] = G.node[child]['sec'] | set(("i"))

    elif kind == "verify_hmac" or kind == "verify_sig":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "key" or G.node[parent]['darg'] == "pkey":
                G.node[parent]['sec'] = set(("c", "i"))
            elif G.node[parent]['darg'] == "auth":
                G.node[parent]['sec'] = set(())
            elif G.node[parent]['darg'] == "msg":
                G.node[parent]['sec'] = G.node[child]['sec'] - set(("i"))

    elif kind == "decrypt":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "iv":
                G.node[parent]['sec'] = set(("i"))
            if G.node[parent]['darg'] == "key":
                G.node[parent]['sec'] = set(("c", "i"))
            elif G.node[parent]['darg'] == "ciphertext":
                G.node[parent]['sec'] = G.node[child]['sec'] - set(("c"))

    elif kind == "guard":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "cond":
                G.node[parent]['sec'] = set(("i"))
            elif G.node[parent]['darg'] == "data":
                G.node[parent]['sec'] = G.node[child]['sec']

    elif kind == "verify_hash":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "hash":
                G.node[parent]['sec'] = set(())
            elif G.node[parent]['darg'] == "msg":
                G.node[parent]['sec'] = G.node[child]['sec']

    elif kind == "dhsec":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "pub":
                G.node[parent]['sec'] = set(())
            if G.node[parent]['darg'] == "sec":
                G.node[parent]['sec'] = set(("c", "i"))

    elif kind == "dhpub":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "gen":
                G.node[parent]['sec'] = set(("i"))
            if G.node[parent]['darg'] == "sec":
                G.node[parent]['sec'] = set(("c", "i"))

    elif kind == "rand":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "len":
                G.node[parent]['sec'] = set(("i"))

    elif kind == "hash":
        for (parent, child) in G.in_edges(nbunch=start):
            if G.node[parent]['darg'] == "msg":
                G.node[parent]['sec'] = G.node[child]['sec'] | set(("c"))

    elif kind == "const":
        pass

    elif kind == "receive":
        pass

    else:
        print "Unknown kind: " + str(kind)

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
        sec |= G.node[child]['sec']
    return sec;

def out_sec_intersection (G, start):
    sec = set(("c", "i", "f"))
    for (parent, child, data) in G.out_edges(nbunch=start, data=True):
        sec &= G.node[child]['sec']
    return sec;

try:
    root = ET.parse(sys.argv[1]).getroot()
except IOError as e:
    print("Error opening XML file: " + str(e))
    sys.exit(1)

G = nx.MultiDiGraph();

# read in graph
for child in root:

    sec = set(())

    if child.tag == "send":
        sec = convert_setset(child.attrib)

    # if child.tag == "receive" or child.tag == "send":
    #     sec['msg'] = convert_setset(child.attrib)
    # elif child.tag == "const":
    #     sec['const'] = None
    # elif child.tag == "xform":
    #     for arg in child.findall('arg'):
    #         sec[arg.attrib['name']] = None
    # elif child.tag == "rand":
    #     sec['len'] = set(("i"))
    # elif child.tag == "hash":
    #     sec['msg'] = None
    # elif child.tag == "verify_hash":
    #     sec['hash'] = set(())
    #     sec['msg']  = None
    # elif child.tag == "hmac":
    #     sec['key'] = set(("c", "i"))
    #     sec['msg']  = None
    # elif child.tag == "verify_hmac":
    #     sec['key']  = set(("c", "i"))
    #     sec['auth'] = set(())
    #     sec['msg']  = None
    # elif child.tag == "sign":
    #     sec['skey'] = set(("c", "i"))
    #     sec['pkey'] = set(("i"))
    #     sec['msg']  = None
    # elif child.tag == "verify_sig":
    #     sec['pkey'] = set(("i"))
    #     sec['auth'] = set(())
    #     sec['msg']  = None
    # elif child.tag == "dhpub":
    #     sec['gen'] = set(("i"))
    #     sec['sec'] = set(("c", "i"))
    # elif child.tag == "dhsec":
    #     sec['pub'] = set(())
    #     sec['sec'] = set(("c", "i"))
    # elif child.tag == "encrypt":
    #     sec['iv']  = set(("f", "i"))
    #     sec['key'] = set(("c", "i"))
    #     sec['plaintext'] = None
    # elif child.tag == "decrypt":
    #     sec['iv']  = set(("i"))
    #     sec['key'] = set(("c", "i"))
    #     sec['ciphertext'] = None
    # elif child.tag == "guard":
    #     sec['data'] = None
    #     sec['cond'] = set(("i"))
    # else:
    #     raise Exception, "Unknown tag: " + child.tag

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
        if "sarg" in element.attrib:
            source = element.attrib["sarg"]
        else:
            source = None
        darg  = element.attrib["darg"]
        argid = element.attrib["sink"] + "/" + darg
        G.add_node (argid, kind="arg", darg=darg, sarg=source, label = darg, shape = "circle")
        G.add_edge (child.attrib["id"], argid)
        G.add_edge (argid, element.attrib["sink"])

nx.drawing.nx_pydot.write_dot(G, sys.argv[2]);

# Find some node to start with
for i in G.nodes():
    if not G.out_edges(nbunch=i):
        analyze(G, i)

for i in G.nodes():
    if G.node[i]['kind'] == "arg":
        if "sec" in G.node[i]:
            G.node[i]['label'] += "\n" + fmtsec(G.node[i]['sec'])

nx.drawing.nx_pydot.write_dot(G, sys.argv[2]);
