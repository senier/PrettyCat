#!/usr/bin/python

#import pydot
import xml.etree.ElementTree as ET
import networkx as nx
import sys

def fmtsec(sec):
    if not sec:
        return "\emptysec"
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
    return "\{" + result + "\}";

def analyze(G, start=None):

    # Find some node to start with
    if start is None:
        s = G.nodes()[0];
    else:
        s = start

    print("Analyzing " + str(s))

    # Get node attribute set
    n = G.node[s]

    # Only continue it node was not processed yet
    if n and "processed" in n:
        print "......Done already"
        return
    print "......Continue"

    # Mark current node as processed
    n["processed"] = True;

    print ("   Handling parents");
    for i in G.in_edges(nbunch=s):
        print str("      " + i[0]) + " => " + str(s)
        analyze(G, i[0]);

    # Calculate sec set for note itself
    kind = n["kind"]
    if kind == "const" or kind == "receive":
        sec = n["sec"]
    elif kind == "rand":
        sec = set(("c", "i", "f"))
    elif kind == "encrypt":
        sec = n["sec"] - set(("c"))
    elif kind == "decrypt":
        sec = n["sec"] & set(("c"))
    elif kind == "xform":
        sec = set()
        for i in G.in_edges(nbunch=s):
            sec = sec & G[i[0]][i[1]][0]["sec"]
    elif kind == "verify_hash":
        sec = n["sec"] & set(("i"))
    else:
        raise Exception, kind

    print "   Handling children"
    for o in G.out_edges(nbunch=s):
        print "      Handling children: " + str(s) + " => " + str(o) + " sec: " + fmtsec(sec)
        G[o[0]][o[1]][0]["sec"] = sec
        analyze(G, o[1]);

try:
    root = ET.parse("otr.spg").getroot()
except IOError as e:
    print("Error opening XML file: " + str(e))
    sys.exit()

G = nx.MultiDiGraph();

# read in graph
for child in root:
    sec = set()

    if "integrity" in child.attrib.keys():
        sec.add("i");
    if "confidentiality" in child.attrib.keys():
        sec.add("c");
    if "freshness" in child.attrib.keys():
        sec.add("f");

    G.add_node(child.attrib["id"], kind=child.tag, sec=sec)

    for element in child:
        G.add_edge \
            (child.attrib["id"], \
             element.attrib["sink"], \
             source = element.tag, \
             dest = element.attrib["arg"])

analyze(G)

# create all edge labels
for edge in G.edges():
    attr = G[edge[0]][edge[1]][0]
    if 'sec' in attr:
        sec = fmtsec(attr['sec'])
    else:
        sec = "?"
    G[edge[0]][edge[1]][0]["label"] = "(" + attr['source'] + "," + attr['dest'] + "," + sec + ")"

# create all node labels
for node in G.nodes(1):
    n = node[1]
    sec = n['sec']
    if n['kind'] == "const":
        label = n['value'] + "^" + fmtsec(sec)
    if n['kind'] == "receive" or n['kind'] == "send":
        label = n['kind'] + "_{" + node[0] + "}^" + fmtsec(sec)
    else:
        label = n['kind'] + "_{" + node[0] + "}"
    n['label'] = label

nx.drawing.nx_pydot.write_dot(G,"test.dot");
