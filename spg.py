#!/usr/bin/env python

import sys
import xml.etree.ElementTree as ET
import argparse
import subprocess
import os

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx

class SPG_Solver:

    def __init__ (self, solver, assert_db):
        self.solver = solver
        self.assert_db = assert_db
        self.solver.set(unsat_core=True)

    def assert_and_track (self, condition, name):
        self.assert_db[name] = condition
        self.solver.assert_and_track (condition, name)

    def solver (self):
        print "FIXME: Create proper solver interface"
        return self.solver

    def condition_by_name (self, name):
        return simplify(self.assert_db[str(name)])

class Guarantees:

    def __init__ ():
        raise IsAbstract

    def setup (self, node, solver, mode):
        self.node   = node
        self.solver = solver
        self.mode   = mode

        self.unsat_c = False
        self.unsat_i = False

        self.base = self.node + "_" + self.mode
        self.c = Bool(self.base + "_c")
        self.i = Bool(self.base + "_i")

    def base (self):
        return base

    def assert_condition (self, condition, desc):
        self.solver.assert_and_track (condition, self.base + "_" + desc)

    def c (self):
        return c

    def i (self):
        return i

    def o (self):
        return o

    def assert_x (self, var, value, tag):
        if value != None: 
            self.solver.assert_and_track (var == value, "assert_" + self.base + "_" + tag)

    def assert_c (self, value):
        self.assert_x (self.c, value, "c")

    def assert_i (self, value):
        self.assert_x (self.i, value, "i")

    def evaluate (self, model):
        self.val_c = str(model.evaluate (self.c)) == "True"
        self.val_i = str(model.evaluate (self.i)) == "True"

    def val_c (self):
        return val_c

    def val_i (self):
        return val_i

    def check_unsat (self, constraints):
        self.unsat_c = self.base + "_c" in constraints
        self.unsat_i = self.base + "_i" in constraints

    def unsat_c (self):
        return unsat_c

    def unsat_i (self):
        return unsat_i

class Guarantees_Src (Guarantees):

    def __init__(self, node, solver):
        Guarantees.setup (self, node, solver, "src")

    def assert_sink (self, sink):
        self.assert_condition (self.c == sink.c, "channel")
        self.assert_condition (self.i == sink.i, "channel")

class Guarantees_Sink (Guarantees):
    def __init__(self, node, solver):
        Guarantees.setup (self, node, solver, "sink")

def parse_bool (attrib, name):
    if not name in attrib:
        return None
    if attrib[name] == "True":
        return True
    if attrib[name] == "False":
        return False
    raise Exception, "Invalid boolean value for '" + name + "'"

def parse_guarantees (attribs):
    return {
        'c': parse_bool (attribs, 'confidentiality'),
        'i': parse_bool (attribs, 'integrity'),
    }

def parse_graph (inpath, solver):
    try:
        root = ET.parse(inpath).getroot()
    except IOError as e:
        print("Error opening XML file: " + str(e))
        sys.exit(1)
    
    G = nx.MultiDiGraph();
    
    # read in graph
    for child in root:
    
        label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"
        name  = child.attrib["id"]

        G.add_node \
            (name, \
             guarantees = parse_guarantees (child.attrib), \
             kind       = child.tag, \
             label      = label, \
             penwidth   = "1", \
             width      = "2.5", \
             height     = "0.6")
    
        for element in child.findall('flow'):
            sarg = element.attrib['sarg']
            darg = element.attrib['darg']
            G.add_edge (name, element.attrib['sink'], \
                sarg = sarg, \
                darg = darg, \
                guarantees_src  = Guarantees_Src (name + "_" + sarg, solver), \
                guarantees_sink = Guarantees_Sink (name + "_" + darg, solver), \
                labelfontsize = "8", \
                labelfontcolor="red", \
                arrowhead="vee", \
                labelfontname="Sans-Serif", \
                labeljust="r", \
                penwidth="3")

    # Assign send/receive guarantees to the respective interfaces
    for node in G.node:
        if G.node[node]['kind'] == "xform":
            guarantees = G.node[node]['guarantees']
            in_edges   = G.in_edges (nbunch=node, data=True)
            out_edges  = G.out_edges (nbunch=node, data=True)
            if in_edges and out_edges:
                # regular xform
                pass
            elif in_edges:
                # send
                print "Guarantees in send/" + node + ": " + str(guarantees)
                for (parent, child, data) in in_edges:
                    data['guarantees_sink'].assert_c (guarantees['c'])
                    data['guarantees_sink'].assert_i (guarantees['i'])
            elif out_edges:
                # receive
                print "Guarantees in recv/" + node + ": " + str(guarantees)
                for (parent, child, data) in out_edges:
                    data['guarantees_src'].assert_c (guarantees['c'])
                    data['guarantees_src'].assert_i (guarantees['i'])
            else:
                raise Exception, "XForm without edges"

    # Establish src -> sink relation
    for (parent, child, data) in G.edges (data=True):
        data['guarantees_src'].assert_sink (data['guarantees_sink'])

    return G

def sec_color(guarantee):

    if guarantee.unsat_c or guarantee.unsat_i:
        return "orange"

    c = guarantee.val_c
    i = guarantee.val_i

    if c and i:
        return "purple"
    elif not c and not i:
        return "black"
    elif c:
        return "red"
    elif i:
        return "blue"

def write_graph(G, title, out):

    for node in G.node:
        if G.in_edges (nbunch=node) and G.out_edges (nbunch=node):
            G.node[node]['shape'] = "rectangle"
        elif not G.in_edges(nbunch=node) or not G.out_edges (nbunch=node):
            G.node[node]['shape'] = "invhouse"
        else:
            raise Exception, "Xform without edges"

    # add edge labels
    for (parent, child, data) in G.edges(data=True):
        src_color  = sec_color (data['guarantees_src'])
        sink_color = sec_color (data['guarantees_src'])

        data['xlabel']    = ""
        data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
        data['headlabel'] = data['darg']
        data['color']   = "\"" + src_color + ":" + sink_color + "\""
        # data['fontcolor'] = sec_color(data['sec'])
    
    # add edge labels
    for (parent, child, data) in G.edges(data=True):
        if 'extralabel' in data:
            data['xlabel'] += data['extralabel']
        if data['guarantees_src'].unsat_c:
            data['color'] = 'orange'
            data['xlabel'] += "\nIN/C"
        if data['guarantees_src'].unsat_i:
            data['color'] = 'orange'
            data['xlabel'] += "\nIN/I"
        if data['guarantees_sink'].unsat_c:
            data['color'] = 'orange'
            data['xlabel'] += "\nOUT/C"
        if data['guarantees_sink'].unsat_i:
            data['color'] = 'orange'
            data['xlabel'] += "\nOUT/I"
    
    pd = nx.drawing.nx_pydot.to_pydot(G)
    pd.set_name("sdg")
    pd.set ("splines", "ortho")
    pd.set ("forcelabels", "true")
    pd.set ("nodesep", "0.5")
    pd.set ("pack", "true")
    pd.set ("size", "15.6,10.7")
    pd.set ("label", title)
    pd.set ("labelloc", "t")
    pd.write(out + ".dot")

    subprocess.check_output (["dot", "-T", "pdf", "-o", out, out + ".dot"])
    #os.remove (out + ".dot")

def positions (G):
    pd = nx.drawing.nx_pydot.to_pydot(G)
    pd.set ("splines", "ortho")
    pd.set ("forcelabels", "true")
    pd.set ("nodesep", "0.5")
    pd.set ("pack", "true")

    pos = nx.drawing.nx_pydot.pydot_layout(G, prog="dot")

    maxy = 0
    for k in pos:
        if maxy < pos[k][1]:
            maxy = pos[k][1]

    miny = maxy
    for k in pos:
        if miny > pos[k][1]:
            miny = pos[k][1]

    for k in pos:
        y = maxy - pos[k][1] + miny
        pos[k] = (pos[k][0], y)

    return pos

def mark_unsat_core (G, uc):
    constraints = {}
    mark_expression (G, constraints, uc)
    for (parent, child, data) in G.edges (data=True):
        data['guarantees_src'].check_unsat (constraints)
        data['guarantees_sink'].check_unsat (constraints)

def mark_expression (G, c, uc):
    if is_and (uc) or is_or (uc):
        for idx in range (0, uc.num_args()):
            mark_expression (G, c, uc.arg(idx))
    elif is_eq(uc):
        mark_expression (G, c, uc.arg(0))
        mark_expression (G, c, uc.arg(1))
    elif is_not(uc):
        mark_expression (G, c, uc.arg(0))
    elif is_const(uc):
        c[str(uc)] = True
    else:
        raise Exception, "Unhandled expression: " + str(uc)

def analyze_satisfiability (G, solver):

    s = solver.solver
    for node in nx.topological_sort (G):
        analyze_sat (G, node)

    print s

    if s.check() == sat:
        print "Solution found"
        m = s.model()
        for (parent, child, data) in G.in_edges(data=True):
            data['guarantees_sink'].evaluate (m)
        for (parent, child, data) in G.out_edges(data=True):
            data['guarantees_src'].evaluate (m)
    else:
        print "No solution"
        unsat_core = []
        for p in s.unsat_core():
            unsat_core.append (solver.condition_by_name(p))
        print And(unsat_core)
        mark_unsat_core (G, simplify(And(unsat_core)))

def meta_input_interface (G, node, if_in):
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        if data['darg'] == if_in:
            data['in_meta'] = True

def gen_c (G, node):
    for (parent, current, if_in) in G.in_edges (nbunch=node, data=True):
        if not 'in_meta' in if_in:
            for (current, child, if_out) in G.out_edges (nbunch=node, data=True):
                g_in = if_in['guarantees_sink']
                g_out = if_out['guarantees_src']
                g_in.assert_condition (Implies (g_in.c, g_out.c), if_in['darg'] + "_" + if_out['sarg'] + "_gen_c")

def gen_i (G, node):
    for (parent, current, if_in) in G.in_edges (nbunch=node, data=True):
        if not 'in_meta' in if_in:
            for (current, child, if_out) in G.out_edges (nbunch=node, data=True):
                g_in = if_in['guarantees_sink']
                g_out = if_out['guarantees_src']
                g_in.assert_condition (Implies (g_out.i, g_in.i), if_in['darg'] + "_" + if_out['sarg'] + "_gen_i")

def analyze_sat (G, node):

    n = G.node[node]
    kind = n['kind']

    if kind == "permute":
        #meta_input_interface (G, node, "order")
        #gen_c (G, node)
        #gen_i (G, node)
        pass

    elif kind == "xform":
        gen_c (G, node)
        gen_i (G, node)

    elif kind == "const":
        pass

    elif kind == "rng":
        # FIXME: Maybe a PRNG later?
        pass

    elif kind == "dhpub":
        pass

    elif kind == "dhsec":
        pass

    elif kind == "hash":
        pass

    elif kind == "encrypt":
        pass

    elif kind == "decrypt":
        pass

    elif kind == "hmac":
        pass

    elif kind == "verify_hmac":
        pass

    elif kind == "sign":
        pass

    elif kind == "verify_sig":
        pass

    elif kind == "release":
        pass

    elif kind == "guard":
        # meta_input_interface (G, node, "cond")
        # gen_c (G, node)
        # gen_i (G, node)
        # also: data_in^O, cond_in^O and data_in^I, cond_in^I
        pass

    elif kind == "counter":
        pass

    elif kind == "comp":
        #gen_i (G, node)
        pass

    else:
        raise Exception, "Unhandled primitive '" + kind + "'"

def main(args):

    # validate input XML
    print subprocess.check_output (["xmllint", "--noout", "--schema", "spg.xsd", args.input[0]]);

    assert_db = {}
    solver = SPG_Solver (Solver(), assert_db)

    G = parse_graph (args.input[0], solver)
    analyze_satisfiability(G, solver)
    write_graph(G, "Final", args.output[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPG Analyzer')
    parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
    parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');
    main(parser.parse_args ())
