#!/usr/bin/env python3

import sys
import xml.etree.ElementTree as ET
import argparse
import subprocess
import os

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx

class Args:

    def __init__ (self):
        raise Exception ("Abstract class")

    def setup (self, name, solver, mode):
        self._name   = name
        self._solver = solver
        self._mode   = mode

    def add_guarantee (self, name): 
        self.__dict__.update (**{name: Guarantees (self._name + "_" + name, self._solver, self._mode)})

    def model (self, model):
        for name in self.__dict__:
            if not name.startswith("_"):
                self.__dict__[name].model (model)

    def guarantees (self):
        return { k: v for k, v in self.__dict__.items() if not k.startswith("_") }

class Args_In (Args):
    def __init__ (self, name, solver):
        Args.setup (self, name, solver, "in")

class Args_Out (Args):
    def __init__ (self, name, solver):
        Args.setup (self, name, solver, "out")

class SPG_Solver:

    def __init__ (self, solver, assert_db):
        self.solver = solver
        self.assert_db = assert_db
        self.solver.set(unsat_core=True)

    def assert_and_track (self, condition, name):
        key = "a_" + name
        self.assert_db[key] = condition
        self.solver.assert_and_track (condition, key)

    def solver (self):
        print ("FIXME: Create proper solver interface")
        return self.solver

    def condition_by_name (self, name):
        return simplify(self.assert_db[str(name)])

class Guarantees:

    def __init__ (self, node, solver, mode):
        self.node   = node
        self.solver = solver

        self.unsat_c = False
        self.unsat_i = False

        self.base = self.node + "_" + mode
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

    def model (self, model):
        self.model = model

    def assert_x (self, var, value, tag):
        if value != None: 
            self.solver.assert_and_track (var == value, self.base + "_" + tag)

    def assert_c (self, value):
        self.assert_x (self.c, value, "c")

    def assert_i (self, value):
        self.assert_x (self.i, value, "i")

    def val_c (self):
        return str(self.model.evaluate (self.c)) == "True"

    def val_i (self):
        return str(self.model.evaluate (self.i)) == "True"

    def check_unsat (self, constraints):
        self.unsat_c = self.base + "_c" in constraints
        self.unsat_i = self.base + "_i" in constraints

    def unsat_c (self):
        return unsat_c

    def unsat_i (self):
        return unsat_i

class Primitive:
    """
    An "abstract" class implementing generic methods for a Primitive
    """

    def __init__ (self, G, name, solver):
        raise Exception ("Abstract")

    def setup (self, G, name, solver):
        self.i      = Args_In (name, solver)
        self.o      = Args_Out (name, solver)
        self.name   = name
        self.node   = G.node[name]
        self.solver = solver

        for (parent, current, data) in G.in_edges (nbunch=name, data=True):
            self.i.add_guarantee (data['darg'])

        for (current, child, data) in G.out_edges (nbunch=name, data=True):
            self.o.add_guarantee (data['sarg'])

    def assert_and_track (self, cond, desc):
        """Track an condition tagging it with the primitive name and a description"""
        self.solver.assert_and_track (cond, self.name + "_" + desc)

    def model (self, model):
        """Set a model for input and output guarantees"""
        self.i.model (model)
        self.o.model (model)

class Primitive_xform (Primitive):
    """
    The xform primitive
    
    This mainly identifies sources and sinks and sets the fixed
    guarantees according to the XML definition.
    """

    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

        # Guarantees explicitly set in send/recv xforms in the XML
        g = self.node['guarantees']

        if sink:
            # send
            for (name, guarantee) in self.i.guarantees().items():
               guarantee.assert_c (g['c'])
               guarantee.assert_i (g['i'])
        elif source:
            # receive
            for (name, guarantee) in self.o.guarantees().items():
               guarantee.assert_c (g['c'])
               guarantee.assert_i (g['i'])

        # Parameter
        #   All input interfaces
        # Confidentiality guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   The confidentiality of an input parameter is not influenced by an
        #   output parameters or other input parameters as the data flow is
        #   directed. Hence, the demand for confidentiality guarantees is
        #   solely determined by the source of an input interface
        # Assertion:
        #   None

        # Parameter
        #   All input interfaces
        # Integrity guarantee can be dropped if:
        #   No output interface demands integrity
        # Reason:
        #   Input from a source lacking integrity guarantees can influence
        #   any output of an xform in undetermined ways. Hence, integrity
        #   guarantees cannot be maintained for any output interface.
        # Assertion:
        #   in_i -> OR out_i
        out_i = []
        for (name, out_g) in self.o.guarantees().items():
            out_i.append (out_g.i)

        if out_i:
            for (in_name, in_g) in self.i.guarantees().items():
                self.assert_and_track (Implies (in_g.i, Or (out_i)), in_name + "_" + "_out_i")

        # Parameter
        #   All output interfaces
        # Confidentiality guarantee can be dropped if:
        #   No input interface demands confidentiality
        # Reason:
        #   Input from a source demanding confidentiality guarantees can
        #   influence any output of an xform in undetermined ways. Hence,
        #   confidentiality must be guaranteed by all output interfaces.
        # Assertion:
        #   out_c -> IN_c
        in_c = []
        for (name, in_g) in self.i.guarantees().items():
            in_c.append (in_g.c)

        if in_c:
            for (name, out_g) in self.o.guarantees().items():
                cond = Implies (Or (in_c), out_g.c)
                print (cond)
                self.assert_and_track (cond, name + "_in_c")
        

class Primitive_const (Primitive):
    """
    The const primivive
    """

    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

        # Const can only drop integrity or confidentiality guarantees if the
        # receiving primitives do not require them.  This is handled in the
        # channel assertions (output guarantees of parent are equivalent to
        # respective input guarantees of child)

        # Just check that const output parameter exists
        assert (self.o.const)

class Primitive_rng (Primitive):
    """
    Primitive for a true (hardware) random number generator

    This RNG is not seeded. It has an input parameter len, determining how
    many bits we request from it.
    """

    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

        # Parameter
        #   len_in
        # Confidentiality guarantee can be dropped if:
        #   Confidentiality is required for data_out
        # Reason:
        #   Attacker could derive len_in from the length of data_out otherwise.
        # Assertion:
        #   Either len_in_c is true or data_out_c is true.
        self.assert_and_track (Or (self.i.len.c, self.o.data.c), "len_in_c")

        # Parameter
        #   len_in
        # Integrity guarantees can be dropped if:
        #   No integrity guarantee is demanded by data_out
        # Reason:
        #   Otherwise, an attacker could change or reorder len_in creating
        #   data_out messages of chosen, invalid length.
        # Assertion:
        #   len_in_i -> data_out_i
        self.assert_and_track (Implies (self.i.len.i, self.o.data.i), "len_in_i")

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   Confidentiality is not required for len_in
        # Reason:
        #   Attacker could derive len_in from the length of data_out otherwise.
        # Assertion:
        #   data_out_c -> len_in_c
        self.assert_and_track (Implies (self.o.data.c, self.i.len.c), "output_data_c")

        # Parameter
        #   data_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   FIXME: Why?
        # Assertion:
        #   -/-
        assert(self.o.data.i)

class Primitive_dhpub (Primitive):

    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

        # Parameter
        #   psec_in
        # Confidentiality guarantee can be dropped if:
        #   The pub_in interfaces (g^y in DH terms) of the corresponding dhsec
        #   primitive demands confidentiality or the result of that dhsec
        #   operation (g^xy) does not demand confidentiality.
        # Reason:
        #   With knowledge of g^y and psec_in (x in DH terms) an attacker can
        #   calculate the shared secret g^y^x
        # Assertion:
        #   FIXME: This requires inter-component reasoning. Interesting, but I
        #   feel a stabbing pain in my head without that already. We should
        #   think about that later and demand confidentiality for psec_in
        #   unconditionally for now.
        self.assert_and_track (self.i.psec.c, "psec_in_c")

        # Parameter
        #   psec_in
        # Integrity guarantees can be dropped if:
        #   same as above.
        # Reason:
        #   If an attacker can choose psec_in (x in DH terms) and knows g^y,
        #   she can calculate the shared secret g^yx
        # Assertion:
        #   See above.
        self.assert_and_track (self.i.psec.i, "psec_in_i")

        # Parameter
        #   pub_out
        # Confidentiality guarantee can be dropped if:
        #   psec_in demands confidentiality and integrity
        # Reason:
        #   Being able to transmit g^x over an non-confidential channel is the
        #   sole purpose of the DH key exchange, given that x has
        #   confidentiality and integrity guarantees
        # Assertion:
        #   pub_out_c or not (psec_in_c and psec_in_i)
        self.assert_and_track (Or (self.o.pub.c, Not (And (self.i.psec.c, self.i.psec.i))), "pub_out_c")

        # Parameter
        #   pub_out
        # Integrity guarantees can be dropped if:
        #   N/A
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None
        assert (self.o.pub.i)
        # FIXME: But the integrity of pub_out determines whether an attacker
        # can mount a MITM. So this somehow has an influence on the shared
        # secret ssec produced in dhsec. Is it integrity, authenticity or what?

class Primitive_dhsec (Primitive):
    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

        # Parameter
        #   psec_in
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality guarantees are demanded for ssec (g^xy in DH
        #   terms)
        # Reason:
        #   With knowledge of pub (g^y in DH terms) and psec_in (x in DH terms)
        #   an attacker can calculate the shared secret g^yx
        # Assertion:
        #   psec_in -> ssec_out
        self.assert_and_track (Implies (self.i.psec.c, self.o.ssec.c), "psec_in_c")

        # Parameter
        #   psec_in
        # Integrity guarantees can be dropped if:
        #   same as above.
        # Reason:
        #   If an attacker can choose psec_in (x in DH terms) and knows g^y,
        #   she can calculate the shared secret g^yx
        # Assertion:
        #   See above.
        self.assert_and_track (Implies (self.i.psec.i, self.o.ssec.c), "psec_in_i")

        # Parameter
        #   pub_in
        # Confidentiality guarantee can be dropped if:
        #   psec_in demands confidentiality and integrity
        # Reason:
        #   Being able to transmit g^x over an non-confidential channel is the
        #   sole purpose of the DH key exchange, given that x has
        #   confidentiality and integrity guarantees
        # Assertion:
        #   pub_in_c or not (psec_in_c and psec_in_i)
        self.assert_and_track (Or (self.i.pub.c, Not (And (self.i.psec.c, self.i.psec.i))), "pub_in_c")

        # Parameter
        #   pub_in
        # Integrity guarantees can be dropped if:
        #   N/A
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None
        assert (self.i.pub.i)
        # FIXME: But the integrity of pub_out determines whether an attacker
        # can mount a MITM. So this somehow has an influence on the shared
        # secret ssec produced in dhsec. Is it integrity, authenticity or what?

        # Parameter
        #   ssec_out
        # Confidentiality guarantee can be dropped if:
        #   Neiter psec_in nor pub_in demand confidentiality guarantees
        # Reason:
        #   With the knowledge of psec_in (y in DH terms) and pub (g^x in DH
        #   terms) an attacker can calculate the shared secret g^yx.
        #   FIXME: We do not require psec_in to be integrity protected, as an
        #   attacker would not be able to derive ssec with a chosen psec in
        #   *this* step. The situation is different if an attacker can chose
        #   the psec used for dhpub (but this is covered in an own rule)
        # Assertion:
        #   psec_in AND pub_in
        self.assert_and_track (And (self.i.psec.c, self.i.pub.c), "ssec_out_c")

        # Parameter
        #   ssec_out
        # Integrity guarantees can be dropped if:
        #   N/A
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None
        assert (self.o.ssec.i)

class Primitive_encrypt (Primitive):
    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

class Primitive_decrypt (Primitive):
    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

class Primitive_hash (Primitive):
    def __init__ (self, G, name, solver, sink, source):
        super ().setup (G, name, solver)

def parse_bool (attrib, name):
    if not name in attrib:
        return None
    if attrib[name] == "True":
        return True
    if attrib[name] == "False":
        return False
    raise Exception ("Invalid boolean value for '" + name + "'")

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
                labelfontsize = "8", \
                labelfontcolor="red", \
                arrowhead="vee", \
                labelfontname="Sans-Serif", \
                labeljust="r", \
                penwidth="3")

    # Initialize all objects
    for node in G.node:
        objname = "Primitive_" + G.node[node]['kind']
        sink   = G.in_edges (nbunch=node) and not G.out_edges (nbunch=node)
        source = G.out_edges (nbunch=node) and not G.in_edges (nbunch=node)
        G.node[node]['p'] = globals()[objname](G, node, solver, sink, source)

    # Establish src -> sink relation
    for (parent, child, data) in G.edges (data=True):
        p = G.node[parent]['p']
        c = G.node[child]['p']
        sarg = data['sarg']
        darg = data['darg']

        name = parent + "_" + sarg + "__" + child + "_" + darg + "_channel_"
        solver.assert_and_track (p.o.guarantees()[sarg].c == c.i.guarantees()[darg].c, name + "c")
        solver.assert_and_track (p.o.guarantees()[sarg].i == c.i.guarantees()[darg].i, name + "i")

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
            raise Exception ("Xform without edges")

    # add edge labels
    for (parent, child, data) in G.edges(data=True):

        # sarg guarantees of parent should are the same as darg guarantees of child
        darg = data['darg']
        sarg = data['sarg']

        data['xlabel']    = ""
        data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
        data['headlabel'] = data['darg']
        data['color']     = sec_color (G.node[parent]['p'].o.guarantees()[sarg])
    
    # add edge labels
    #for (parent, child, data) in G.edges(data=True):
    #    if 'extralabel' in data:
    #        data['xlabel'] += data['extralabel']
    #    if data['guarantees_src'].unsat_c:
    #        data['color'] = 'orange'
    #        data['xlabel'] += "\nIN/C"
    #    if data['guarantees_src'].unsat_i:
    #        data['color'] = 'orange'
    #        data['xlabel'] += "\nIN/I"
    #    if data['guarantees_sink'].unsat_c:
    #        data['color'] = 'orange'
    #        data['xlabel'] += "\nOUT/C"
    #    if data['guarantees_sink'].unsat_i:
    #        data['color'] = 'orange'
    #        data['xlabel'] += "\nOUT/I"
    
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
        pass
        #data['guarantees_src'].check_unsat (constraints)
        #data['guarantees_sink'].check_unsat (constraints)

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
        raise Exception ("Unhandled expression: " + str(uc))

def analyze_satisfiability (G, solver):

    s = solver.solver
    if s.check() == sat:
        print ("Solution found")
        for node in G.node:
            G.node[node]['p'].model (s.model())
    else:
        print ("No solution")
        unsat_core = []
        for p in s.unsat_core():
            unsat_core.append (solver.condition_by_name(p))
            print (str (p))
            print ("    " + str(solver.condition_by_name(p)))
        mark_unsat_core (G, simplify(And(unsat_core)))

def main(args):

    # validate input XML
    print (subprocess.check_output (["xmllint", "--noout", "--schema", "spg.xsd", args.input[0]]))

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
