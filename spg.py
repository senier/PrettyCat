#!/usr/bin/env python3

import time
import sys
import argparse
import subprocess
import os
import re
import pydot
import json

from libspg import warn, info, err
import libspg

from os.path import dirname
from io   import StringIO
from lxml import etree

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx
from networkx.readwrite import json_graph

# TODO: Check for excess output parameters in fixed primitives

schema_src = StringIO ('''<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">

<xs:complexType name="assertionElement">
    <xs:simpleContent>
        <xs:extension base="xs:string">
            <xs:attribute name="confidentiality" type="xs:boolean" />
            <xs:attribute name="integrity" type="xs:boolean" />
        </xs:extension>
    </xs:simpleContent>
</xs:complexType>

<xs:complexType name="flowElement">
    <xs:sequence>
        <xs:element name="assert" type="assertionElement" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="sink" use="required" />
    <xs:attribute name="sarg" use="required" />
    <xs:attribute name="darg" use="required" />
</xs:complexType>

<xs:complexType name="argElement">
    <xs:attribute name="name" use="required" />
    <xs:attribute name="controlled" type="xs:boolean"/>
</xs:complexType>

<xs:complexType name="baseElement">
    <xs:sequence>
        <xs:element name="assert" type="assertionElement" minOccurs="0" maxOccurs="1"/>
        <xs:element name="description" type="xs:string" minOccurs="0" maxOccurs="1"/>
        <xs:element name="config" type="xs:anyType" minOccurs="0" maxOccurs="1"/>
    </xs:sequence>
    <xs:attribute name="id" use="required" />
</xs:complexType>

<xs:complexType name="constElement">
    <xs:complexContent>
        <xs:extension base="baseElement">
            <xs:sequence minOccurs="0" maxOccurs="unbounded">
                <xs:choice>
                    <xs:element name="flow" type="flowElement"/>
                </xs:choice>
            </xs:sequence>
            <xs:attribute name="confidentiality" type="xs:boolean"/>
        </xs:extension>
    </xs:complexContent>
</xs:complexType>

<xs:complexType name="outputElement">
    <xs:complexContent>
        <xs:extension base="baseElement">
            <xs:sequence minOccurs="1" maxOccurs="1">
                <xs:choice>
                    <xs:element name="arg"  type="argElement"/>
                </xs:choice>
            </xs:sequence>
            <xs:attribute name="code" type="xs:string"/>
            <xs:attribute name="confidentiality" type="xs:boolean"/>
            <xs:attribute name="integrity" type="xs:boolean"/>
        </xs:extension>
    </xs:complexContent>
</xs:complexType>

<xs:complexType name="inputElement">
    <xs:complexContent>
        <xs:extension base="baseElement">
            <xs:sequence minOccurs="1" maxOccurs="1">
                <xs:choice>
                    <xs:element name="flow" type="flowElement"/>
                </xs:choice>
            </xs:sequence>
            <xs:attribute name="code" type="xs:string"/>
            <xs:attribute name="confidentiality" type="xs:boolean"/>
            <xs:attribute name="integrity" type="xs:boolean"/>
        </xs:extension>
    </xs:complexContent>
</xs:complexType>

<xs:complexType name="xformElement">
    <xs:complexContent>
        <xs:extension base="baseElement">
            <xs:sequence minOccurs="0" maxOccurs="unbounded">
                <xs:choice>
                    <xs:element name="flow" type="flowElement"/>
                    <xs:element name="arg" type="argElement"/>
                </xs:choice>
            </xs:sequence>
            <xs:attribute name="code" type="xs:string" use="required"/>
        </xs:extension>
    </xs:complexContent>
</xs:complexType>

<xs:complexType name="forwardElement">
    <xs:complexContent>
        <xs:extension base="baseElement">
                <xs:sequence minOccurs="0" maxOccurs="unbounded">
                    <xs:choice>
                        <xs:element name="flow" type="flowElement"/>
                   </xs:choice>
                </xs:sequence>
        </xs:extension>
    </xs:complexContent>
</xs:complexType>

<xs:complexType name="baseElements">
    <xs:sequence minOccurs="1" maxOccurs="unbounded">
        <xs:choice>
            <xs:element name="output"          type="outputElement"/>
            <xs:element name="input"           type="inputElement"/>
            <xs:element name="xform"           type="xformElement"/>
            <xs:element name="branch"          type="forwardElement"/>
            <xs:element name="const"           type="constElement"/>
            <xs:element name="dhpub"           type="forwardElement"/>
            <xs:element name="dhsec"           type="forwardElement"/>
            <xs:element name="rng"             type="forwardElement"/>
            <xs:element name="hmac"            type="forwardElement"/>
            <xs:element name="hmac_out"        type="forwardElement"/>
            <xs:element name="sign"            type="forwardElement"/>
            <xs:element name="verify_sig"      type="forwardElement"/>
            <xs:element name="verify_hmac"     type="forwardElement"/>
            <xs:element name="verify_hmac_out" type="forwardElement"/>
            <xs:element name="hash"            type="forwardElement"/>
            <xs:element name="decrypt"         type="forwardElement"/>
            <xs:element name="encrypt"         type="forwardElement"/>
            <xs:element name="encrypt_ctr"     type="forwardElement"/>
            <xs:element name="guard"           type="forwardElement"/>
            <xs:element name="release"         type="forwardElement"/>
            <xs:element name="comp"            type="forwardElement"/>
            <xs:element name="verify_commit"   type="forwardElement"/>
            <xs:element name="latch"           type="forwardElement"/>
        </xs:choice>
    </xs:sequence>
    <xs:attribute name="assert_fail" type="xs:boolean" />
    <xs:attribute name="code" type="xs:string" />
</xs:complexType>

<xs:element name="spg" type="baseElements">
    <xs:key name="IDKey">
        <xs:selector xpath="*"/>
        <xs:field xpath="@id"/>
    </xs:key>
    <xs:keyref name="IDRef" refer="IDKey">
        <xs:selector xpath="*/flow"/>
        <xs:field xpath="@sink"/>
    </xs:keyref>
</xs:element>

</xs:schema>
''')

args = ()

class MissingIncomingEdge (Exception):
    def __init__ (self, name, arg):
        Exception.__init__(self, "Node '" + name + "' has no incoming edge for argument '" + arg + "'")

class PrimitiveDuplicateConfRule (Exception):
    def __init__ (self, name):
        Exception.__init__(self, "Duplicate confidentiality rule for '" + name + "'")

class PrimitiveDuplicateIntgRule (Exception):
    def __init__ (self, name):
        Exception.__init__(self, "Duplicate integrity rule for '" + name + "'")

class PrimitiveInvalidRules (Exception):
    def __init__ (self, kind, name):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") has contradicting rules")

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

def mark_partition (G, node, partition):

    # Partition already set
    if 'partition' in G.node[node]:
        return False

    G.node[node]['partition'] = partition

    # Partition towards parents
    for (parent, child) in G.in_edges (nbunch=node):
        if G.node[parent]['guarantees']['c'] == G.node[node]['guarantees']['c'] and \
           G.node[parent]['guarantees']['i'] == G.node[node]['guarantees']['i']:
            mark_partition (G, parent, partition)

    # Partition towards children
    for (parent, child) in G.out_edges (nbunch=node):
        if G.node[child]['guarantees']['c'] == G.node[node]['guarantees']['c'] and \
           G.node[child]['guarantees']['i'] == G.node[node]['guarantees']['i']:
            mark_partition (G, child, partition)

    return True

def jdefault (o):
    return None

class Graph:

    def __init__ (self, graph, code, fail):
        self.graph    = graph
        self.fail     = fail
        self.code     = code 
        self.pd       = None

    def graph (self):
        return self.graph

    def check_assertions (self):

        success = True

        for (parent, child, data) in self.graph.edges (data=True):
            darg = data['darg']
            sarg = data['sarg']

            if data['assert_c'] != None:
                val_c = self.graph.node[parent]['primitive'].output.guarantees()[sarg].val_c()
                if val_c != data['assert_c']:
                    err (parent + "/" + sarg + " => " + child + "/" + darg + ": confidentiality assertion failed: " + str(val_c) + ", expected: " + str(data['assert_c']))
                    success = False

            if data['assert_i'] != None:
                val_i = self.graph.node[parent]['primitive'].output.guarantees()[sarg].val_i()
                if val_i != data['assert_i']:
                    err (parent + "/" + sarg + " => " + child + "/" + darg + ": integrity assertion failed: " + str(val_i) + ", expected: " + str(data['assert_i']))
                    success = False

        return success

    def analyze (self, dump_rules):

        solver = SPG_Solver()
        assertno = 0

        # Put node rules into solver
        for n in self.graph.nodes():
            self.graph.node[n]['primitive'].populate (solver)

        # Put edge (channel) rules into solver
        for (parent, child, data) in self.graph.edges(data=True):
            pog = self.graph.node[parent]['primitive'].output.guarantees()
            cig = self.graph.node[child]['primitive'].input.guarantees()
            darg = data['darg']
            sarg = data['sarg']
            channel = "CHNL_" + parent + "/" + sarg + " -> " + child + "/" + darg
            solver.assert_and_track (Conf(pog[sarg]) == Conf(cig[darg]), channel + "_conf")
            solver.assert_and_track (Intg(pog[sarg]) == Intg(cig[darg]), channel + "_intg")

        # Dump all rules if requested
        if dump_rules:
            for a in solver.solver.assertions():
                print (a)

        if solver.check() == sat:

            # Update all guarantee values
            for n in self.graph.nodes():
                primitive = self.graph.node[n]['primitive']
                ig = primitive.input.guarantees()
                for g in ig:
                    ig[g].update (solver.model())
                og = primitive.output.guarantees()
                for g in og:
                    og[g].update (solver.model())

            # Check assertions
            result = self.check_assertions()
            if result:
                info ("Assertions checked")
            else:
                warn ("Assertions failed")

            if self.fail:
                err ("Failure expected, but solution found");
                return False

            info ("Solution found")

            return result

        else:
            solver.mark_unsat_core(self.graph)

            # We expect a failure - exit without error
            if self.fail:
                return True

            err ("No solution")
            return False

    def partition (self, cluster):

        G = self.graph

        partitions = {}
        partition_no = 1

        for node in G.node:
            new_partition = mark_partition (G, node, partition_no)
            if new_partition:
                prefix = "cluster_" if cluster else "partition_"
                partitions[str(partition_no)] = pydot.Subgraph (graph_name = prefix + str(partition_no), label = "partition " + str(partition_no), penwidth = 2, bgcolor = "gray80")
                partition_no = partition_no + 1

        info ("Created " + str(partition_no - 1) + " partitions")

        for node in G.node:
            label = "<<b>" + node + "</b><font point-size=\"6\"><sub> (" + G.node[node]['kind'] + ")</sub></font> PART=" + str(G.node[node]['partition']) + ">"
            G.node[node]['label'] = label

        for node in nx.drawing.nx_pydot.to_pydot(G).get_nodes():
            node_partition = node.get('partition')
            new_node = pydot.Node(node.get_name())
            attributes = node.get_attributes()
            for a in attributes:
                new_node.set (a, attributes[a])
            partitions[node_partition].add_node (new_node)

        # Create graph
        graph = pydot.Dot()
        graph.set_type ("digraph")

        # Add partition subgraphs
        for p in partitions:
            graph.add_subgraph (partitions[p])

        for edge in self.pd.get_edges():
            new_edge = pydot.Edge (src = edge.get_source(), dst = edge.get_destination())
            attributes = edge.get_attributes()
            for a in attributes:
                new_edge.set (a, attributes[a])
            graph.add_edge (new_edge)

        self.pd = graph

    def label (self):

        G = self.graph
        for node in G.node:

            if G.node[node]['kind'] == "output":
                G.node[node]['shape'] = "invhouse"
                G.node[node]['style'] = "filled"
            elif G.node[node]['kind'] == "input":
                G.node[node]['shape'] = "cds"
                G.node[node]['style'] = "filled"
            else:
                G.node[node]['shape'] = "rectangle"

            val_c = False
            val_i = False

            if 'guarantees' in G.node[node]:
                val_c = G.node[node]['guarantees']['c']
                val_i = G.node[node]['guarantees']['i']

            for (parent, current, data) in G.in_edges (nbunch=node, data=True):
                darg = data['darg']
                val_c = val_c or G.node[current]['primitive'].input.guarantees()[darg].val_c()
                val_i = val_i or G.node[current]['primitive'].input.guarantees()[darg].val_i()

            for (current, child, data) in G.out_edges (nbunch=node, data=True):
                sarg = data['sarg']
                val_c = val_c or G.node[current]['primitive'].output.guarantees()[sarg].val_c()
                val_i = val_i or G.node[current]['primitive'].output.guarantees()[sarg].val_i()

            set_style (G.node[node], val_c, val_i)

            # Store node guarantees
            G.node[node]['guarantees']['c'] = val_c
            G.node[node]['guarantees']['i'] = val_i

        # add edge labels
        for (parent, child, data) in G.edges(data=True):

            # sarg guarantees of parent should are the same as darg guarantees of child
            darg = data['darg']
            sarg = data['sarg']

            data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
            data['headlabel'] = data['darg']
            data['tooltip'] = parent + ":" + data['sarg'] + " ==> " + child + ":" + data['darg']

            pg = G.node[parent]['primitive'].output.guarantees()[sarg]
            cg = G.node[child]['primitive'].input.guarantees()[darg]
            set_style (data, pg.val_c() and cg.val_c(), pg.val_i() and cg.val_i())

        self.pd = nx.drawing.nx_pydot.to_pydot(self.graph)

    def write (self, out):

        pd = self.pd
        pd.set_name("sdg")

        # Choose fixed rng start value to get deterministic layout
        pd.set ("start", "1")

        pd.set ("sep", "+50,20")
        pd.set ("esep", "+10,4")
        pd.set ("splines", "ortho")
        pd.set ("size", "15.6,10.7")
        pd.set ("labelloc", "t")

        if out.endswith(".pdf"):
            pd.write (out, prog = 'fdp', format = 'pdf')
        elif out.endswith(".svg"):
            pd.write (out, prog = 'fdp', format = 'svg')
        elif out.endswith(".dot"):
            pd.write (out, prog = 'dot', format = 'dot')
        elif out.endswith(".graph"):
            with open (out, 'w') as outfile:
                for (node, data) in sorted (self.graph.nodes (data=True)):
                    for outarg in sorted (self.graph.node[node]['primitive'].output.guarantees()):
                        c = self.graph.node[node]['primitive'].output.guarantees()[outarg].val_c()
                        i = self.graph.node[node]['primitive'].output.guarantees()[outarg].val_i()
                        outfile.write (node + ": OUTPUT " + outarg + " i=" + str(i) + " c=" + str(c) + "\n")
                    for inarg in sorted (self.graph.node[node]['primitive'].input.guarantees()):
                        c = self.graph.node[node]['primitive'].input.guarantees()[inarg].val_c()
                        i = self.graph.node[node]['primitive'].input.guarantees()[inarg].val_i()
                        outfile.write (node + ": INPUT " + outarg + " i=" + str(i) + " c=" + str(c) + "\n")

        elif out.endswith(".json"):
            with open (out, 'w') as outfile:
                nld = json_graph.node_link_data (self.graph)

                # Cleanup unneeded elements
                del nld['graph']
                del nld['directed']
                del nld['multigraph']

                for l in nld['links']:
                    del l['tooltip']
                    del l['headlabel']
                    del l['taillabel']
                    del l['labelfontname']
                    del l['penwidth']
                    l['type'] = 'Directed'
                    l['source'] = nld['nodes'][l['source']]['id']
                    l['target'] = nld['nodes'][l['target']]['id']

                for n in nld['nodes']:
                    del n['tooltip']
                    del n['width']
                    del n['height']
                    del n['penwidth']

                    n['label'] = n['id']
                    n['shape'] = 'box'

                # Rename edges to links
                nld['edges'] = nld.pop('links')

                json.dump (nld, outfile, default = jdefault)
        else:
            raise Exception ("Unsupported graphviz output type")

    def statistics (self):

        out_i = 0
        out_c = 0
        in_i = 0
        in_c = 0

        for (parent, child, data) in self.graph.edges (data=True):

            sarg = data['sarg']
            if self.graph.node[parent]['primitive'].output.guarantees()[sarg].val_c():
                out_c = out_c + 1

            if self.graph.node[parent]['primitive'].output.guarantees()[sarg].val_i():
                out_i = out_i + 1

            darg = data['darg']
            if self.graph.node[child]['primitive'].input.guarantees()[darg].val_c():
                in_c = in_c + 1

            if self.graph.node[child]['primitive'].input.guarantees()[darg].val_i():
                in_i = in_i + 1

        info ("in_c: " + str(in_c) + " in_i: " + str(in_i) + " out_c: " + str(out_c) + " out_i: " + str(out_i))

    def run (self):

        G = self.graph

        # import global library
        libspg   = __import__ ("libspg")
        liblocal = __import__ (self.code)

        for node in G.node:

            kind = G.node[node]['kind']
            lib  = libspg
            name = kind

            if kind == "input" or kind == "output" or kind == "xform":
                classname = G.node[node]['classname']
                if classname != None:
                    name = kind + "_" + G.node[node]['classname']

            try:
                libclass = getattr (libspg, name)
            except AttributeError:
                try:
                    libclass = getattr (liblocal, name)
                except AttributeError:
                    raise PrimitiveNotImplemented (name)

            classobj = libclass (node, G.node[node]['config'], G.node[node]['arguments'])
            G.node[node]['class'] = classobj

        for node in G.node:

            # Insert send methods into class object
            sendmethods = {}
            for (parent, child, data) in G.out_edges (nbunch=node, data=True):
                try:
                    recvmethod = getattr (G.node[child]['class'], "recv_" + data['darg'])
                except AttributeError:
                    warn ("Implementation of '" + child + "' does not have receive method for parameter '" + data['darg'] + "'")
                    raise
                sendmethods[data['sarg']] = recvmethod

            G.node[node]['class'].sendmethods (sendmethods)

        for node in G.node:
            G.node[node]['class'].setDaemon (True)
            G.node[node]['class'].start ()

        # join all threads
        for node in G.node:
            G.node[node]['class'].join ()

class Args:

    def __init__ (self, graph, name):
        raise Exception ("Abstract")

    def setup (self, graph, name):
        self._graph  = graph
        self._name   = name

    def add_guarantee (self, name):
        self.__dict__.update (**{name: Guarantees (self._graph, self._name + "_" + name)})

    def guarantees (self):
        return { k: v for k, v in self.__dict__.items() if not k.startswith("_") }

class Input_Args (Args):

    def __init__ (self, graph, name):
        super().setup (graph, name + "_input")

class Output_Args (Args):

    def __init__ (self, graph, name):
        super().setup (graph, name + "_output")

class SPG_Solver_Base:

    def __init__ (self):
        raise Exception ("Abstract")

    def check (self):
        return self.solver.check()

    def model (self):
        return self.solver.model()

class SPG_Solver (SPG_Solver_Base):

    def __init__ (self):
        self.solver = Solver()
        self.assert_db = {}
        self.solver.set(unsat_core=True)
        self.constraints = {}

    def assert_and_track (self, condition, name):

        if (condition == None):
            return

        key = "ASSERT_" + str(name)
        if key in self.assert_db:
            raise InconsistentRule (name, "Already present")
        self.assert_db[key] = condition
        self.solver.assert_and_track (condition, key)

    def mark_expression (self, G, uc):
        if is_and (uc) or is_or (uc):
            for idx in range (0, uc.num_args()):
                self.mark_expression (G, uc.arg(idx))
        elif is_eq(uc):
            self.mark_expression (G, uc.arg(0))
            self.mark_expression (G, uc.arg(1))
        elif is_not(uc):
            self.mark_expression (G, uc.arg(0))
        elif is_const(uc):
            self.constraints[str(uc)] = True
        else:
            raise Exception ("Unhandled expression: " + str(uc))

    def mark_unsat_core (self, G):
        unsat_core = []
        for p in self.solver.unsat_core():
            unsat_core.append (simplify (self.assert_db[str(p)]))
        self.mark_expression (G, simplify (And (unsat_core)))
        info ("Full, simplified unsat core:")
        info (str(simplify (And (unsat_core))))

class Guarantees:

    def __init__ (self, graph, name):
        self.graph = graph
        self.name  = name

        # Rules defining integrity and confidentiality
        # This is assigned by the primitive init function
        self.__conf  = None
        self.__intg  = None

        # Z3 variables representing confidentiality and
        # integrity within the solver. These values are
        # used in the rules.
        self.__c   = Bool(name + "_conf")
        self.__i   = Bool(name + "_intg")

        # The actual boolean value. This is filled in from
        # a valid model found by the solver
        self.__val_c = None
        self.__val_i = None

    def conf (self, value):
        if self.__conf != None:
            raise PrimitiveDuplicateConfRule (self.name)
        self.__conf = value

    def intg (self, value):
        if self.__intg != None:
            raise PrimitiveDuplicateIntgRule (self.name)
        self.__intg = value

    def get_conf (self):
        return self.__conf

    def get_intg (self):
        return self.__intg

    def name (self):
        return name

    def get_i (self):
        return self.__i

    def get_c (self):
        return self.__c

    def val_c (self):
        return self.__val_c

    def val_i (self):
        return self.__val_i

    def update (self, model):
        self.__val_c = is_true(model[self.__c])
        self.__val_i = is_true(model[self.__i])
    
def Intg (guarantee):
    return guarantee.get_i()

def Conf (guarantee):
    return guarantee.get_c()

####################################################################################################

class Primitive:
    """
    An "abstract" class implementing generic methods for a Primitive
    """

    def __init__ (self, G, name):
        raise Exception ("Abstract")

    def setup (self, G, name):
        self.input  = Input_Args (G, name)
        self.output = Output_Args (G, name)
        self.name   = name
        self.node   = G.graph.node[name]
        self.graph  = G

        for (parent, current, data) in G.graph.in_edges (nbunch=name, data=True):
            self.input.add_guarantee (data['darg'])

        for (current, child, data) in G.graph.out_edges (nbunch=name, data=True):
            self.output.add_guarantee (data['sarg'])

    def populate (self, solver):
        ig = self.input.guarantees()
        for g in ig:
            solver.assert_and_track (ig[g].get_conf(), "RULE_" + self.name + "_" + g + "_input_conf")
            solver.assert_and_track (ig[g].get_intg(), "RULE_" + self.name + "_" + g + "_input_intg")
        og = self.output.guarantees()
        for g in og:
            solver.assert_and_track (og[g].get_conf(), "RULE_" + self.name + "_" + g + "_output_conf")
            solver.assert_and_track (og[g].get_intg(), "RULE_" + self.name + "_" + g + "_output_intg")

    def prove (self, solver):
        self.populate (solver)
        if solver.check() != sat:
            raise PrimitiveInvalidRules (self.__class__.__name__, self.name)
        del solver

class Primitive_output (Primitive):
    """
    The output primitive

    Denotes one sink outside the model. Fixed guarantees according to the
    XML definition are used only here.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Guarantees explicitly set in the XML
        g = self.node['guarantees']

        for (name, ig) in self.input.guarantees().items():
            if g['c'] != None:
                ig.conf (Conf (ig) == g['c'])
            if g['i'] != None:
                ig.intg (Intg (ig) == g['i'])

class Primitive_input (Primitive):
    """
    The input primitive

    Denotes one source outside the model. Fixed guarantees according to the
    XML definition are used only here.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Guarantees explicitly set in the XML
        g = self.node['guarantees']

        for (name, og) in self.output.guarantees().items():
            if g['c'] != None:
                og.conf (Conf (og) == g['c'])
            if g['i'] != None:
                og.intg (Intg (og) == g['i'])

class Primitive_xform (Primitive):
    """
    The xform primitive

    This mainly identifies sources and sinks and sets the fixed
    guarantees according to the XML definition.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        #   Input from a source lacking integrity guarantees can influence
        #   any output of an xform in undetermined ways. Hence, integrity
        #   guarantees cannot be maintained for any output interface.
        #
        #   Integrity can be maintained if the input interfaces is
        #   controlled by the xform implementation, i.e. it is guaranteed
        #   that it can influence the output only in well-defined ways
        #   (permutation, fixed output position).
        #
        #   (Intg(output_if) ⇒ Intg(input_if)) ∨ Controlled (input_if)

        for (in_name, input_if) in self.input.guarantees().items():
            controlled = in_name in G.graph.node[name]['controlled']
            input_if_rules = []
            for (out_name, output_if) in self.output.guarantees().items():
                input_if_rules.append (Or (Implies (Intg(output_if), Intg(input_if)), controlled))
            input_if.intg (And (input_if_rules))

        #   Input from a source demanding confidentiality guarantees can
        #   influence any output of an xform in undetermined ways. Hence,
        #   confidentiality must be guaranteed by all output interfaces.
        #
        #   Conf(input_if) -> Conf(output_if)
        for (out_name, output_if) in self.output.guarantees().items():
            output_if_rules = []
            for (in_name, input_if) in self.input.guarantees().items():
                output_if_rules.append (Implies (Conf(input_if), Conf(output_if)))
            output_if.conf (And (output_if_rules))

class Primitive_branch (Primitive):
    """
    The branch primitive

    Copy the input parameter into all output parameters.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        if len(self.input.guarantees().items()) > 1:
            raise PrimitiveInvalidAttributes (name, "branch", "More than one input parameters")

        # If integrity is guaranteed for some output, then integrity
        # must be guaranteed for the input, too.
        for (out_name, out_g) in self.output.guarantees().items():
            out_g.intg (Implies (Intg(out_g), Intg(self.input.data)))

        # If confidentiality is guaranteed for the input, then integrity
        # must be guaranteed for all outputs, too.
        output_conf_rules = []
        for (out_name, out_g) in self.output.guarantees().items():
            output_conf_rules.append (Implies (Conf(self.input.data), Conf(out_g)))
        out_g.conf (And (output_conf_rules))

class Primitive_const (Primitive):
    """
    The const primitive
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Guarantees explicitly set in the XML
        g = self.node['guarantees']

        og = self.output.guarantees()['const']
        if g['c'] != None:
            og.conf (Conf (og) == g['c'])
        else:
            self.output.const.conf (Conf(self.output.const))

class Primitive_rng (Primitive):
    """
    Primitive for a true (hardware) random number generator

    This RNG is not seeded. It has an input parameter len, determining how
    many bits we request from it.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  len
        #   Output: data

        # Parameter
        #   len_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   The confidentiality of an input parameter is not influenced by an
        #   output parameters or other input parameters as the data flow is
        #   directed. Hence, the demand for confidentiality guarantees is
        #   solely determined by the source of an input interface
        #   FIXME: This does not hold if we consider meta-confidentiality (e.g. the length out output data)
        # Assertion:
        #   None

        # Parameter
        #   len_in
        # Integrity guarantees can be dropped if:
        #   Always
        # Reason:
        #   An attacker could change or reorder len_in creating
        #   data_out messages of chosen, invalid length.
        # Assertion:
        #   len_in_i
        self.input.len.intg (Intg(self.input.len))

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   Never
        # Reason:
        #   We assume that this RNG is always used to produce keys which need to
        #   be confidential. If required, we can introduce a nonce generator later
        #   which does not imply confidentiality guarantees for its output. The RNG
        #   should be safe, as the worst thing that may happen is that confidentiality
        #   is required unnecessarily. Most likely this will result in a conflict in
        #   nonce case, as those are typically passed to domains without
        #   confidentiality guarantees.
        self.output.data.conf (Conf (self.output.data))

        # Parameter
        #   data_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   FIXME
        # Assertion:
        #   None

class Primitive_dhpub (Primitive):

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:   modulus, generator, psec
        #   Outputs: pub

        # Parameters are public, but an attacker may not chose a weak ones.
        # Hence, integrity must be guaranteed
        self.input.modulus.intg (Intg(self.input.modulus))
        self.input.generator.intg (Intg(self.input.generator))

        #   With knowledge of g^y and psec_in (x in DH terms) an attacker can
        #   calculate the shared secret g^y^x
        self.input.psec.conf (Conf(self.input.psec))

        #   If an attacker can choose psec_in (x in DH terms) and knows g^y,
        #   she can calculate the shared secret g^yx
        self.input.psec.intg (Intg(self.input.psec))

        #   Being able to transmit g^x over an non-confidential channel is the
        #   sole purpose of the DH key exchange, given that x has
        #   confidentiality and integrity guarantees
        self.output.pub.conf (Or (Conf(self.output.pub), And (Conf(self.input.psec), Intg(self.input.psec))))

class Primitive_dhsec (Primitive):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  modulus, generator, pub, psec
        #   Outputs: ssec

        # With knowledge of pub (g^y) and psec_in (x) an attacker can
        # calculate ssec (the shared secret g^yx ≡ g^xy)
        self.input.psec.conf (Conf(self.input.psec))

        # If the shared secret shall be confidential, then psec must not be chosen
        # by an attacker
        self.input.psec.intg (Intg(self.input.psec))

        # No weak parameters must be chosen by an attacker
        self.input.modulus.intg (Intg(self.input.modulus))
        self.input.generator.intg (Intg (self.input.generator))

        # Confidentiality must be guaranteed for shared secret
        self.output.ssec.conf (Conf(self.output.ssec))

class Primitive_encrypt (Primitive):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  plaintext, key, ctr
        #   Outputs: ciphertext

        # Counter mode encryption does not achieve integrity, hence an attacker
        # can could change plaintext_in to influence the integrity of
        # ciphertext_out. If integrity must be guaranteed for ciphertext_out,
        # it also must be guaranteed for plaintext_in.
        self.input.plaintext.intg (Implies (Intg(self.output.ciphertext), Intg(self.input.plaintext)))

        # If plaintext_in is known to an attacker (i.e. not confidential), it
        # is superfluous to guarantee confidentiality for key_in.
        # If ciphertext_out requires confidentiality, the confidentiality of
        # pt_in is guaranteed even if key_in is known to an attacker.
        self.input.key.conf (Or (Conf(self.input.key), Not (Conf(self.input.plaintext)), Conf(self.output.ciphertext)))

        # Integrity of input key must always be guaranteed
        self.input.key.intg (Intg (self.input.key))

        # If no confidentiality is guaranteed for plaintext_in in the first
        # place, it is superfluous to encrypt (and hence chose unique counter
        # values). If confidentiality is guaranteed for ciphertext_out,
        # encryption is not necessary. Hence, a ctr_in chose by an attacker
        # does no harm.
        self.input.ctr.intg (Or (Intg(self.input.ctr), Not (Conf(self.input.plaintext)), Conf(self.output.ciphertext)))

        # If confidentiality and integrity is guaranteed for the key and
        # integrity is guaranteed for ctr (to avoid using the same key/ctr
        # combination twice), an attacker cannot decrypt the ciphertext and
        # thus no confidentiality needs to be guaranteed by the environment.
        self.output.ciphertext.conf (Or (Conf(self.output.ciphertext), And (Conf(self.input.key), Intg(self.input.key), Intg(self.input.ctr))))

class Primitive_encrypt_ctr (Primitive_encrypt):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  plaintext, key, ctr
        #   Outputs: ciphertext, ctr

        # If integrity is guaranteed for output counter, integrity must be guaranteed for initial counter
        self.output.ctr.intg (Implies (Intg(self.output.ctr), Intg(self.input.ctr)))

        # If confidentiality is guaranteed for initial counter, confidentiality must be guaranteed for output counter
        self.output.ctr.conf (Implies (Conf(self.input.ctr), Conf(self.output.ctr)))

class Primitive_decrypt (Primitive):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  ciphertext, key, ctr
        #   Output: plaintext

        # Parameter
        #   ciphertext_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        #   FIXME: I thought of only dropping confidentiality if confidentiality
        #   is guaranteed for key_in. However, this would preclude commitment
        #   schemes where a party sends the key over a non-confidential channel.
        # Reason:
        #   This is the purpose of (symmetric) encryption.
        # Assertion:
        #   None

        # Parameter
        #   ciphertext_in
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   Data flow is directed. Integrity of an input parameter cannot be
        #   influenced by an output parameter or other input parameters.
        # Assertion:
        #   None

        # Parameter
        #   key_in
        # Confidentiality guarantee can be dropped if:
        #   If no confidentiality is guaranteed for plaintext_out
        # Reason:
        #   If confidentiality is not guaranteed for the decryption
        #   result, keeping the cipher key secret is superfluous.
        # Assertion:
        #   key_in_c ∨ ¬plaintext_out_c (equiv: plaintext_out_c ⇒ key_in_c)
        self.input.key.conf (Implies (Conf(self.output.plaintext), Conf(self.input.key)))

        # Parameter
        #   key_in
        # Integrity guarantee can be dropped if:
        #   Anytime.
        #   FIXME: What happens when an attacker can chose a key for decryption? My
        #   feeling is that this does not harm to confidentiality. It may enable oracle
        #   attacks, however.
        # Reason:
        #   An attacker cannot derive the plaintext by providing an own key to
        #   the decryption. The output will be wrong, but integrity is not achieved by
        #   counter mode encryption anyway.
        # Assertion:
        #   None

        # Parameter
        #   ctr_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The counter is public as per counter mode definition.
        # Assertion:
        #   None

        # Parameter
        #   ctr_in
        # Integrity guarantee can be dropped if:
        #   If no confidentiality is guaranteed for plaintext_out
        # Reason:
        #   If confidentiality is not guaranteed for the decryption
        #   result, ensuring proper encryption (the freshness of the
        #   key/ctr combination in this case) is superfluous.
        # Assertion:
        #   None

        # Parameter
        #   plaintext_out
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The guarantees required only depend on the primitives using
        #   the decryption result (i.e. encrypting data that has no
        #   confidentiality requirements is perfectly fine)
        # Assertion:
        #   None

        # Parameter
        #   plaintext_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity guarantees are required is only determined by the
        #   primitive using the decryption result.
        # Assertion:
        #   None

class Primitive_hash (Primitive):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data
        #   Output: hash

        # Parameter
        #   data_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   As data flow is directed, confidentiality guarantees for an input
        #   interface only depend on the primitive providing the data for that
        #   interface.
        # Assertion:
        #   None

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   Never
        # Reason:
        #   Using a cryptographically secure hash makes no sense with non-integer data.
        # Assertion:
        #   data_in_i
        self.input.data.intg (Intg(self.input.data))

        # Parameter
        #   hash_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for data_in
        # Reason:
        #   Even with a cryptographically secure hash function, an attacker
        #   may be able to recover data_in from hash_out, depending on the
        #   resource available and the structure of data_in. As we don't want
        #   to get probabilistic here, we just assume this is always possible.
        #   FIXME: It may become hard to cope with protocols where the
        #   infeasibility of reversing the hash is used, e.g. password
        #   authentication.
        # Truth table:
        #   hash_out_i data_in_i result
        #   0          0         1
        #   0          1         0
        # Assertion:
        #   hash_out_c ∨ ¬data_in_c (equiv: data_in_c ⇒ hash_out_c)
        self.output.hash.conf (Implies (Conf(self.input.data), Conf(self.output.hash)))

        # Parameter
        #   hash_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   FIXME

class Primitive_hmac (Primitive):

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  key, msg
        #   Output: auth

        # Parameter
        #   key_in
        # Confidentiality guarantee can be dropped if:
        #   Integrity is not guaranteed for msg_in
        # Reason:
        #   If integrity is not guaranteed for the input data, HMAC cannot
        #   protect anything. Hence, it does not harm if the key is released
        #   to an attacker.
        # Assertion:
        #   key_in_c ∨ ¬msg_in_i (equiv: msg_in_i ⇒ key_in_c)
        self.input.key.conf (Implies (Intg(self.input.msg), Conf(self.input.key)))

        # Parameter
        #   key_in
        # Integrity guarantee can be dropped if:
        #   Integrity is not guaranteed for msg_in
        # Reason:
        #   If integrity is not guaranteed for the input data and attacker can
        #   chose a key and HMAC cannot protect anything. Hence, it does not
        #   harm if the key is chosen by an attacker.
        # Assertion:
        #   key_in_i ∨ ¬msg_in_i (equiv: msg_in_i ⇒ key_in_i)
        self.input.key.intg (Implies (Intg(self.input.msg), Intg(self.input.key)))

        # Parameter
        #   msg_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   HMAC does not achieve nor assume confidentiality
        # Assertion:
        #   None

        # Parameter
        #   msg_in
        # Integrity guarantee can be dropped if:
        #   Never
        # Reason:
        #   We assume that an HMAC component is only used when integrity must
        #   be guaranteed for the msg_in.
        #   FIXME: Are there scenarios where it makes sense to HMAC data that
        #   has not integrity requirements?
        # Assertion:
        #   msg_in_i
        self.input.msg.intg (Intg (self.input.msg))

        # Parameter
        #   auth_out
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Without knowing the secret key, an attacker cannot create a msg/auth
        #   pair which authenticates using that key. Hence, neither for the message
        #   nor for the auth value the environment has to maintain confidentiality.
        # Assertion:
        #   None
        self.output.auth.conf (Implies (Conf(self.input.msg), Conf(self.output.auth)))

        # Parameter
        #   auth_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Without knowing the secret key, an attacker cannot create a msg/auth
        #   pair which authenticates using that key. Hence, neither for the message
        #   nor for the auth value the environment has to maintain integrity.
        # Assertion:
        #   None

class Primitive_hmac_out (Primitive_hmac):

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  key, msg
        #   Output: auth, msg

        # Parameter
        #   msg_out
        # Confidentiality guarantee can be dropped if:
        #   msg_in requires no confidentiality
        # Reason:
        #   The HMAC does not achieve confidentiality.
        # Assertion:
        #   msg_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ msg_out_c)
        self.output.msg.conf (Implies (Conf(self.input.msg), Conf(self.output.msg)))

        # Parameter
        #   msg_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   This is the purpose of HMAC.
        # Assertion:
        #   None

class Primitive_sign (Primitive):

    """
    The sign primitive

    Creates an asymmetric digital signature for a message using a given set of
    public and secret keys.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  msg, pubkey, privkey, rand
        #   Output: auth

        # The private key must stay confidential
        self.input.privkey.conf (Conf (self.input.privkey))

        # An attacker must not chose the private key
        self.input.privkey.intg (Intg (self.input.privkey))

        # An attacker must not chose the public key
        self.input.pubkey.intg (Intg (self.input.pubkey))

        # Random number x must be confidential and not chosen by attacker
        self.input.rand.intg (Intg (self.input.rand))
        self.input.rand.conf (Conf (self.input.rand))

        # Even with a cryptographically secure hash function, an attacker
        # may be able to recover data_in from auth_out, depending on the
        # resource available and the structure of msg_in. As we don't want
        # to get probabilistic here, we just assume this is always possible.
        self.output.auth.conf (Implies (Conf(self.input.msg), Conf(self.output.auth)))

class Primitive_verify_sig (Primitive):

    """
    The signature verification primitive

    Checks whether an auth value represents a valid message signature by a given public key.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  msg, auth, pubkey
        #   Output: result

        # If an attacker can modify the result of a verify operation, she could
        # as well chose an own public key for which she has the secret key available
        # (and thus can create a valid signature yielding a positive result)
        self.input.pubkey.intg (Intg(self.input.pubkey))

        # If confidentiality is to be guaranteed for msg, this may also apply for
        # the fact whether it was signed with pubkey.
        self.output.result.conf (Implies (Conf(self.input.msg), Conf(self.output.result)))

class Primitive_verify_hmac (Primitive):

    """
    HMAC verification primitive

    Checks whether a given pair (msg, auth) was MAC'ed with key.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  msg, auth, key
        #   Output: result

        # Parameter
        #   msg_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   HMAC verification does not assume confidentiality for the input
        #   message.
        # Assertion:
        #   None

        # Parameter
        #   msg_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None

        # Parameter
        #   auth_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Signature verification does not assume confidentiality for signature.
        # Assertion:
        #   None

        # Parameter
        #   auth_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None

        # Parameter
        #   key_in
        # Confidentiality guarantee can be dropped if:
        #   If no integrity is guaranteed for result
        # Reason:
        #   If an attacker can modify the result of a verify operation, she could
        #   as well chose an own key and use it to create a valid signature yielding
        #   a positive result
        # Assertion:
        #   pkey_in_c ∨ ¬result_out_i (equiv: result_out_i ⇒ pkey_in_c)
        self.input.key.conf (Implies (Intg(self.output.result), Conf(self.input.key)))

        # Parameter
        #   key_in
        # Integrity guarantee can be dropped if:
        #   If no integrity is guaranteed for result
        # Reason:
        #   If an attacker can modify the result of a verify operation, she could
        #   as well chose an own public key for which she has the secret key available
        #   (and thus can create a valid signature yielding a positive result)
        # Assertion:
        #   key_in_i ∨ ¬result_out_i (equiv: result_out_i ⇒ key_in_i)
        self.input.key.intg (Implies (Intg(self.output.result), Intg(self.input.key)))

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for msg_in
        # Reason:
        #   FIXME: Does the value of result really allow for gaining knowledge about msg?
        # Assertion:
        #   result_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ result_out_c)
        self.output.result.conf (Implies (Conf(self.input.msg), Conf(self.output.result)))

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_verify_hmac_out (Primitive_verify_hmac):

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  msg, auth, key
        #   Output: result, msg

        # Parameter
        #   msg_out
        # Confidentiality guarantee can be dropped if:
        #   msg_in requires no confidentiality
        # Reason:
        #   The HMAC does not achieve confidentiality.
        # Assertion:
        #   msg_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ msg_out_c)
        self.output.msg.conf (Implies (Conf(self.input.msg), Conf(self.output.msg)))

        # Parameter
        #   msg_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_guard (Primitive):

    """
    Guard primitive

    This primitive guards the control the data flow in a protocol. Input data is
    only transferred to the output interfaces if the condition on the input interfaces is
    true.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data, cond
        #   Output: data

        # Parameter
        #   data_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   As data flow is directed, confidentiality guarantees for an input
        #   interface only depend on the primitive providing the data for that
        #   interface.
        # Assertion:
        #   None

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   No integrity is to be guaranteed for data_out
        # Reason:
        #   If data_out requires no integrity, it is OK for data_in to be altered
        #   by an attacker.
        # Assertion:
        #   data_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ data_in_i)
        self.input.data.intg (Implies (Intg(self.output.data), Intg(self.input.data)))

        # Parameter
        #   cond_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   As data flow is directed, confidentiality guarantees for an input
        #   interface only depend on the primitive providing the data for that
        #   interface.
        # Assertion:
        #   None

        # Parameter
        #   cond_in
        # Integrity guarantee can be dropped if:
        #   Never
        # Reason:
        #   Guard can be used to coordinate protocol steps, e.g. to send a reply
        #   only if the signature of a previous message was OK. Hence, the
        #   integrity requirements are at protocol level and cannot be derived
        #   from the primitive (or other primitives)
        #   FIXME: Is it true we cannot derive it from primitives? Should we
        #   make this configurable then?
        # Assertion:
        #   cond_in_i
        self.input.cond.intg (Intg (self.input.cond))

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is to be guaranteed for data_in
        # Reason:
        #   If data_in has no confidentiality guarantees, it
        #   makes no sense to keep data_out confidential.
        # Assertion:
        #   data_out_c ∨ ¬data_in_c (equiv: data_in_c ⇒ data_out_c)
        self.output.data.conf (Implies (Conf(self.input.data), Conf(self.output.data)))

        # Parameter
        #   data_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_release (Primitive):

    """
    Release primitive

    This primitive allows to drop all security guarantees.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data
        #   Output: data

        # Parameter
        #   data_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   As data flow is directed, confidentiality guarantees for an input
        #   interface only depend on the primitive providing the data for that
        #   interface.
        # Assertion:
        #   None

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   This is the purpose of the component
        # Assertion:
        #   None

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   This is the purpose of the component
        # Assertion:
        #   None

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_comp (Primitive):

    """
    Comp primitive

    This primitive compares two arbitrary inputs and outputs a boolean value
    indicating whether both inputs were identical or not.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data1, data2
        #   Output: result

        # Parameter
        #   data1_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   As data flow is directed, confidentiality guarantees for an input
        #   interface only depend on the primitive providing the data for that
        #   interface.
        # Assertion:
        #   None

        # Parameter
        #   data1_in
        # Integrity guarantee can be dropped if:
        #   No integrity guarantee is demanded for result_out
        # Reason:
        #   If an attacker can chose data1_in, she can influence the integrity
        #   of result_out (at least, make result_out false with a very high
        #   likelihood by choosing a random value for data1_in)
        # Assertion:
        #   data1_in_i ∨ ¬result_out_i (equiv: result_out_i ⇒ data1_in_i)
        self.input.data1.intg (Implies (Intg(self.output.result), Intg(self.input.data1)))

        # Parameter
        #   data2_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   As data flow is directed, confidentiality guarantees for an input
        #   interface only depend on the primitive providing the data for that
        #   interface.
        # Assertion:
        #   None

        # Parameter
        #   data2_in
        # Integrity guarantee can be dropped if:
        #   No integrity guarantee is demanded for result_out
        # Reason:
        #   If an attacker can chose data2_in, she can influence the integrity
        #   of result_out (at least, make result_out false with a very high
        #   likelihood by choosing a random value for data2_in)
        # Assertion:
        #   data2_in_i ∨ ¬result_out_c (equiv: result_out_c ⇒ data2_in_i)
        self.input.data2.intg (Implies (Intg(self.output.result), Intg(self.input.data2)))

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   If confidentiality is not guaranteed for both, data1 and data2
        # Reason:
        #   If an attacker knows data1 and data2 she can derive result_out
        #   by comparing both values
        # Assertion:
        #   result_out_c ∨ ¬(data1_in_c ∧ data2_in_c)
        self.output.result.conf (Or (Conf(self.output.result), Not (And (Conf (self.input.data1), Conf (self.input.data2)))))

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_verify_commit (Primitive):
    """
    Primitive for a verifying a commitment.

    This primitives verifies a commitment using a cryptographic hash function. It
    takes a hash value h and a data value d. If the hash value is received prior to
    the data value and the hash(d) == h, then the primitive outputs d.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data, hash
        #   Output: data

        # Parameter
        #   data
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
        #   data_in
        # Integrity guarantees can be dropped if:
        #   No integrity is guaranteed for data_out
        # Reason:
        #   If an attacker can chose data, she may change the output data.
        # Truth table
        #   data_in_i data_out_i result
        #   0         0          1
        #   0         1          0
        # Assertion:
        #   data_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ data_in_i)
        self.input.data.intg (Implies (Intg(self.output.data), Intg(self.input.data)))

        # Parameter
        #   hash
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
        #   hash
        # Integrity guarantees can be dropped if:
        #   Anytime
        #   FIXME: Really?
        # Reason:
        #   Output data is not influenced by hash input parameter.
        # Assertion:
        #   None

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is to be guaranteed for data_in
        # Reason:
        #   If data_in has no confidentiality guarantees, it
        #   makes no sense to keep data_out confidential.
        # Assertion:
        #   data_out_c ∨ ¬data_in_c (equiv: data_in_c ⇒ data_out_c)
        self.output.data.conf (Implies (Conf(self.input.data), Conf(self.output.data)))

        # Parameter
        #   data_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_latch (Primitive):

    """
    Latch primitive

    This primitive receives a value (potentially without any guarantees) and outputs
    it unmodified. It guarantees that after receiving a value once it cannot be changed anymore.
    Additionally it has a trigger output signaling that data was received.

    Rationale: This is used for commitment schemes where we open a commitment only after
    we received a peers (immutable) value.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data
        #   Output: data, trigger

        # Parameter
        #   data_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The confidentiality of an input parameter is not influenced by an
        #   output parameters or other input parameters as the data flow is
        #   directed. Hence, the demand for confidentiality guarantees is
        #   solely determined by the source of an input interface
        # Assertion:
        #   None

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   data_out has no integrity guaranteed
        # Reason:
        #   Otherwise, an attacker could change the content of data_out
        #   by changing data_in
        # Assertion:
        #   data_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ data_in_i)
        self.input.data.intg (Implies (Intg(self.output.data), Intg(self.input.data)))

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   data_in demands no confidentiality
        # Reason:
        #   Confidential data from data_in is passed on to data_out. Hence,
        #   confidentiality can only be dropped if data_in guarantees no
        #   confidentiality
        # Assertion:
        #   data_in_c -> data_out_c
        self.output.data.conf (Implies (Conf(self.input.data), Conf(self.output.data)))

        # Parameter
        #   data_out
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

        # Parameter
        #   trigger_out
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   No confidential information is passed on to trigger.
        # Assertion:
        #   None

        # Parameter
        #   trigger_out
        # Integrity guarantee can be dropped if:
        #   Never.
        # Reason:
        #   The purpose of the latch primitive is to open a commitment. If it triggers
        #   too early, this may happen before the peer has committed to a value. Hence,
        #   the trigger value requires integrity guarantees.
        # Assertion:
        #   trigger_out_i
        self.output.trigger.intg (Intg (self.output.trigger))

####################################################################################################

def parse_bool (attrib, name):
    if not name in attrib:
        return None
    if attrib[name] == "true":
        return True
    if attrib[name] == "false":
        return False
    raise Exception ("Invalid boolean value for '" + name + "'")

def parse_guarantees (attribs):
    return {
        'c': parse_bool (attribs, 'confidentiality'),
        'i': parse_bool (attribs, 'integrity'),
    }

def parse_graph (inpath):

    try:
        schema_doc = etree.parse(schema_src)
        schema = etree.XMLSchema (schema_doc)
    except etree.XMLSchemaParseError as e:
        err ("Error compiling schema: " + str(e))
        sys.exit(1)

    try:
        tree = etree.parse (inpath)
    except (IOError, etree.XMLSyntaxError) as e:
        err (inpath + ": " + str(e))
        sys.exit(1)

    if not schema.validate (tree):
        err (inpath)
        print (schema.error_log.last_error)
        sys.exit(1)

    root = tree.getroot()
    assert_fail = False
    if 'assert_fail' in root.attrib and root.attrib['assert_fail'] == 'true':
        assert_fail = True

    if 'code' in root.attrib:
        code = root.attrib['code']
    else:
        code = os.path.splitext(os.path.basename (inpath))[0]

    mdg  = nx.MultiDiGraph()
    G    = Graph (mdg, code, assert_fail)

    # read in graph
    for child in root.iterchildren(tag = etree.Element):

        name  = child.attrib["id"]

        descnode = child.find('description')
        if descnode is not None:
            desc = "<" + child.tag + ":&#10;" + re.sub ('\n\s*', '&#10;', descnode.text.strip()) + ">"
        else:
            warn ("No description for " + name)
            desc = "<No description&#10;available.>"

        controlled = set()
        arguments = []
        for element in child.findall('arg'):
            argname = element.attrib['name']
            arguments.append (argname)
            if parse_bool (element.attrib, 'controlled'):
                controlled.add (argname)

        classname = child.attrib['code'] if 'code' in child.attrib else None
        config    = child.find('config')

        mdg.add_node \
            (name, \
             guarantees = parse_guarantees (child.attrib), \
             kind       = child.tag, \
             classname  = classname, \
             config     = config, \
             tooltip    = desc, \
             arguments  = arguments,
             controlled = controlled,
             style      = "bold", \
             penwidth   = "2", \
             width      = "2.5", \
             height     = "0.6")

        for element in child.findall('flow'):
            sarg = element.attrib['sarg']
            darg = element.attrib['darg']

            assert_c = None
            assert_i = None

            for assertion in element.findall('assert'):
                assert_c = parse_bool (assertion.attrib, 'confidentiality')
                assert_i = parse_bool (assertion.attrib, 'integrity')

            mdg.add_edge (name, element.attrib['sink'], \
                sarg = sarg, \
                darg = darg, \
                assert_c = assert_c, \
                assert_i = assert_i, \
                labelfontsize = "7", \
                labelfontcolor="black", \
                arrowhead="vee", \
                labelfontname="Sans-Serif", \
                labeljust="r", \
                penwidth="2")

    # Initialize all objects
    for node in mdg.node:

        for arg in mdg.node[node]['arguments']:
            found = False
            for (parent, child, data) in mdg.in_edges (nbunch=node, data=True):
                if arg == data['darg']:
                    found = True
                    break
            if not found:
                raise MissingIncomingEdge (node, arg)

        if mdg.node[node]['kind'] == "xform":
            if not mdg.in_edges (nbunch=node):
                raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], "No inputs")
            if not mdg.out_edges (nbunch=node):
                raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], "No outputs")

        objname = "Primitive_" + mdg.node[node]['kind']
        try:
            mdg.node[node]['primitive'] = globals()[objname](G, node)
            mdg.node[node]['primitive'].prove(SPG_Solver())
        except KeyError:
            raise PrimitiveMissing (mdg.node[node]['kind'], node)
        except AttributeError as e:
            raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], str(e))

    # Check arguments
    for node in mdg.node:
        iargs = set(())
        for (parent, child, data) in mdg.in_edges (nbunch=node, data=True):
            if data['darg'] in iargs:
                raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], "Duplicate input argument '" + data['darg'] + "'")
            iargs.add (data['darg'])
        oargs = set(())
        for (parent, child, data) in mdg.out_edges (nbunch=node, data=True):
            if data['sarg'] in oargs:
                raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], "Duplicate output argument '" + data['sarg'] + "'")
            oargs.add (data['sarg'])

    for (parent, child, data) in mdg.edges (data=True):
        darg = data['darg']
        if mdg.node[child]['kind'] == "xform":
            if not darg in mdg.node[child]['arguments']:
                raise PrimitiveInvalidAttributes (child, mdg.node[child]['kind'], "Non-existing interface '" + darg + "' referenced by '" + parent + "'")

    info (str(len(mdg.node)) + " nodes.")
    return G

def set_style (o, c, i):

    #if c == None or i == None:
    #    o['style'] = "dashed"

    if (c and i):
        o['color'] = "purple"
    elif not c and not i:
        o['color'] = "black"
    elif c:
        o['color'] = "red"
    elif i:
        o['color'] = "blue"
    else:
        o['color'] = "orange"

    o['fillcolor'] = o['color']

def dump_primitive_rules():
    for primitive_class in Primitive.__subclasses__():

        name = primitive_class.__name__[10:]

        # FIXME: This does not work as long as the primitive
        # structure is constructed from the config file.
        mdg = nx.DiGraph()
        mdg.add_node (name, guarantees = None, kind = name)

        G = Graph (mdg, "dump", False)
        P = primitive_class (G, name)

def main():

    # Add directory containing our model to search path so we can find the
    # local library there
    sys.path.append (dirname(args.input[0]))

    # Read in graph
    G = parse_graph (args.input[0])

    if args.initial:
        G.label()
        G.write ("initial_" + args.output[0])
      
    solved = G.analyze(args.dump_rules)
    G.label()

    #if args.dump_rules:
    #    dump_primitive_rules()

    libspg.exitval = 0
    if solved:
        G.partition(args.cluster)
        if args.run:
            G.run()
    G.write (args.output[0])

    G.statistics()

    sys.exit (libspg.exitval if solved else 1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPG Analyzer')
    parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
    parser.add_argument('--dump', action='store_true', help='Dump rules', dest='dump_rules');
    parser.add_argument('--test', action='store_true', help='Run in test mode', dest='test');
    parser.add_argument('--cluster', action='store_true', help='Cluster graph output', dest='cluster');
    parser.add_argument('--initial', action='store_true', help='Write graph prior to analysis', dest='initial');
    parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');
    parser.add_argument('--run', action='store_true', required=False, help='Run model', dest='run');
    parser.add_argument('--verbose', action='store_true', required=False, help='Verbose output', dest='verbose');

    try:
        args = parser.parse_args ()
        if args.test or args.run and not args.verbose:
            libspg.quiet = 1
        main()
    except PrimitiveMissing as e:
        warn (e)
    except (PrimitiveInvalidAttributes, InconsistentRule, PrimitiveNotImplemented) as e:
        err (e)
        sys.exit (1)
