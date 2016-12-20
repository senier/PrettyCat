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

<xs:complexType name="envElement">
    <xs:complexContent>
        <xs:extension base="baseElement">
            <xs:sequence minOccurs="1" maxOccurs="unbounded">
                <xs:choice>
                    <xs:element name="flow" type="flowElement"/>
                    <xs:element name="arg" type="argElement"/>
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
            <xs:element name="env"             type="envElement">
                <xs:unique name="EnvUniqueSourceArg">
                    <xs:selector xpath="./flow" />
                    <xs:field xpath="@sarg"/>
                </xs:unique>
            </xs:element>
            <xs:element name="xform"           type="xformElement">
                <xs:unique name="XformUniqueSourceArg">
                    <xs:selector xpath="./flow" />
                    <xs:field xpath="@sarg"/>
                </xs:unique>
            </xs:element>
            <xs:element name="branch"          type="forwardElement">
                <xs:unique name="ForwardUniqueSourceArg">
                    <xs:selector xpath="./flow" />
                    <xs:field xpath="@sarg"/>
                </xs:unique>
            </xs:element>
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

def mark_partition (G, node, partition):

    # Partition already set
    if 'partition' in G.node[node]:
        return False

    G.node[node]['partition'] = partition

    # Partition towards parents
    for (parent, child) in G.in_edges (nbunch=node):
        if G.node[parent]['primitive'].guarantees['c'] == G.node[node]['primitive'].guarantees['c'] and \
           G.node[parent]['primitive'].guarantees['i'] == G.node[node]['primitive'].guarantees['i']:
            mark_partition (G, parent, partition)

    # Partition towards children
    for (parent, child) in G.out_edges (nbunch=node):
        if G.node[child]['primitive'].guarantees['c'] == G.node[node]['primitive'].guarantees['c'] and \
           G.node[child]['primitive'].guarantees['i'] == G.node[node]['primitive'].guarantees['i']:
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

        # Create primitive objects
        for node in graph.nodes():

            attrs = { \
               'inputs'     : [ data['darg'] for (unused1, unused2, data) in graph.in_edges (nbunch = node, data = True) ], \
               'arguments'  : graph.node[node]['arguments'], \
               'outputs'    : graph.node[node]['outputs'], \
               'controlled' : graph.node[node]['controlled'], \
               'config'     : graph.node[node]['config'], \
               'guarantees' : graph.node[node]['guarantees'] }

            objname = "Primitive_" + graph.node[node]['kind']

            try:
                primitive = globals()[objname](self, node, attrs)
                primitive.prove(SPG_Solver())
            except AttributeError as e:
                raise PrimitiveInvalidAttributes (node, kind, str(e))

            graph.node[node]['primitive'] = primitive

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
            label = "<<b>" + G.node[node]['kind'] + ": </b>" + node + "<font point-size=\"6\"><sub> (" + str(G.node[node]['partition']) + ")</sub></font>>"
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

            if G.node[node]['kind'] == "env":
                G.node[node]['shape'] = "invhouse"
            else:
                G.node[node]['shape'] = "rectangle"

            G.node[node]['label'] = "<<b>" + G.node[node]['kind'] + ": </b>" + node + ">"
            val_c = False
            val_i = False

            if G.node[node]['primitive'].guarantees != None:
                val_c = G.node[node]['primitive'].guarantees['c']
                val_i = G.node[node]['primitive'].guarantees['i']

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
            G.node[node]['primitive'].guarantees['c'] = val_c
            G.node[node]['primitive'].guarantees['i'] = val_i

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

            if kind == "env" or kind == "output" or kind == "xform":
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

            classobj = libclass (node, G.node[node]['primitive'].config, G.node[node]['primitive'].attributes)
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

            G.node[node]['class'].set_sendmethods (sendmethods)

        for node in G.node:
            G.node[node]['class'].setDaemon (True)
            G.node[node]['class'].start ()

        # join all threads
        for node in G.node:
            G.node[node]['class'].join ()

class Args:

    def __init__ (self, name):
        raise Exception ("Abstract")

    def setup (self, name):
        self._name   = name

    def add_guarantee (self, name):
        self.__dict__.update (**{name: Guarantees (self._name + "_" + name)})

    def guarantees (self):
        return { k: v for k, v in self.__dict__.items() if not k.startswith("_") }

class Input_Args (Args):

    def __init__ (self, name):
        super().setup (name + "_input")

class Output_Args (Args):

    def __init__ (self, name):
        super().setup (name + "_output")

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

    def __init__ (self, name):
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

    def setup (self, name, G, attributes, interfaces = { 'inputs': None, 'outputs': None} ):

        self.input  = Input_Args (name)
        self.output = Output_Args (name)
        self.name   = name
        self.rule   = []
        self.G = G

        self.attributes = attributes
        self.guarantees = attributes['guarantees']
        self.config     = attributes['config']
        self.inputs     = attributes['inputs']
        self.outputs    = attributes['outputs']
        self.arguments  = attributes['arguments']

        if interfaces['inputs'] == None:
            for arg in self.inputs:
                self.input.add_guarantee (arg)
        else:
            for in_if in interfaces['inputs']:
                self.input.add_guarantee (in_if)

            if self.inputs:
                missing_args = set(interfaces['inputs']) - set(self.inputs)
                excess_args = set(self.inputs) - set(interfaces['inputs'])

                if missing_args and excess_args: raise MissingAndExcessIncomingEdges (name, missing_args, excess_args)
                if missing_args:                 raise MissingIncomingEdges (name, missing_args)
                if excess_args:                  raise ExcessIncomingEdges (name, excess_args)

        if interfaces['outputs'] == None:
            for arg in self.outputs:
                self.output.add_guarantee (arg)
        else:
            for out_if in interfaces['outputs']:
                self.output.add_guarantee (out_if)

            if self.outputs:
                missing_args = set(interfaces['outputs']) - set(self.outputs)
                excess_args = set(self.outputs) - set(interfaces['outputs'])

                if missing_args and excess_args: raise MissingAndExcessOutgoingEdges (name, missing_args, excess_args)
                if missing_args:                 raise MissingOutgoingEdges (name, missing_args)
                if excess_args:                  raise ExcessOutgoingEdges (name, excess_args)


    def populate (self, solver):
        solver.assert_and_track (And (self.rule), "RULE_" + self.name)

    def prove (self, solver):
        self.populate (solver)
        if solver.check() != sat:
            raise PrimitiveInvalidRule (self.__class__.__name__, self.name)
        del solver

class Primitive_env (Primitive):
    """
    The env primitive

    Denotes one source/sink outside the model. Fixed guarantees are defined here.
    """

    def __init__ (self, G, name, attributes):
        super ().setup (name, G, attributes)

        for (current, child, data) in G.graph.out_edges (nbunch=name, data=True):
            self.output.add_guarantee (data['sarg'])

        for (parent, current, data) in G.graph.in_edges (nbunch=name, data=True):
            self.input.add_guarantee (data['darg'])

        for (name, ig) in self.input.guarantees().items():
            if self.guarantees['c'] != None:
                self.rule.append (Conf (ig) == self.guarantees['c'])
            if self.guarantees['i'] != None:
                self.rule.append (Intg (ig) == self.guarantees['i'])

        for (name, og) in self.output.guarantees().items():
            if self.guarantees['c'] != None:
                self.rule.append (Conf (og) == self.guarantees['c'])
            if self.guarantees['i'] != None:
                self.rule.append (Intg (og) == self.guarantees['i'])

class Primitive_xform (Primitive):
    """
    The xform primitive

    This mainly identifies sources and sinks and sets the fixed
    guarantees according to the XML definition.
    """

    def __init__ (self, G, name, attributes):
        super ().setup (name, G, attributes)

        for (parent, current, data) in G.graph.in_edges (nbunch=name, data=True):
            self.input.add_guarantee (data['darg'])

        for (current, child, data) in G.graph.out_edges (nbunch=name, data=True):
            self.output.add_guarantee (data['sarg'])

        # Input from a source lacking integrity guarantees can influence
        # any output of an xform in undetermined ways. Hence, integrity
        # guarantees cannot be maintained for any output interface.
        #
        # Integrity can be maintained if the input interfaces is
        # controlled by the xform implementation, i.e. it is guaranteed
        # that it can influence the output only in well-defined ways
        # (permutation, fixed output position).
        #
        # (Intg(output_if) ⇒ Intg(input_if)) ∨ Controlled (input_if)

        for (in_name, input_if) in self.input.guarantees().items():
            input_if_rules = []
            for (out_name, output_if) in self.output.guarantees().items():
                input_if_rules.append (Or (Implies (Intg(output_if), Intg(input_if)), in_name in attributes['controlled']))
            self.rule.append (And (input_if_rules))

        # Input from a source demanding confidentiality guarantees can
        # influence any output of an xform in undetermined ways. Hence,
        # confidentiality must be guaranteed by all output interfaces.
        #
        #   Conf(input_if) -> Conf(output_if)
        for (out_name, output_if) in self.output.guarantees().items():
            output_if_rules = []
            for (in_name, input_if) in self.input.guarantees().items():
                output_if_rules.append (Implies (Conf(input_if), Conf(output_if)))
            self.rule.append (And (output_if_rules))

class Primitive_branch (Primitive):
    """
    The branch primitive

    Copy the input parameter into all output parameters.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data'], 'outputs': None }
        super ().setup (name, G, attributes, interfaces)

        for (current, child, data) in G.graph.out_edges (nbunch=name, data=True):
            self.output.add_guarantee (data['sarg'])

        # If integrity is guaranteed for some output, then integrity
        # must be guaranteed for the input, too.
        for (out_name, out_g) in self.output.guarantees().items():
            self.rule.append (Implies (Intg(out_g), Intg(self.input.data)))

        # If confidentiality is guaranteed for the input, then integrity
        # must be guaranteed for all outputs, too.
        output_conf_rules = []
        for (out_name, out_g) in self.output.guarantees().items():
            output_conf_rules.append (Implies (Conf(self.input.data), Conf(out_g)))

        self.rule.append (And (output_conf_rules))

class Primitive_const (Primitive):
    """
    The const primitive
    """

    def __init__ (self, G, name, attributes):
        interfaces = { 'inputs': [], 'outputs': ['const'] }
        super ().setup (name, G, attributes, interfaces)

        # Guarantees explicitly set in the XML
        og = self.output.guarantees()['const']
        if self.guarantees['c'] != None:
            self.rule.append (Conf (og) == self.guarantees['c'])
        else:
            self.rule.append (Conf(self.output.const))

class Primitive_rng (Primitive):
    """
    Primitive for a true (hardware) random number generator

    This RNG is not seeded. It has an input parameter len, determining how
    many bits we request from it.
    """

    def __init__ (self, G, name, attributes):
        interfaces = { 'inputs': ['len'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        # input.len: If an attacker can choose the length requested from an RNG,
        # too short keys would be generated.
        self.rule.append (Intg(self.input.len))

        # output.data: We assume that this RNG is always used to produce keys which
        # need to be confidential.
        self.rule.append (Conf (self.output.data))

        # Discussion:
        # If required, we can introduce a nonce generator later which does not imply
        # confidentiality guarantees for its output. The RNG # should be safe, as the
        # worst thing that may happen is that confidentiality is required unnecessarily.
        # Most likely this will result in a conflict in nonce case, as those are
        # typically passed to domains without confidentiality guarantees.

class Primitive_dhpub (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['modulus', 'generator', 'psec'], 'outputs': ['pub'] }
        super ().setup (name, G, attributes, interfaces)

        # Parameters are public, but an attacker may not chose a weak ones.
        # Hence, integrity must be guaranteed
        self.rule.append (And (Intg(self.input.modulus), Intg(self.input.generator)))

        # With knowledge of g^y and psec_in (x in DH terms) an attacker can
        # calculate the shared secret g^y^x
        self.rule.append (Conf(self.input.psec))

        # If an attacker can choose psec_in (x in DH terms) and knows g^y,
        # she can calculate the shared secret g^yx
        self.rule.append (Intg(self.input.psec))

        # Being able to transmit g^x over an non-confidential channel is the
        # sole purpose of the DH key exchange, given that x has
        # confidentiality and integrity guarantees
        self.rule.append (Or (Conf(self.output.pub), And (Conf(self.input.psec), Intg(self.input.psec))))

class Primitive_dhsec (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['modulus', 'generator', 'pub', 'psec'], 'outputs': ['ssec'] }
        super ().setup (name, G, attributes, interfaces)

        # With knowledge of pub (g^y) and psec_in (x) an attacker can
        # calculate ssec (the shared secret g^yx ≡ g^xy)
        self.rule.append (Conf(self.input.psec))

        # If the shared secret shall be confidential, then psec must not be chosen
        # by an attacker
        self.rule.append (Intg(self.input.psec))

        # No weak parameters must be chosen by an attacker
        self.rule.append (Intg(self.input.modulus))
        self.rule.append (Intg (self.input.generator))

        # Confidentiality must be guaranteed for shared secret
        self.rule.append (Conf(self.output.ssec))

class Primitive_encrypt (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['plaintext', 'key', 'ctr'], 'outputs': ['ciphertext'] }
        super ().setup (name, G, attributes, interfaces)

        # Counter mode encryption does not achieve integrity, hence an attacker
        # can could change plaintext_in to influence the integrity of
        # ciphertext_out. If integrity must be guaranteed for ciphertext_out,
        # it also must be guaranteed for plaintext_in.
        self.rule.append (Implies (Intg(self.output.ciphertext), Intg(self.input.plaintext)))

        # If plaintext_in is known to an attacker (i.e. not confidential), it
        # is superfluous to guarantee confidentiality for key_in.
        # If ciphertext_out requires confidentiality, the confidentiality of
        # pt_in is guaranteed even if key_in is known to an attacker.
        self.rule.append (Or (Conf(self.input.key), Not (Conf(self.input.plaintext)), Conf(self.output.ciphertext)))

        # Integrity of input key must always be guaranteed
        self.rule.append (Intg (self.input.key))

        # If no confidentiality is guaranteed for plaintext_in in the first
        # place, it is superfluous to encrypt (and hence chose unique counter
        # values). If confidentiality is guaranteed for ciphertext_out,
        # encryption is not necessary. Hence, a ctr_in chose by an attacker
        # does no harm.
        self.rule.append (Or (Intg(self.input.ctr), Not (Conf(self.input.plaintext)), Conf(self.output.ciphertext)))

        # If confidentiality and integrity is guaranteed for the key and
        # integrity is guaranteed for ctr (to avoid using the same key/ctr
        # combination twice), an attacker cannot decrypt the ciphertext and
        # thus no confidentiality needs to be guaranteed by the environment.
        self.rule.append (Or (Conf(self.output.ciphertext), And (Conf(self.input.key), Intg(self.input.key), Intg(self.input.ctr))))

class Primitive_encrypt_ctr (Primitive_encrypt):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['plaintext', 'key', 'ctr'], 'outputs': ['ciphertext', 'ctr'] }
        super ().setup (name, G, attributes, interfaces)

        # If integrity is guaranteed for output counter, integrity must be guaranteed for initial counter
        self.rule.append (Implies (Intg(self.output.ctr), Intg(self.input.ctr)))

        # If confidentiality is guaranteed for initial counter, confidentiality must be guaranteed for output counter
        self.rule.append (Implies (Conf(self.input.ctr), Conf(self.output.ctr)))

class Primitive_decrypt (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['ciphertext', 'key', 'ctr'], 'outputs': ['plaintext'] }
        super ().setup (name, G, attributes, interfaces)

        # If the plaintext is confidential, the key must be confidential, too.
        # FIXME: What happens when an attacker can chose a key for decryption?
        self.rule.append (Implies (Conf(self.output.plaintext), Conf(self.input.key)))

class Primitive_hash (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data'], 'outputs': ['hash'] }
        super ().setup (name, G, attributes, interfaces)

        # Using a cryptographically secure hash makes no sense with non-integer data.
        self.rule.append (Intg(self.input.data))

        #   Even with a cryptographically secure hash function, an attacker
        #   may be able to recover data_in from hash_out, depending on the
        #   resource available and the structure of data_in. As we don't want
        #   to get probabilistic here, we just assume this is always possible.
        #   FIXME: It may become hard to cope with protocols where the
        #   infeasibility of reversing the hash is used, e.g. password
        #   authentication.
        self.rule.append (Implies (Conf(self.input.data), Conf(self.output.hash)))

class Primitive_hmac (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['key', 'msg'], 'outputs': ['auth'] }
        super ().setup (name, G, attributes, interfaces)

        # If integrity is not guaranteed for the input data, HMAC cannot
        # protect anything. Hence, it does not harm if the key is released
        # to or chosen by an attacker.
        self.rule.append (Conf(self.input.key))
        self.rule.append (Intg(self.input.key))

        # We assume that an HMAC component is only used when integrity must
        # be guaranteed for the msg_in.
        self.rule.append (Intg (self.input.msg))

class Primitive_hmac_out (Primitive_hmac):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['key', 'msg'], 'outputs': ['auth', 'msg'] }
        super ().setup (name, G, attributes, interfaces)

        # HMAC does not achieve confidentiality.
        self.rule.append (Implies (Conf(self.input.msg), Conf(self.output.msg)))

class Primitive_sign (Primitive):

    """
    The sign primitive

    Creates an asymmetric digital signature for a message using a given set of
    public and secret keys.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'pubkey', 'privkey', 'rand'], 'outputs': ['auth'] }
        super ().setup (name, G, attributes, interfaces)

        # The private key must stay confidential
        self.rule.append (Conf (self.input.privkey))

        # An attacker must not chose the private key
        self.rule.append (Intg (self.input.privkey))

        # An attacker must not chose the public key
        self.rule.append (Intg (self.input.pubkey))

        # Random number x must be confidential and not chosen by attacker
        self.rule.append (Intg (self.input.rand))
        self.rule.append (Conf (self.input.rand))

        # Even with a cryptographically secure hash function, an attacker
        # may be able to recover data_in from auth_out, depending on the
        # resource available and the structure of msg_in. As we don't want
        # to get probabilistic here, we just assume this is always possible.
        self.rule.append (Implies (Conf(self.input.msg), Conf(self.output.auth)))

class Primitive_verify_sig (Primitive):

    """
    The signature verification primitive

    Checks whether an auth value represents a valid message signature by a given public key.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'auth', 'pubkey'], 'outputs': ['result'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can modify the result of a verify operation, she could
        # as well chose an own public key for which she has the secret key available
        # (and thus can create a valid signature yielding a positive result)
        self.rule.append (Intg(self.input.pubkey))

        # If confidentiality is to be guaranteed for msg, this may also apply for
        # the fact whether it was signed with pubkey.
        self.rule.append (Implies (Conf(self.input.msg), Conf(self.output.result)))

class Primitive_verify_hmac (Primitive):

    """
    HMAC verification primitive

    Checks whether a given pair (msg, auth) was MAC'ed with key.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'auth', 'key'], 'outputs': ['result'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can modify the result of a verify operation, she could
        # as well chose an own key and use it to create a valid signature yielding
        # a positive result
        self.rule.append (Implies (Intg(self.output.result), And (Conf(self.input.key), Intg(self.input.key))))


        # If the input message is confidential, the result is confidential, too.
        self.rule.append  (Implies (Conf(self.input.msg), Conf(self.output.result)))

class Primitive_verify_hmac_out (Primitive_verify_hmac):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'auth', 'key'], 'outputs': ['msg'] }
        super ().setup (name, G, attributes, interfaces)

        #   The HMAC does not achieve confidentiality.
        self.rule.append (Implies (Conf(self.input.msg), Conf(self.output.msg)))

class Primitive_guard (Primitive):

    """
    Guard primitive

    This primitive guards the control the data flow in a protocol. Input data is
    only transferred to the output interfaces if the condition on the input interfaces is
    true.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data', 'cond'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        # Guard does nothing to integrity.
        self.rule.append (Implies (Intg(self.output.data), Intg(self.input.data)))

        #   Guard can be used to coordinate protocol steps, e.g. to send a reply
        #   only if the signature of a previous message was OK. Hence, the
        #   integrity requirements are at protocol level and cannot be derived
        #   from the primitive (or other primitives)
        #   FIXME: Is it true we cannot derive it from primitives? Should we make this configurable then?
        self.rule.append (Intg (self.input.cond))

        # Guard does nothing to confidentiality.
        self.rule.append (Implies (Conf(self.input.data), Conf(self.output.data)))

class Primitive_release (Primitive):

    """
    Release primitive

    This primitive allows to drop all security guarantees.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        self.rule.append (True)

class Primitive_comp (Primitive):

    """
    Comp primitive

    This primitive compares two arbitrary inputs and outputs a boolean value
    indicating whether both inputs were identical or not.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data1', 'data2'], 'outputs': ['result'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can chose data1_in, she can influence the integrity
        # of result_out (at least, make result_out false with a very high
        # likelihood by choosing a random value for data1_in)
        self.rule.append (Implies (Intg(self.output.result), Intg(self.input.data1)))

        # If an attacker can chose data2_in, she can influence the integrity
        # of result_out (at least, make result_out false with a very high
        # likelihood by choosing a random value for data2_in)
        self.rule.append (Implies (Intg(self.output.result), Intg(self.input.data2)))

        # If an attacker knows data1 and data2 she can derive result_out by comparing both values
        # FIXME: Need both input values be confidential or is confidentiality for on input sufficient
        # (we assume the latter right now)
        self.rule.append (Implies (Conf(self.output.result), Or (Conf (self.input.data1), Conf (self.input.data2))))

class Primitive_verify_commit (Primitive):
    """
    Primitive for a verifying a commitment.

    This primitives verifies a commitment using a cryptographic hash function. It
    takes a hash value h and a data value d. If the hash value is received prior to
    the data value and the hash(d) == h, then the primitive outputs d.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data', 'hash'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can chose input data, she may change the output data.
        self.rule.append (Implies (Intg(self.output.data), Intg(self.input.data)))

        # If input data is confidential, confidentiality must be guaranteed for output data
        self.rule.append (Implies (Conf(self.input.data), Conf(self.output.data)))

class Primitive_latch (Primitive):

    """
    Latch primitive

    This primitive receives a value (potentially without any guarantees) and outputs
    it unmodified. It guarantees that after receiving a value once it cannot be changed anymore.
    Additionally it has a trigger output signaling that data was received.

    Rationale: This is used for commitment schemes where we open a commitment only after
    we received a peers (immutable) value.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data'], 'outputs': ['data', 'trigger'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can chose input data, she may change the output data.
        self.rule.append (Implies (Intg(self.output.data), Intg(self.input.data)))

        # If input data is confidential, confidentiality must be guaranteed for output data
        self.rule.append (Implies (Conf(self.input.data), Conf(self.output.data)))

        # The purpose of the latch primitive is to open a commitment. If it triggers too early,
        # this may happen before the peer has committed to a value. Hence, the trigger value
        # requires integrity guarantees.
        self.rule.append (Intg (self.output.trigger))

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

    # read in graph
    for child in root.iterchildren(tag = etree.Element):

        name  = child.attrib["id"]

        descnode = child.find('description')
        if descnode is not None:
            desc = "<" + child.tag + ":&#10;" + re.sub ('\n\s*', '&#10;', descnode.text.strip()) + ">"
        else:
            warn ("No description for " + name)
            desc = "<No description&#10;available.>"

        kind       = child.tag
        classname  = child.attrib['code'] if 'code' in child.attrib else None

        config     = child.find('config')
        guarantees = parse_guarantees (child.attrib)

        mdg.add_node \
            (name, \
             kind       = kind, \
             classname  = classname, \
             config     = config, \
             guarantees = guarantees, \
             arguments  = [ arg.attrib['name'] for arg in child.findall('arg')],
             controlled = [ arg.attrib['name'] for arg in child.findall('arg') if 'controlled' in arg.attrib],
             outputs    = [ arg.attrib['sarg'] for arg in child.findall('flow')],
             tooltip    = desc, \
             style      = "bold", \
             penwidth   = "2", \
             width      = "2.5", \
             height     = "0.6")

        for element in child.findall('flow'):
            sarg       = element.attrib['sarg']
            darg       = element.attrib['darg']

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

    info (str(len(mdg.node)) + " nodes.")
    return Graph (mdg, code, assert_fail)

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

def latex_expression (prefix, exp):

    result = ""
    na = exp.num_args()

    if is_and (exp):
        for idx in range (0, na):
            if idx != 0:
                result += "\land{}"
            result += latex_expression (prefix, exp.arg(idx))
    elif is_or (exp):
        if na > 1: result += "("
        for idx in range (0, na):
            if idx != 0:
                result += "\lor{}"
            result += latex_expression (prefix, exp.arg(idx))
        if na > 1: result += ")"
    elif is_eq(exp):
        result += latex_expression (prefix, exp.arg(0))
        result += " ≡ "
        result += latex_expression (prefix, exp.arg(1))
    elif is_not(exp):
        result += latex_expression (prefix, exp.arg(0))
    elif is_const(exp):

        var = str(exp)

        if var == "True" or var == "False":
            result += var
        else:
            # demangle variable name
            intg   = False
            conf   = False
            invar  = False
            outvar = False

            if not var.startswith (prefix + "_"):
                raise Exception ("Invalid variable " + var + ": does not start with prefix " + prefix)
            var = var[len(prefix)+1:]

            if var.endswith ("_intg"):
                intg = True
            elif var.endswith ("_conf"):
                conf = True
            else:
                raise Exception ("Invalid variable " + var + ": neither integrity nor confidentiality")
            var = var[:-5]

            if var.startswith ("input_"):
                invar = True
                var = var[6:]
            elif var.startswith ("output_"):
                outvar = True
                var = var[7:]
            else:
                raise Exception ("Invalid variable " + var + ": neither input nor output")

            var = "\\text{" + var + "}"

            if invar:  var = "\\invar{" + var + "}"
            if outvar: var = "\\outvar{" + var + "}"

            if intg: var = "\\intg{" + var + "}"
            if conf: var = "\\conf{" + var + "}"

            result += var

    elif exp == None:
        result += "\Downarrow"
    else:
        raise Exception ("Unhandled expression: " + str(exp))

    return result

def dump_primitive_rules (filename):

    with open (filename, 'w') as outfile:
        for primitive_class in Primitive.__subclasses__():
            name = primitive_class.__name__[10:]
            if not name in ['env', 'xform', 'const', 'branch']:
                p = primitive_class (None, name, { 'guarantees': None, 'config': None, 'inputs': None, 'outputs': None, 'arguments': None})
                n = name.replace ("_", '') 
                outfile.write ("\\newcommand{\\" + n + "rule}{\\text{rule}_{\\text{" + n + "}} = " + \
                    latex_expression(name, simplify (And (p.rule))) + "}" + "\n")

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

    if args.dump_latex:
        dump_primitive_rules(args.dump_latex[0])

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
    parser.add_argument('--latex', action='store', nargs=1, required=False, help='Store rules as latex file', dest='dump_latex');
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
