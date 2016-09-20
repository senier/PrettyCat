#!/usr/bin/env python3

import sys
import argparse
import subprocess
import os
import re
import pydot
import json

from io   import StringIO
from lxml import etree

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx
from networkx.readwrite import json_graph

# TODO: Check for excess output parameters in fixed primitives

schema_src = StringIO ('''<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">

<xs:complexType name="flowElement">
    <xs:attribute name="sarg" use="required" />
    <xs:attribute name="sink" use="required" />
    <xs:attribute name="darg" use="required" />
    <xs:attribute name="assert_c" type="xs:boolean" />
    <xs:attribute name="assert_i" type="xs:boolean" />
</xs:complexType>

<xs:complexType name="argElement">
    <xs:attribute name="name" use="required" />
</xs:complexType>

<xs:complexType name="baseElement">
    <xs:sequence>
        <xs:element name="description" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:attribute name="id" use="required" />
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
        </xs:extension>
    </xs:complexContent>
</xs:complexType>

<xs:complexType name="envElement">
    <xs:complexContent>
        <xs:extension base="xformElement">
            <xs:attribute name="confidentiality" type="xs:boolean"/>
            <xs:attribute name="integrity" type="xs:boolean"/>
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
            <xs:element name="env"             type="envElement"/>
            <xs:element name="xform"           type="xformElement"/>
            <xs:element name="branch"          type="forwardElement"/>
            <xs:element name="const"           type="forwardElement"/>
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
            <xs:element name="guard"           type="forwardElement"/>
            <xs:element name="release"         type="forwardElement"/>
            <xs:element name="comp"            type="forwardElement"/>
            <xs:element name="scomp"           type="forwardElement"/>
            <xs:element name="verify_commit"   type="forwardElement"/>
            <xs:element name="layout"          type="forwardElement"/>
            <xs:element name="counter"         type="forwardElement"/>
            <xs:element name="latch"           type="forwardElement"/>
        </xs:choice>
    </xs:sequence>
    <xs:attribute name="assert_fail" type="xs:boolean" />
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

def warn (message):
    print ("[1m[35mWARNING: [2m" + str(message) + "[0m")

def info (message):
    if not args.test:
        print ("[1m[34mINFO: [2m" + str(message) + "[0m")

def err (message):
    print ("[1m[31mERROR: [2m" + str(message) + "[0m")

class PrimitiveMissing (Exception):
    def __init__ (self, kind, name):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") not implemented")

class PrimitiveInvalidAttributes (Exception):
    def __init__ (self, name, kind, text):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") has invalid attributes: " + text)

class InconsistentRule(Exception):
    def __init__ (self, rule, text):
        Exception.__init__(self, "Rule '" + rule + "': " + text)

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

    def __init__ (self, graph, fail):
        self.graph    = graph
        self.fail     = fail
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

            if self.fail:
                err ("Failure expected, but solution found");
                return False

            info ("Solution found")

            # Check assertions
            return self.check_assertions()

        else:
            solver.mark_unsat_core(self.graph)

            # We expect a failure - exit without error
            if self.fail:
                return True

            err ("No solution")
            return False

    def partition (self):

        G = self.graph

        partitions = {}
        partition_no = 1

        for node in G.node:
            new_partition = mark_partition (G, node, partition_no)
            if new_partition:
                partitions[str(partition_no)] = pydot.Subgraph (graph_name = "cluster_" + str(partition_no), label = "partition " + str(partition_no), penwidth = 2, bgcolor = "gray80")
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

            if G.node[node]['kind'] == "env":
                G.node[node]['shape'] = "invhouse"
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
        self.conf  = None
        self.intg  = None

        # Z3 variables representing confidentiality and
        # integrity within the solver. These values are
        # used in the rules.
        self.__c   = Bool(name + "_conf")
        self.__i   = Bool(name + "_intg")

        # The actual boolean value. This is filled in from
        # a valid model found by the solver
        self.__val_c = None
        self.__val_i = None

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
            solver.assert_and_track (ig[g].conf, "RULE_" + self.name + "_" + g + "_input_conf")
            solver.assert_and_track (ig[g].intg, "RULE_" + self.name + "_" + g + "_input_intg")
        og = self.output.guarantees()
        for g in og:
            solver.assert_and_track (og[g].conf, "RULE_" + self.name + "_" + g + "_output_conf")
            solver.assert_and_track (og[g].intg, "RULE_" + self.name + "_" + g + "_output_intg")

class Primitive_env (Primitive):
    """
    The env primitive

    Denotes sources and sinks outside the model. Fixed guarantees according to the
    XML definition are used only here.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Guarantees explicitly set in the XML
        g = self.node['guarantees']

        for (name, ig) in self.input.guarantees().items():
            if g['c'] != None:
                ig.conf = (Conf (ig) == g['c'])
            if g['i'] != None:
                ig.intg = (Intg (ig) == g['i'])

        for (name, og) in self.output.guarantees().items():
            if g['c'] != None:
                og.conf = (Conf (og) == g['c'])
            if g['i'] != None:
                og.intg = (Intg (og) == g['i'])

class Primitive_xform (Primitive):
    """
    The xform primitive

    This mainly identifies sources and sinks and sets the fixed
    guarantees according to the XML definition.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

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
        #   ∃out_i ⇒ ∀in_j
        for (out_name, out_g) in self.output.guarantees().items():
            for (in_name, in_g) in self.input.guarantees().items():
                in_g.intg = Implies (Intg(out_g), Intg(in_g))

        # Parameter
        #   All output interfaces
        # Confidentiality guarantee can be dropped if:
        #   No input interface demands confidentiality
        # Reason:
        #   Input from a source demanding confidentiality guarantees can
        #   influence any output of an xform in undetermined ways. Hence,
        #   confidentiality must be guaranteed by all output interfaces.
        # Assertion:
        #   in_c -> out_c
        for (in_name, in_g) in self.input.guarantees().items():
            for (out_name, out_g) in self.output.guarantees().items():
                out_g.conf = Implies (Conf(in_g), Conf(out_g))

        # Parameter
        #   All output interfaces
        # Integrity guarantee can be dropped if:
        #   No input interface demands integrity
        # Reason:
        #   FIXME: If any input interfaces guarantees integrity, we also need to guarantee
        #   for outgoing data.
        # Assertion:
        #   in_i -> out_i
        # Assertion:
        #for (in_name, in_g) in self.input.guarantees().items():
        #    for (out_name, out_g) in self.output.guarantees().items():
        #        self.assert_and_track (Implies (in_g.i, out_g.i), in_name + "_" + out_name + "_i")

class Primitive_branch (Primitive):
    """
    The branch primitive

    Copy the input parameter into all output parameters.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        if len(self.input.guarantees().items()) > 1:
            raise PrimitiveInvalidAttributes (name, "branch", "More than one input parameters")

        # Parameters
        #   Inputs:  data
        #   Outputs: data_1..data_n

        for (out_name, out_g) in self.output.guarantees().items():
            out_g.conf = (Conf(out_g) == Conf(self.input.data))
            out_g.intg = (Implies (Intg(out_g), Intg(self.input.data)))

class Primitive_layout (Primitive):
    """
    The layout primitive

    This primitive controls the layout of an output message. Input may either
    be controlled (i.e. with integrity guarantees) or uncontrolled. The latter
    input has only limited influence on the output, e.g. the permutation of
    trusted input fields or the content of specific fixed untrusted fields of
    the output message.

    This can be used to feed a MAC data that contains untrusted portions (like
    a DH public key received over the Internet) as well as trusted portions
    like the local DH key to authenticate a connection. It can also be used
    to let untrusted data control the layout (but not the content) of trusted
    data, e.g. the selection of trusted keys from an untrusted ID contained
    in a message.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  uncontrolled, controlled
        #   Outputs: data

        # Parameter
        #   uncontrolled
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
        #   uncontrolled
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Having uncontrolled data influence the layout of the output
        #   securely is one purpose of this component.
        # Assertion:
        #   None

        # Parameter
        #   controlled
        # Integrity guarantee can be dropped if:
        #   If the output data interfaces has not security guarantees.
        # Reason:
        #   Otherwise, an attacker could change the content of data
        #   by changing the controlled input data.
        # Assertion:
        #   controlled_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ controlled_in_i)
        self.input.controlled.intg =  Implies (Intg(self.output.data), Intg(self.input.controlled))

        # Parameter
        #   controlled
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
        #   data
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

        # Parameter
        #   data
        # Confidentiality guarantee can be dropped if:
        #   No input interface demands confidentiality
        # Reason:
        #   Input from an interface guaranteeing confidentiality may pass
        #   confidential data to any output. Hence, confidentiality can
        #   only be dropped if no input interface guarantees confidentiality
        # Assertion:
        #   controlled_c ∨ uncontrolled_c -> data_c
        self.output.data.intg = Implies (Or (Conf(self.input.controlled), Conf(self.input.uncontrolled)), Conf(self.output.data))

class Primitive_const (Primitive):
    """
    The const primivive
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  ø
        #   Outputs: const

        # Const can only drop integrity or confidentiality guarantees if the
        # receiving primitives do not require them.  This is handled in the
        # channel assertions (output guarantees of parent are equivalent to
        # respective input guarantees of child)

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
        #   No integrity guarantee is demanded by data_out
        # Reason:
        #   Otherwise, an attacker could change or reorder len_in creating
        #   data_out messages of chosen, invalid length.
        # Truth table
        #   len_in_i    data_out_i  valid
        #   0           0           1
        #   0           1           0
        # Assertion:
        #   len_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ len_in_i)
        self.input.len.intg = Implies (Intg(self.output.data), Intg(self.input.len))

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
        self.output.data.conf = Conf (self.output.data)

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
        #   Input:   psec
        #   Outputs: pub

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
        self.input.psec.conf = Bool (True)

        # Parameter
        #   psec_in
        # Integrity guarantees can be dropped if:
        #   same as above.
        # Reason:
        #   If an attacker can choose psec_in (x in DH terms) and knows g^y,
        #   she can calculate the shared secret g^yx
        # Assertion:
        #   See above.
        self.input.psec.intg = Bool (True)

        # Parameter
        #   pub_out
        # Confidentiality guarantee can be dropped if:
        #   psec_in demands confidentiality and integrity
        # Reason:
        #   Being able to transmit g^x over an non-confidential channel is the
        #   sole purpose of the DH key exchange, given that x has
        #   confidentiality and integrity guarantees
        # Truth table:
        #   pub_out_c psec_in_c psec_in_i result
        #   0         0         0         0
        #   0         0         1         0
        #   0         1         0         0
        #   0         1         1         1
        # Assertion:
        #   pub_out_c or (psec_in_c and psec_in_i)
        self.output.pub.conf = Or (Conf(self.output.pub), And (Conf(self.input.psec), Intg(self.input.psec)))

        # Parameter
        #   pub_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None

class Primitive_dhsec (Primitive):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  pub, psec
        #   Outputs: ssec

        # Parameter
        #   psec_in
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for ssec (g^xy in DH terms) or
        #   confidentiality is guaranteed for pub (g^y)
        # Reason:
        #   With knowledge of pub (g^y) and psec_in (x) an attacker can
        #   calculate ssec (the shared secret g^yx ≡ g^xy)
        # Assertion:
        #   psec_in_c ∨ ssec_out_c ∨ ¬pub_in_c
        self.input.psec.conf = Or (Conf(self.input.psec), Conf(self.output.ssec), Not (Conf(self.input.pub)))

        # Parameter
        #   psec_in
        # Integrity guarantees can be dropped if:
        #   No confidentiality is guaranteed for ssec (g^xy in DH terms)
        # Reason:
        # Assertion:
        #   ssec_out_c => psec_in_i
        self.input.psec.intg = Implies (Conf(self.output.ssec), Intg(self.input.psec))

        # Parameter
        #   pub_in
        # Confidentiality guarantee can be dropped if:
        #   psec_in demands confidentiality or no confidentiality is guaranteed
        #   for ssec_out
        # Reason:
        #   Being able to transmit g^x over an non-confidential channel is the
        #   sole purpose of the DH key exchange, given that x is confidential.
        #   FIXME: How about integrity of x? If an attacker can choose x, she
        #   cannot derive g^xy. MITM attacks may be possible, though.
        # Truth table:
        #   pub_in_c   ssec_out_c psec_in_c result
        #   0          0          0         1
        #   0          0          1         1
        #   0          1          0         0
        #   0          1          1         1
        # Assertion:
        #   pub_in_c ∨ ¬ssec_out_c ∨ psec_in_c
        self.input.pub.conf = Or (Conf(self.input.pub), Not (Conf(self.output.ssec)), Conf(self.input.psec))

        # Parameter
        #   pub_in
        # Integrity guarantees can be dropped if:
        #   Anytime.
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None

        # Parameter
        #   ssec_out
        # Confidentiality guarantee can be dropped if:
        #   Neither psec_in nor pub_in demand confidentiality guarantees
        # Reason:
        #   With the knowledge of psec_in (y in DH terms) and pub (g^x in DH
        #   terms) an attacker can calculate the shared secret g^yx.
        #   FIXME: We do not require psec_in to be integrity protected, as an
        #   attacker would not be able to derive ssec with a chosen psec in
        #   *this* step. The situation is different if an attacker can chose
        #   the psec used for dhpub (but this is covered in an own rule)
        # Truth table:
        #   ssec_out_c psec_in_c pub_in_c result
        #   0          0         0        1
        #   0          0         1        0
        #   0          1         0        0
        #   0          1         1        0
        # Assertion:
        #   ssec_out_c ∨ ¬(psec_in_c ∨ pub_in_c)
        self.output.ssec.conf = Or (Conf(self.output.ssec), Not (Or (Conf(self.input.psec), Conf(self.input.pub))))

        # Parameter
        #   ssec_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None

class Primitive_encrypt (Primitive):
    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  plaintext, key, ctr
        #   Outputs: ciphertext

        # Parameter
        #   plaintext_in
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
        #   plaintext_in
        # Integrity guarantee can be dropped if:
        #   ciphertext_out has no integrity guarantees
        # Reason:
        #   Counter mode encryption does not achieve integrity, hence an attacker
        #   can could change plaintext_in to influence the integrity of
        #   ciphertext_out. If integrity must be guaranteed for ciphertext_out,
        #   it also must be guaranteed for plaintext_in.
        # Truth table:
        #   ciphertext_out_i plaintext_in_i result
        #   0                0              1
        #   0                1              0
        # Assertion:
        #   plaintext_in_i ∨ ¬ciphertext_out_i (equiv: ciphertext_out_i ⇒ plaintext_in_i)
        self.input.plaintext.intg = Implies (Intg(self.output.ciphertext), Intg(self.input.plaintext))

        # Parameter
        #   key_in
        # Confidentiality guarantee can be dropped if:
        #   Plaintext_in demands no confidentiality or
        #   confidentiality is guaranteed for ciphertext_out
        # Reason:
        #   If plaintext_in is known to an attacker (i.e. not confidential), it
        #   is superfluous to guarantee confidentiality for key_in.
        #   If ciphertext_out requires confidentiality, the confidentiality of
        #   pt_in is guaranteed even if key_in is known to an attacker.
        # Truth table:
        #   key_in_c       plaintext_in_c  ciphertext_out_c result
        #   0              0               0                1
        #   0              0               1                1
        #   0              1               0                0
        #   0              1               1                1
        # Assertion:
        #   key_in_c ∨ ¬plaintext_in_c ∨ cipertext_out_c
        self.input.key.conf = Or (Conf(self.input.key), Not (Conf(self.input.plaintext)), Conf(self.output.ciphertext))

        # Parameter
        #   key_in
        # Integrity guarantee can be dropped if:
        #   Never
        # Reason:
        # Assertion:
        self.input.key.intg = Intg (self.input.key)

        # Parameter
        #   ctr_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The counter/IV in counter mode encryption is not confidential by
        #   definition
        # Assertion:
        #   None

        # Parameter
        #   ctr_in
        # Integrity guarantee can be dropped if:
        #   No confidentiality is guaranteed for plaintext_in or
        #   confidentiality is guaranteed for ciphertext_out
        # Reason:
        #   If no confidentiality is guaranteed for plaintext_in in the first
        #   place, it is superfluous to encrypt (and hence chose unique counter
        #   values). If confidentiality is guaranteed for ciphertext_out,
        #   encryption is not necessary. Hence, a ctr_in chose by an attacker
        #   does no harm.
        # Assertion:
        #   ctr_in_i ∨ ¬plaintext_in_c ∨ cipertext_out_c
        self.input.ctr.intg = Or (Intg(self.input.ctr), Not (Conf(self.input.plaintext)), Conf(self.output.ciphertext))

        # Parameter
        #   ciphertext_out
        # Confidentiality guarantee can be dropped if:
        #   Confidentiality is guaranteed for key_in and
        #   integrity is guaranteed for key_in and
        #   integrity is guaranteed for ctr_in.
        # Reason:
        #   If confidentiality and integrity is guaranteed for the key and
        #   integrity is guaranteed for ctr (to avoid using the same key/ctr
        #   combination twice), an attacker cannot decrypt the ciphertext and
        #   thus no confidentiality needs to be guaranteed by the environment.
        # Assertion:
        #   ciphertext_out_c ∨ (key_in_c ∧ key_in_i ∧ ¬ctr_in_i)
        self.output.ciphertext.conf = Or (Conf(self.output.ciphertext), And (Conf(self.input.key), Intg(self.input.key), Intg(self.input.ctr)))

        # Parameter
        #   ciphertext_out
        # Integrity guarantee can be dropped if:
        #   If plaintext_in has no integrity guarantees
        # Reason:
        #   Counter mode encryption neither assumes nor achieves integrity.
        # Assertion:
        #   ciphertext_out_i ∨ ¬plaintext_in_i (equiv: plaintext_in_i ⇒ ciphertext_out_i)
        self.output.ciphertext.intg = Implies (Intg(self.input.plaintext), Intg(self.output.ciphertext))

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
        self.input.key.conf = Implies (Conf(self.output.plaintext), Conf(self.input.key))

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
        #   No integrity is guaranteed for hash_out
        # Reason:
        #   If an attacker can chose data, she may change the output hash.
        #   FIXME: But not chose hash arbitrarily if a cryptographically
        #   secure hash function is used. What does that mean for the
        #   integrity of data_out?
        # Truth table:
        #   data_in_i hash_out_i result
        #   0         0          1
        #   0         1          0
        # Assertion:
        #   data_in_i ∨ ¬hash_out_i (equiv: hash_out_i ⇒ data_in_i)
        self.input.data.intg = Implies (Intg(self.output.hash), Intg(self.input.data))

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
        self.output.hash.conf = Implies (Conf(self.input.data), Conf(self.output.hash))

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
        self.input.key.conf = Implies (Intg(self.input.msg), Conf(self.input.key))

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
        self.input.key.intg = Implies (Intg(self.input.msg), Intg(self.input.key))

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
        self.input.msg.intg = Intg (self.input.msg)

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
        self.output.msg.conf = Implies (Conf(self.input.msg), Conf(self.output.msg))

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
        #   Input:  msg, skey
        #   Output: auth

        # Parameter
        #   msg_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Sign does not assume nor achieve confidentiality for the input
        #   message.
        # Assertion:
        #   None

        # Parameter
        #   msg_in
        # Integrity guarantee can be dropped if:
        #   Never
        # Reason:
        #   Signing arbitrary data makes no sense.
        # Assertion:
        #   msg_in_i
        self.input.msg.intg = Intg (self.input.msg)

        # Parameter
        #   skey_in
        # Confidentiality guarantee can be dropped if:
        #   Never
        # Reason:
        # Assertion:
        #   skey_in_c ∨ ¬msg_in_i (equiv: msg_in_i ⇒ skey_in_c)
        self.input.skey.conf = Conf (self.input.skey)

        # Parameter
        #   skey_in
        # Integrity guarantee can be dropped if:
        #   Never
        # Reason:
        # Assertion:
        #   skey_in_i
        self.input.skey.intg = Intg (self.input.skey)

        # Parameter
        #   auth_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for data_in
        # Reason:
        #   Even with a cryptographically secure hash function, an attacker
        #   may be able to recover data_in from hash_out, depending on the
        #   resource available and the structure of data_in. As we don't want
        #   to get probabilistic here, we just assume this is always possible.
        # Assertion:
        #   auth_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ auth_out_c)
        self.output.auth.conf = Implies (Conf(self.input.msg), Conf(self.output.auth))

        # Parameter
        #   auth_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None

class Primitive_verify_sig (Primitive):

    """
    The signature verification primitive

    Checks whether an auth value represents a valid message signature by a given public key.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  msg, auth, pkey
        #   Output: result

        # Parameter
        #   msg_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Signature verification does not assume confidentiality for the input
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
        #   pkey_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Public key is, by definition, public.
        # Assertion:
        #   None

        # Parameter
        #   pkey_in
        # Integrity guarantee can be dropped if:
        #   If no integrity is guaranteed for result
        # Reason:
        #   If an attacker can modify the result of a verify operation, she could
        #   as well chose an own public key for which she has the secret key available
        #   (and thus can create a valid signature yielding a positive result)
        # Assertion:
        #   pkey_in_i ∨ ¬result_out_i (equiv: result_out_i ⇒ pkey_in_i)
        self.input.pkey.intg = Implies (Intg(self.output.result), Intg(self.input.pkey))

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for msg_in
        # Reason:
        #   FIXME: Does the value of result really allow for gaining knowledge about msg?
        # Assertion:
        #   result_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ result_out_c)
        self.output.result.conf = Implies (Conf(self.input.msg), Conf(self.output.result))

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

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
        self.input.key.conf = Implies (Intg(self.output.result), Conf(self.input.key))

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
        self.input.key.intg = Implies (Intg(self.output.result), Intg(self.input.key))

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for msg_in
        # Reason:
        #   FIXME: Does the value of result really allow for gaining knowledge about msg?
        # Assertion:
        #   result_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ result_out_c)
        self.output.result.conf = Implies (Conf(self.input.msg), Conf(self.output.result))

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
        self.output.msg.conf = Implies (Conf(self.input.msg), Conf(self.output.msg))

        # Parameter
        #   msg_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_counter (Primitive):

    """
    Monotonic counter primitive

    This primitive outputs a monotonic sequence of counters initialized by to a
    specific value every time the trigger input receives a true value.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  init, trigger
        #   Output: ctr

        # Parameter
        #   init_in
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for ctr_out or confidentiality
        #   is guaranteed for trigger.
        # Reason:
        #   By observing the initial value and the trigger values, an attacker
        #   may derive the value of the counter. If ctr_out requires
        #   confidentiality guarantees, init or trigger must guarantee
        #   confidentiality.
        # Assertion:
        #   init_in_c ∨ trigger_in_c ∨ ¬ctr_out_c
        self.input.init.conf = Or (Conf(self.input.init), Conf(self.input.trigger), Not (Conf(self.output.ctr)))

        # Parameter
        #   init_in
        # Integrity guarantee can be dropped if:
        #   No integrity is to be guaranteed for ctr_out
        # Reason:
        #   An attacker who's able to chose the initial value of the counter can
        #   void the integrity of ctr_out
        # Assertion:
        #   init_in_i ∨ ¬ctr_out_i (equiv: ctr_out_i ⇒ init_in_i)
        #
        self.input.init.intg = Implies (Intg(self.output.ctr), Intg(self.input.init))

        # Parameter
        #   trigger_in
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for ctr_out
        # Reason:
        #   By observing the initial value and the trigger values, an attacker
        #   may derive the value of the counter. As the initial value may not
        #   be random, it is not sufficient to guarantee confidentiality for
        #   init_in
        # Assertion:
        #   trigger_in_c ∨ ¬ctr_out_c (equiv: ctr_out_c ⇒ trigger_in_c)
        self.input.trigger.conf = Implies (Conf(self.output.ctr), Conf(self.input.trigger))

        # Parameter
        #   trigger_in
        # Integrity guarantee can be dropped if:
        #   No integrity is to be guaranteed for ctr_out
        # Reason:
        #   An attacker who's able to chose a sequence of triggers can void the
        #   integrity of ctr_out. While the initial value of the counter is
        #   required, confidentiality for init_in is not sufficient to drop
        #   confidentiality guarantees for trigger_in. The reason is, that even
        #   though init_in is be confidential, it may still be predictable and
        #   allow and attacker to construct a specific ctr_out from a chosen
        #   sequence of triggers.
        # Assertion:
        #   trigger_in_i ∨ ¬ctr_out_i (equiv: ctr_out_i ⇒ trigger_in_i)
        #
        self.input.trigger.intg = Implies (Intg(self.output.ctr), Intg(self.input.trigger))

        # Parameter
        #   ctr_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for init_in or trigger_in
        # Reason:
        #   If trigger_in or init_in have not confidentiality guarantees, an
        #   attacker may derive ctr from it, hence guaranteeing confidentiality
        #   for ctr_out is superfluous.
        # Assertion:
        #   ctr_out_c ∨ ¬init_in_c ∨ ¬trigger_in_c
        self.output.ctr.conf = Or (Conf(self.output.ctr), Not (Conf(self.input.trigger)), Not (Conf(self.input.init)))

        # Parameter
        #   ctr_out
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
        self.input.data.intg = Implies (Intg(self.output.data), Intg(self.input.data))

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
        self.input.cond.intg = Intg (self.input.cond)

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is to be guaranteed for data_in
        # Reason:
        #   If data_in has no confidentiality guarantees, it
        #   makes no sense to keep data_out confidential.
        # Assertion:
        #   data_out_c ∨ ¬data_in_c (equiv: data_in_c ⇒ data_out_c)
        self.output.data.conf = Implies (Conf(self.input.data), Conf(self.output.data))

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
        self.input.data1.intg = Implies (Intg(self.output.result), self.input.data1)

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
        self.input.data2.intg = Implies (Intg(self.output.result), self.input.data2)

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   If confidentiality is not guaranteed for both, data1 and data2
        # Reason:
        #   If an attacker knows data1 and data2 she can derive result_out
        #   by comparing both values
        # Assertion:
        #   result_out_c ∨ ¬(data1_in_c ∧ data2_in_c)
        self.output.result.conf = Or (Conf(self.output.result), Not (And (self.input.data1, self.input.data2)))

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

class Primitive_scomp (Primitive):

    """
    Comp primitive

    The stream comparator compares data with the previous message received on
    the same interface. Depending on whether the current value equals the previous
    value a boolean result is emitted on the outgoing result interfaces.
    """

    def __init__ (self, G, name):
        super ().setup (G, name)

        # Parameters
        #   Input:  data
        #   Output: result

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
        #   No integrity guarantee is demanded for result_out
        # Reason:
        #   If an attacker can chose data_in, she can determine the value
        #   of result_out
        # Assertion:
        #   data_in_i ∨ ¬result_out_i (equiv: result_out_i ⇒ data_in_i)
        self.input.data.intg = Implies (Intg(self.output.result), Intg(self.input.data))

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   If confidentiality is not guaranteed for both data
        # Reason:
        #   If an attacker knows data result by comparing with previous values
        # Assertion:
        #   result_out_c ∨ ¬data_in_c (equiv: result_out_c ⇒ data_in_c)
        self.output.result.conf = Implies (Conf(self.output.result), Conf(self.input.data))

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
        self.input.data.intg = Implies (Intg(self.output.data), Intg(self.input.data))

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
        self.output.data.conf = Implies (Conf(self.input.data), Conf(self.output.data))

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
        self.input.data.intg = Implies (Intg(self.output.data), Intg(self.input.data))

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
        self.output.data.conf = Implies (Conf(self.input.data), Conf(self.output.data))

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
        self.output.trigger.intg = Intg (self.output.trigger)

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

    mdg = nx.MultiDiGraph()
    G   = Graph (mdg, assert_fail)

    # read in graph
    for child in root.iterchildren(tag = etree.Element):

        name  = child.attrib["id"]

        descnode = child.find('description')
        if descnode is not None:
            desc = "<" + child.tag + ":&#10;" + re.sub ('\n\s*', '&#10;', descnode.text.strip()) + ">"
        else:
            warn ("No description for " + name)
            desc = "<No description&#10;available.>"

        arguments = []
        for element in child.findall('arg'):
            argname = element.attrib['name']
            arguments.append (argname)

        mdg.add_node \
            (name, \
             guarantees = parse_guarantees (child.attrib), \
             kind       = child.tag, \
             tooltip    = desc, \
             arguments  = arguments,
             style      = "bold", \
             penwidth   = "2", \
             width      = "2.5", \
             height     = "0.6")

        for element in child.findall('flow'):
            sarg = element.attrib['sarg']
            darg = element.attrib['darg']

            assert_c = parse_bool (element.attrib, 'assert_c') if 'assert_c' in element.attrib else None
            assert_i = parse_bool (element.attrib, 'assert_i') if 'assert_i' in element.attrib else None

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
                warn ("'" + node + "' has no incoming edge for '" + arg + "'")

        if mdg.node[node]['kind'] == "xform":
            if not mdg.in_edges (nbunch=node):
                raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], "No inputs")
            if not mdg.out_edges (nbunch=node):
                raise PrimitiveInvalidAttributes (node, mdg.node[node]['kind'], "No outputs")

        objname = "Primitive_" + mdg.node[node]['kind']
        try:
            mdg.node[node]['primitive'] = globals()[objname](G, node)
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
                warn ("'" + child + "' has edge from '" + parent + "' for non-existing argument '" + darg + "'")

    info (str(len(mdg.node)) + " nodes.")
    return G

def set_style (o, c, i):

    if c == None or i == None:
        o['style'] = "dashed"

    if (c and i) or (c == None and i == None):
        o['color'] = "purple"
    elif not c and not i and c != None and i != None:
        o['color'] = "black"
    elif c or c == None:
        o['color'] = "red"
    elif i or i == None:
        o['color'] = "blue"

def main():

    G = parse_graph (args.input[0])
    solved = G.analyze(args.dump_rules)
    G.label()

    if solved: G.partition()

    G.write (args.output[0])
    sys.exit (0 if solved else 1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPG Analyzer')
    parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
    parser.add_argument('--dump', action='store_true', help='Dump rules', dest='dump_rules');
    parser.add_argument('--test', action='store_true', help='Run in test mode', dest='test');
    parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');

    try:
        args = parser.parse_args ()
        main()
    except PrimitiveMissing as e:
        warn (e)
    except (PrimitiveInvalidAttributes, InconsistentRule) as e:
        err (e)
        raise
        sys.exit (1)
