#!/usr/bin/env python3

import sys
import xml.etree.ElementTree as ET
import argparse
import subprocess
import os

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx

class PrimitiveMissing (Exception):
    def __init__ (self, kind, name):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") not implemented")

class PrimitiveInvalidAttributes (Exception):
    def __init__ (self, name, kind, text):
        Exception.__init__(self, "Primitive '" + name + "' (" + kind + ") has invalid attributes: " + text)

class Graph:

    def __init__ (self, graph, solver, maximize):
        self.graph    = graph
        self.solver   = solver
        self.model    = None
        self.maximize = maximize

    def graph (self):
        return self.graph

    def solver (self):
        return self.solver

    def model (self):
        return self.solver.model()

    def analyze (self):
        if self.solver.check() == sat:
            print ("Solution found")
            self.solver.optimize (self.graph, self.maximize)
            self.model = self.solver.model
        else:
            print ("No solution")
            self.solver.mark_unsat_core(self.graph)

    def write (self, title, out):
    
        G = self.graph 
        for node in G.node:
            if G.in_edges (nbunch=node) and G.out_edges (nbunch=node) or G.node[node]['kind'] == "const":
                G.node[node]['shape'] = "rectangle"
            elif not G.in_edges(nbunch=node) or not G.out_edges (nbunch=node):
                G.node[node]['shape'] = "invhouse"
            else:
                raise Exception ("Xform without edges")

            val_c = False
            val_i = False
            for (parent, current, data) in G.in_edges (nbunch=node, data=True):
                darg = data['darg']
                val_c = val_c or G.node[current]['primitive'].i.guarantees()[darg].val_c()
                val_i = val_i or G.node[current]['primitive'].i.guarantees()[darg].val_i()

            for (current, child, data) in G.out_edges (nbunch=node, data=True):
                sarg = data['sarg']
                val_c = val_c or G.node[current]['primitive'].o.guarantees()[sarg].val_c()
                val_i = val_i or G.node[current]['primitive'].o.guarantees()[sarg].val_i()

            set_style (G.node[node], val_c, val_i)
    
        # add edge labels
        for (parent, child, data) in G.edges(data=True):
    
            # sarg guarantees of parent should are the same as darg guarantees of child
            darg = data['darg']
            sarg = data['sarg']
    
            data['xlabel']    = ""
            data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
            data['headlabel'] = data['darg']

            g = G.node[parent]['primitive'].o.guarantees()[sarg]
            set_style (data, g.val_c(), g.val_i())
        
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
        os.remove (out + ".dot")

class Args:

    def __init__ (self):
        raise Exception ("Abstract class")

    def setup (self, graph, name, mode):
        self._graph  = graph
        self._name   = name
        self._mode   = mode

    def add_guarantee (self, name): 
        self.__dict__.update (**{name: Guarantees (self._graph, self._name + "_" + name, self._mode)})

    def guarantees (self):
        return { k: v for k, v in self.__dict__.items() if not k.startswith("_") }

class Args_In (Args):
    def __init__ (self, graph, name):
        Args.setup (self, graph, name, "in")

class Args_Out (Args):
    def __init__ (self, graph, name):
        Args.setup (self, graph, name, "out")

class SPG_Solver_Base:

    def __init__ (self):
        raise Exception ("Abstract")

    def check (self):
        return self.solver.check()

    def optimize (self, graph, maximize):
        print ("Info: Running with plain solver, performing no optimization.");

    def model (self):
        return self.solver.model()

class SPG_Optimizer (SPG_Solver_Base):

    def __init__ (self):
        self.solver = Optimize()
        self.cost   = Int('cost');

    def assert_and_track (self, condition, name):
        self.solver.add (condition)

    def optimize (self, graph, maximize):

        print ("Optimizing result")

        edge_sum = Int(0)
        for (parent, child, data) in graph.edges (data=True):
            parent_primitive = graph.node[parent]['primitive']
            child_primitive = graph.node[child]['primitive']
            sarg = data['sarg']
            darg = data['darg']

            edge_sum = edge_sum + \
                If(parent_primitive.o.guarantees()[sarg].c, Int(1), Int(0)) + \
                If(parent_primitive.o.guarantees()[sarg].i, Int(1), Int(0)) + \
                If(child_primitive.i.guarantees()[darg].c, Int(1), Int(0)) + \
                If(child_primitive.i.guarantees()[darg].i, Int(1), Int(0))


        self.solver.add (self.cost == edge_sum)
        if maximize:
            print ("Maximizing cost")
            h = self.solver.maximize (self.cost)
        else:
            print ("Minimizing cost")
            h = self.solver.minimize (self.cost)

        self.solver.check()
        self.solver.lower(h)

class SPG_Solver (SPG_Solver_Base):

    def __init__ (self):
        self.solver = Solver()
        self.assert_db = {}
        self.solver.set(unsat_core=True)
        self.constraints = {}

    def assert_and_track (self, condition, name):
        key = "a_" + str(name)
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
        print ("Unsat core:")
        unsat_core = []
        for p in self.solver.unsat_core():
            unsat_core.append (simplify (self.assert_db[str(p)]))
            print ();
            print ("   " + str (p) + ":")
            print ("      " + str(simplify(self.assert_db[str(p)])))
        self.mark_expression (G, simplify (And (unsat_core)))
        print ("Full, simplified uncore:")
        print (simplify (And (unsat_core)))
        print ("Constraints:")
        for c in self.constraints:
            print ("   " + c)

class Guarantees:

    def __init__ (self, graph, node, mode):
        self.graph  = graph
        self.node   = node

        self.base = self.node + "_" + mode
        self.c = Bool(self.base + "_c")
        self.i = Bool(self.base + "_i")

    def base (self):
        return base

    def assert_condition (self, condition, desc):
        self.graph.solver.assert_and_track (condition, self.base + "_" + desc)

    def c (self):
        return c

    def i (self):
        return i

    def assert_x (self, var, value, tag):
        if value != None: 
            self.graph.solver.assert_and_track (var == value, self.base + "_" + tag)

    def assert_c (self, value):
        self.assert_x (self.c, value, "c")

    def assert_i (self, value):
        self.assert_x (self.i, value, "i")

    def val_c (self):
        if self.graph.model == None:
            return None if self.base + "_c" in self.graph.solver.constraints else False
        return is_true(self.graph.model()[self.c])

    def val_i (self):
        if self.graph.model == None:
            return None if self.base + "_i" in self.graph.solver.constraints else False
        return is_true(self.graph.model()[self.i])

####################################################################################################

class Primitive:
    """
    An "abstract" class implementing generic methods for a Primitive
    """

    def __init__ (self, G, name):
        raise Exception ("Abstract")

    def setup (self, G, name):
        self.i      = Args_In (G, name)
        self.o      = Args_Out (G, name)
        self.name   = name
        self.node   = G.graph.node[name]
        self.graph  = G

        for (parent, current, data) in G.graph.in_edges (nbunch=name, data=True):
            self.i.add_guarantee (data['darg'])

        for (current, child, data) in G.graph.out_edges (nbunch=name, data=True):
            self.o.add_guarantee (data['sarg'])

    def assert_and_track (self, cond, desc):
        """Track an condition tagging it with the primitive name and a description"""
        self.graph.solver.assert_and_track (cond, self.name + "_" + desc)

    def assert_nothing (self, cond, desc):
        self.assert_and_track (Or (cond, Not(cond)), desc)

class Primitive_xform (Primitive):
    """
    The xform primitive
    
    This mainly identifies sources and sinks and sets the fixed
    guarantees according to the XML definition.
    """

    def __init__ (self, G, name, sink, source):
        super ().setup (G, name)

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
        #   ∃out_i ⇒ ∀in_j
        for (out_name, out_g) in self.o.guarantees().items():
            for (in_name, in_g) in self.i.guarantees().items():
                    self.assert_and_track (Implies (out_g.i, in_g.i), in_name + "_" + out_name + "_i")

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
        for (in_name, in_g) in self.i.guarantees().items():
            for (out_name, out_g) in self.o.guarantees().items():
                self.assert_and_track (Implies (in_g.c, out_g.c), in_name + "_" + out_name + "_c")

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
        for (in_name, in_g) in self.i.guarantees().items():
            for (out_name, out_g) in self.o.guarantees().items():
                self.assert_and_track (Implies (in_g.i, out_g.i), in_name + "_" + out_name + "_i")

class Primitive_permute (Primitive):
    """
    The permute primitive
    
    This primitive change the flow from input data interfaces to output
    interfaces based on order input interfaces.
    """

    def __init__ (self, G, name, sink, source):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  order, data_i
        #   Outputs: data_j

        # Parameter
        #   All input interfaces data_i
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
        #   All input interfaces data_i
        # Integrity guarantee can be dropped if:
        #   No output data interface guarantees integrity
        # Reason:
        #   Input from a source lacking integrity guarantees can influence
        #   any output of an xform in undetermined ways. Hence, maintaining
        #   integrity for an input is superfluous if no output guarantees
        #   integrity
        #   FIXME: If any input does not guarantee integrity, we should also
        #   be able to drop integrity guarantees.
        # Assertion:
        #   ∃out_i ⇒ ∀in_j
        for (out_name, out_g) in self.o.guarantees().items():
            for (in_name, in_g) in self.i.guarantees().items():
                    if in_name != "order":
                        self.assert_and_track (Implies (out_g.i, in_g.i), in_name + "_" + out_name + "_i")

        # Parameter
        #   All output interfaces data_j
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None

        # Parameter
        #   All output interfaces data_j
        # Confidentiality guarantee can be dropped if:
        #   No input interface demands confidentiality
        # Reason:
        #   Input from an interface guaranteeing confidentiality may pass
        #   confidential data to any output. Hence, confidentiality can
        #   only be dropped if no input interface guarantees confidentiality
        # Assertion:
        #   in_c -> out_c
        for (in_name, in_g) in self.i.guarantees().items():
            if in_name != "order":
                for (out_name, out_g) in self.o.guarantees().items():
                    self.assert_and_track (Implies (in_g.c, out_g.c), in_name + "_" + out_name + "_c")

        # Parameter
        #   order_in
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   The permute primitive assumes that receiver of the output data
        #   copes with arbitrary permutations of the input data and that
        #   otherwise the order input interfaces cannot influence the
        #   integrity of output data
        # Assertion:
        #   None
        self.assert_nothing (self.i.order.i, "order_in_i")

        # Parameter
        #   order_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The confidentiality of an input parameter is not influenced by an
        #   output parameters or other input parameters as the data flow is
        #   directed. Hence, the demand for confidentiality guarantees is
        #   solely determined by the source of an input interface
        # Assertion:
        #   None
        self.assert_nothing (self.i.order.c, "order_in_c")

class Primitive_const (Primitive):
    """
    The const primivive
    """

    def __init__ (self, G, name, sink, source):
        super ().setup (G, name)

        # Parameters
        #   Inputs:  ø
        #   Outputs: const

        # Const can only drop integrity or confidentiality guarantees if the
        # receiving primitives do not require them.  This is handled in the
        # channel assertions (output guarantees of parent are equivalent to
        # respective input guarantees of child)

        # Just check that const output parameter exists
        self.assert_nothing (self.o.const.c, "const_out_c")
        self.assert_nothing (self.o.const.i, "const_out_i")

class Primitive_rng (Primitive):
    """
    Primitive for a true (hardware) random number generator

    This RNG is not seeded. It has an input parameter len, determining how
    many bits we request from it.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.len.c, "len_in_c")

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
        self.assert_and_track (Implies (self.o.data.i, self.i.len.i), "len_in_i")

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   Confidentiality is not required for len_in
        # Reason:
        #   Attacker could derive len_in from the length of data_out otherwise.
        # Truth table
        #   data_out_c  len_in_c    valid
        #   0           0           1
        #   0           1           0
        # Assertion:
        #   data_out_c ∨ ¬len_in_c (equiv: len_in_c ⇒ data_out_c)
        self.assert_and_track (Implies (self.i.len.c, self.o.data.c), "data_out_c")

        # Parameter
        #   data_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   FIXME
        # Assertion:
        #   None
        self.assert_nothing (self.o.data.i, "data_out_i")

class Primitive_dhpub (Primitive):

    def __init__ (self, G, name, sink, source):
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
        # Truth table:
        #   pub_out_c psec_in_c psec_in_i result
        #   0         0         0         0
        #   0         0         1         0
        #   0         1         0         0
        #   0         1         1         1
        # Assertion:
        #   pub_out_c or (psec_in_c and psec_in_i)
        self.assert_and_track (Or (self.o.pub.c, And (self.i.psec.c, self.i.psec.i)), "pub_out_c")

        # Parameter
        #   pub_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None
        self.assert_nothing (self.o.pub.i, "pub_out_i")

class Primitive_dhsec (Primitive):
    def __init__ (self, G, name, sink, source):
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
        # Truth table:
        #   psec_in_c ssec_out_c pub_in_c result
        #   0         0          0        1
        #   0         0          1        1
        #   0         1          0        0
        #   0         1          1        1
        # Assertion:
        #   psec_in_c ∨ ssec_out_c ∨ ¬pub_in_c
        self.assert_and_track (Or (self.i.psec.c, self.o.ssec.c, Not (self.i.pub.c)), "psec_in_c")

        # Parameter
        #   psec_in
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   If an attacker can choose psec_in (x) in the dhsec step, she can
        #   influence the resulting g^yx. However, this is not the shared
        #   secret unless psec was consistently changed for the respective
        #   dhpub step. This case is handled there.
        # Assertion:
        #   None.
        self.assert_nothing (self.i.psec.i, "psec_in_i")

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
        self.assert_and_track (Or (self.i.pub.c, Not (self.o.ssec.c), self.i.psec.c), "pub_in_c")

        # Parameter
        #   pub_in
        # Integrity guarantees can be dropped if:
        #   Anytime.
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None
        self.assert_nothing (self.i.pub.i, "pub_in_i")

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
        self.assert_and_track (Or (self.o.ssec.c, Not (Or (self.i.psec.c, self.i.pub.c))), "ssec_out_c")

        # Parameter
        #   ssec_out
        # Integrity guarantees can be dropped if:
        #   Anytime
        # Reason:
        #   DH does not achieve nor assume integrity
        # Assertion:
        #   None
        self.assert_nothing (self.o.ssec.i, "ssec_out_i")

class Primitive_encrypt (Primitive):
    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.plaintext.c, "plaintext_in_c")

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
        self.assert_and_track (Implies (self.o.ciphertext.i, self.i.plaintext.i), "ciphertext_in_i")

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
        self.assert_and_track (Or (self.i.key.c, Not (self.i.plaintext.c), self.o.ciphertext.c), "key_in_c")

        # Parameter
        #   key_in
        # Integrity guarantee can be dropped if:
        #   Same as for confidentiality.
        # Reason:
        #   See above
        # Assertion:
        #   key_in_i ∨ ¬(plaintext_in_c ∧ ctr_in_i ∧ ¬cipertext_out_c)
        self.assert_and_track (Or (self.i.key.i, Not (And (self.i.plaintext.c, self.i.ctr.i, Not (self.o.ciphertext.c)))), "key_in_c")

        # Parameter
        #   ctr_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The counter/IV in counter mode encryption is not confidential by
        #   definition
        # Assertion:
        #   None
        self.assert_nothing (self.i.ctr.c, "ctr_in_c")

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
        self.assert_and_track (Or (self.i.ctr.i, Not (self.i.plaintext.c), self.o.ciphertext.c), "ctr_in_c")

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
        self.assert_and_track (Or (self.o.ciphertext.c, And (self.i.key.c, self.i.key.i), self.i.ctr.i), "ciphertext_out_c")

        # Parameter
        #   ciphertext_out
        # Integrity guarantee can be dropped if:
        #   If plaintext_in has no integrity guarantees
        # Reason:
        #   Counter mode encryption neither assumes nor achieves integrity.
        # Assertion:
        #   ciphertext_out_i ∨ ¬plaintext_in_i (equiv: plaintext_in_i ⇒ ciphertext_out_i)
        self.assert_and_track (Implies (self.i.plaintext.i, self.o.ciphertext.i), "ciphertext_out_i")

class Primitive_decrypt (Primitive):
    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.ciphertext.c, "ciphertext_in_c")

        # Parameter
        #   ciphertext_in
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   Data flow is directed. Integrity of an input parameter cannot be
        #   influenced by an output parameter or other input parameters.
        # Assertion:
        #   None
        self.assert_nothing (self.i.ciphertext.i, "ciphertext_in_i")

        # Parameter
        #   key_in
        # Confidentiality guarantee can be dropped if:
        #   If no confidentiality is guaranteed for plaintext_out
        # Reason:
        #   If confidentiality is not guaranteed for the decryption
        #   result, keeping the cipher key secret is superfluous.
        # Assertion:
        #   key_in_c ∨ ¬plaintext_out_c (equiv: plaintext_out_c ⇒ key_in_c)
        self.assert_and_track (Implies (self.o.plaintext.c, self.i.key.c), "key_in_c")

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
        self.assert_nothing (self.i.key.i, "key_in_i")

        # Parameter
        #   ctr_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The counter is public as per counter mode definition.
        # Assertion:
        #   None
        self.assert_nothing (self.i.ctr.c, "ctr_in_c")

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
        self.assert_nothing (self.i.ctr.i, "ctr_in_i")

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
        self.assert_nothing (self.o.plaintext.c, "plaintext_out_c")

        # Parameter
        #   plaintext_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity guarantees are required is only determined by the
        #   primitive using the decryption result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.plaintext.i, "plaintext_out_i")

class Primitive_hash (Primitive):
    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.data.i, "data_in_i")

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
        self.assert_and_track (Implies (self.o.hash.i, self.i.data.i), "data_in_i")

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
        self.assert_and_track (Implies (self.i.data.c, self.o.hash.c), "hash_out_c")

        # Parameter
        #   hash_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   FIXME
        self.assert_nothing (self.o.hash.i, "hash_out_i")

class Primitive_hmac (Primitive):

    def __init__ (self, G, name, sink, source):
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
        self.assert_and_track (Implies (self.i.msg.i, self.i.key.c), "key_in_c")

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
        self.assert_and_track (Implies (self.i.msg.i, self.i.key.i), "key_in_i")

        # Parameter
        #   msg_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   HMAC does not achieve nor assume confidentiality
        # Assertion:
        #   None
        self.assert_nothing (self.i.msg.c, "msg_in_c")

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
        self.assert_and_track (self.i.msg.i, "msg_in_i")

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
        self.assert_nothing (self.o.auth.c, "auth_out_c")

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
        self.assert_nothing (self.o.auth.i, "auth_out_i")

class Primitive_sign (Primitive):

    """
    The sign primitive
    
    Creates an asymmetric digital signature for a message using a given set of
    public and secret keys.
    """

    def __init__ (self, G, name, sink, source):
        super ().setup (G, name)

        # Parameters
        #   Input:  msg, pkey, skey
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
        self.assert_nothing (self.i.msg.c, "msg_in_c")

        # Parameter
        #   msg_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Data flow is directed. Integrity of an input parameter cannot be
        #   influenced by an output parameter or other input parameters.
        # Assertion:
        #   None
        self.assert_nothing (self.i.msg.i, "msg_in_i")

        # Parameter
        #   pkey_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   The public key is assumed to be public, hence guaranteeing
        #   confidentiality is unnecessary.
        # Assertion:
        #   None
        self.assert_nothing (self.i.pkey.c, "pkey_i_c")

        # Parameter
        #   pkey_in
        # Integrity guarantee can be dropped if:
        #   No integrity is guaranteed for msg_in.
        # Reason:
        #   If no integrity is guaranteed for the input message in the
        #   first place, creating a valid digital signature is useless.
        #   FIXME: I'd assume that combining invalid pubkey/seckey pairs
        #   would be detected by a signature algorithm, but I don't know
        #   for sure. If not, we need to guarantee integrity also for the
        #   public key.
        # Assertion:
        #   pkey_in_i ∨ ¬msg_in_i (equiv: msg_in_i ⇒ pkey_in_i)
        self.assert_and_track (Implies (self.i.msg.i, self.i.pkey.i), "pkey_in_i")

        # Parameter
        #   skey_in
        # Confidentiality guarantee can be dropped if:
        #   If no integrity is guaranteed for msg_in
        # Reason:
        #   If no integrity is guaranteed for the input message in the
        #   first place, creating a valid digital signature is useless.
        # Assertion:
        #   skey_in_c ∨ ¬msg_in_i (equiv: msg_in_i ⇒ skey_in_c)
        self.assert_and_track (Implies (self.i.msg.i, self.i.skey.c), "skey_in_c")

        # Parameter
        #   skey_in
        # Integrity guarantee can be dropped if:
        #   No integrity is guaranteed for msg_in.
        # Reason:
        #   If no integrity is guaranteed for the input message in the
        #   first place, creating a valid digital signature is useless.
        # Assertion:
        #   skey_in_i ∨ ¬msg_in_i (equiv: msg_in_i ⇒ skey_in_i)
        self.assert_and_track (Implies (self.i.msg.i, self.i.skey.i), "pkey_in_i")

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
        self.assert_and_track (Implies (self.i.msg.c, self.o.auth.c), "auth_out_c")

        # Parameter
        #   auth_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None
        self.assert_nothing (self.o.auth.i, "auth_out_i")

class Primitive_verify_sig (Primitive):

    """
    The signature verification primitive
    
    Checks whether an auth value represents a valid message signature by a given public key.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.msg.c, "msg_in_c")

        # Parameter
        #   msg_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None
        self.assert_nothing (self.i.msg.i, "msg_in_i")

        # Parameter
        #   auth_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Signature verification does not assume confidentiality for signature.
        # Assertion:
        #   None
        self.assert_nothing (self.i.auth.c, "auth_in_c")

        # Parameter
        #   auth_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None
        self.assert_nothing (self.i.auth.i, "auth_in_i")

        # Parameter
        #   pkey_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Public key is, by definition, public.
        # Assertion:
        #   None
        self.assert_nothing (self.i.pkey.c, "pkey_in_c")

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
        self.assert_and_track (Implies (self.o.result.i, self.i.pkey.i), "pkey_in_i")

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for msg_in
        # Reason:
        #   FIXME: Does the value of result really allow for gaining knowledge about msg?
        # Assertion:
        #   result_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ result_out_c)
        self.assert_and_track (Implies (self.i.msg.c, self.o.result.c), "result_out_c")

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.result.i, "result_out_i")

class Primitive_verify_hmac (Primitive):

    """
    HMAC verification primitive
    
    Checks whether a given pair (msg, auth) was MAC'ed with key.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.msg.c, "msg_in_c")

        # Parameter
        #   msg_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None
        self.assert_nothing (self.i.msg.i, "msg_in_i")

        # Parameter
        #   auth_in
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Signature verification does not assume confidentiality for signature.
        # Assertion:
        #   None
        self.assert_nothing (self.i.auth.c, "auth_in_c")

        # Parameter
        #   auth_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Achieving integrity (in addition to authentication) cryptographically
        #   is the purpose of a signature operation.
        # Assertion:
        #   None
        self.assert_nothing (self.i.auth.i, "auth_in_i")

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
        self.assert_and_track (Implies (self.o.result.i, self.i.key.c), "key_in_c")

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
        self.assert_and_track (Implies (self.o.result.i, self.i.key.i), "key_in_i")

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is guaranteed for msg_in
        # Reason:
        #   FIXME: Does the value of result really allow for gaining knowledge about msg?
        # Assertion:
        #   result_out_c ∨ ¬msg_in_c (equiv: msg_in_c ⇒ result_out_c)
        self.assert_and_track (Implies (self.i.msg.c, self.o.result.c), "result_out_c")

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.result.i, "result_out_i")

class Primitive_counter (Primitive):

    """
    Monotonic counter primitive
    
    This primitive outputs a monotonic sequence of counters initialized by to a
    specific value every time the trigger input receives a true value.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_and_track (Or (self.i.init.c, self.i.trigger.c, Not (self.o.ctr.c)), "init_in_c")

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
        self.assert_and_track (Implies (self.o.ctr.i, self.i.init.i), "init_in_i")

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
        self.assert_and_track (Implies (self.o.ctr.c, self.i.trigger.c), "trigger_in_c")

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
        self.assert_and_track (Implies (self.o.ctr.i, self.i.trigger.i), "trigger_in_i")

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
        self.assert_and_track (Or (self.o.ctr.c, Not (self.i.trigger.c), Not (self.i.init.c)), "ctr_out_c")

        # Parameter
        #   ctr_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.ctr.i, "ctr_out_i")

class Primitive_guard (Primitive):

    """
    Guard primitive
    
    This primitive guards the control the data flow in a protocol. Input data is
    only transferred to the output interfaces if the condition on the input interfaces is
    true.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.data.c, "data_in_c")

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   No integrity is to be guaranteed for data_out
        # Reason:
        #   If data_out requires no integrity, it is OK for data_in to be altered
        #   by an attacker.
        # Assertion:
        #   data_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ data_in_i)
        self.assert_and_track (Implies (self.o.data.i, self.i.data.i), "data_in_i")

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
        self.assert_nothing (self.i.data.c, "cond_in_c")

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
        self.assert_and_track (self.i.cond.i, "cond_in_i")

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   No confidentiality is to be guaranteed for data_in
        # Reason:
        #   If data_in has no confidentiality guarantees, it
        #   makes no sense to keep data_out confidential.
        # Assertion:
        #   data_out_c ∨ ¬data_in_c (equiv: data_in_c ⇒ data_out_c)
        self.assert_and_track (Implies (self.i.data.c, self.o.data.c), "data_out_c")

        # Parameter
        #   data_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   data_in_i ∨ ¬data_out_i (equiv: data_out_i ⇒ data_in_i)
        self.assert_and_track (Implies (self.o.data.i, self.i.data.i), "data_out_i")

class Primitive_release (Primitive):

    """
    Release primitive
    
    This primitive allows to drop all security guarantees.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.data.c, "data_in_c")

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   This is the purpose of the component
        # Assertion:
        #   None
        self.assert_nothing (self.i.data.i, "data_in_i")

        # Parameter
        #   data_out
        # Confidentiality guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   This is the purpose of the component
        # Assertion:
        #   None
        self.assert_nothing (self.o.data.c, "data_out_c")

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.data.i, "data_out_i")

class Primitive_comp (Primitive):

    """
    Comp primitive
    
    This primitive compares two arbitrary inputs and outputs a boolean value
    indicating whether both inputs were identical or not.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.data1.c, "data1_in_c")

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
        self.assert_and_track (Implies (self.o.result.i, self.i.data1.i), "data1_in_i")

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
        self.assert_nothing (self.i.data2.c, "data2_in_c")

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
        self.assert_and_track (Implies (self.o.result.i, self.i.data2.i), "data2_in_i")

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   If confidentiality is not guaranteed for both, data1 and data2
        # Reason:
        #   If an attacker knows data1 and data2 she can derive result_out
        #   by comparing both values
        # Assertion:
        #   result_out_c ∨ ¬(data1_in_c ∧ data2_in_c)
        self.assert_and_track (Or (self.o.result.c, Not (And (self.i.data1.c, self.i.data2.c))), "result_out_c")

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.result.i, "result_out_i")


class Primitive_scomp (Primitive):

    """
    Comp primitive
    
    The stream comparator compares data with the previous message received on
    the same interface. Depending on whether the current value equals the previous
    value a boolean result is emitted on the outgoing result interfaces.
    """

    def __init__ (self, G, name, sink, source):
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
        self.assert_nothing (self.i.data.c, "data_in_c")

        # Parameter
        #   data_in
        # Integrity guarantee can be dropped if:
        #   No integrity guarantee is demanded for result_out
        # Reason:
        #   If an attacker can chose data_in, she can determine the value
        #   of result_out
        # Assertion:
        #   data_in_i ∨ ¬result_out_i (equiv: result_out_i ⇒ data_in_i)
        self.assert_and_track (Implies (self.o.result.i, self.i.data.i), "data_in_i")

        # Parameter
        #   result_out
        # Confidentiality guarantee can be dropped if:
        #   If confidentiality is not guaranteed for both data
        # Reason:
        #   If an attacker knows data result by comparing with previous values
        # Assertion:
        #   result_out_c ∨ ¬data_in_c (equiv: result_out_c ⇒ data_in_c)
        self.assert_and_track (Implies (self.o.result.c, self.i.data.c), "result_out_c")

        # Parameter
        #   result_out
        # Integrity guarantee can be dropped if:
        #   Anytime
        # Reason:
        #   Whether integrity needs to be guaranteed only depends on the primitive using
        #   the result.
        # Assertion:
        #   None
        self.assert_nothing (self.o.result.i, "result_out_i")

####################################################################################################

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

def parse_graph (inpath, solver, maximize):
    try:
        root = ET.parse(inpath).getroot()
    except IOError as e:
        print("Error opening XML file: " + str(e))
        sys.exit(1)
    
    mdg = nx.MultiDiGraph()
    G   = Graph (mdg, solver, maximize)
    
    # read in graph
    for child in root:
    
        label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"
        name  = child.attrib["id"]

        mdg.add_node \
            (name, \
             guarantees = parse_guarantees (child.attrib), \
             kind       = child.tag, \
             label      = label, \
             penwidth   = "2", \
             width      = "2.5", \
             height     = "0.6")
    
        for element in child.findall('flow'):
            sarg = element.attrib['sarg']
            darg = element.attrib['darg']
            mdg.add_edge (name, element.attrib['sink'], \
                sarg = sarg, \
                darg = darg, \
                labelfontsize = "7", \
                labelfontcolor="black", \
                arrowhead="vee", \
                labelfontname="Sans-Serif", \
                labeljust="r", \
                penwidth="2")

    # Initialize all objects
    for node in mdg.node:
        objname = "Primitive_" + mdg.node[node]['kind']
        sink   = mdg.in_edges (nbunch=node) and not mdg.out_edges (nbunch=node)
        source = mdg.out_edges (nbunch=node) and not mdg.in_edges (nbunch=node)
        try:
            mdg.node[node]['primitive'] = globals()[objname](G, node, sink, source)
        except KeyError:
            raise PrimitiveMissing (mdg.node[node]['kind'], node)
        except AttributeError as e:
            raise PrimitiveInvalidAttributes (mdg.node[node]['kind'], node, str(e))

    # Establish src -> sink relation
    for (parent, child, data) in mdg.edges (data=True):
        parent_primitive = mdg.node[parent]['primitive']
        child_primitive = mdg.node[child]['primitive']
        sarg = data['sarg']
        darg = data['darg']

        name = parent + "_" + sarg + "__" + child + "_" + darg + "_channel_"
        G.solver.assert_and_track (parent_primitive.o.guarantees()[sarg].c == child_primitive.i.guarantees()[darg].c, name + "c")
        G.solver.assert_and_track (parent_primitive.o.guarantees()[sarg].i == child_primitive.i.guarantees()[darg].i, name + "i")

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

def main(args):

    # validate input XML
    # FIXME: Is there a python way to validate using XML Schema?
    print (subprocess.check_output (["xmllint", "--noout", "--schema", "spg.xsd", args.input[0]]))

    s = SPG_Optimizer() if args.optimize else SPG_Solver()

    G = parse_graph (args.input[0], s, args.maximize)
    G.analyze()
    G.write ("Final", args.output[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPG Analyzer')
    parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
    parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');
    parser.add_argument('--optimize', action='store_true', help='Use optimizer (disables uncore generation)', dest='optimize');
    parser.add_argument('--maximize', action='store_true', help='Perform maximization (for testing)', dest='maximize');

    try:
        main(parser.parse_args ())
    except PrimitiveMissing as e:
        print (e)
    except PrimitiveInvalidAttributes as e:
        print (e)
