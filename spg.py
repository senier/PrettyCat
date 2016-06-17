#!/usr/bin/env python3

import sys
import xml.etree.ElementTree as ET
import argparse
import subprocess
import os

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx

class Graph:

    def __init__ (self, graph, solver):
        self.graph  = graph
        self.solver = solver
        self.model  = None

    def graph (self):
        return self.graph

    def solver (self):
        return self.solver

    def model (self):
        return self.solver.model()

    def analyze (self):
        if self.solver.check() == sat:
            print ("Solution found")
            self.solver.minimize ()
            self.model = self.solver.model
        else:
            print ("No solution")
            self.solver.mark_unsat_core(self.graph)

    def write (self, title, out):
    
        G = self.graph 
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
            data['color'] = sec_color (G.node[parent]['primitive'].o.guarantees()[sarg])
        
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

    def minimize (self):
        print ("Info: Running with plain solver, performing no optimization.");

    def model (self):
        return self.solver.model()

class SPG_Optimizer (SPG_Solver_Base):

    def __init__ (self):
        self.solver = Optimize()

    def assert_and_track (self, condition, name):
        self.solver.add (condition)

    def minimize (self):
        cost = Int ('cost')
        h = self.solver.minimize (cost)
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
        assert (self.o.const)

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
        assert (self.i.len.c)

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
        assert(self.o.data.i)

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
        assert (self.o.pub.i)

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
        assert (self.i.psec.i)

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
        assert (self.i.pub.i)

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
        assert (self.o.ssec.i)

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
        assert (self.i.plaintext.c)

        # Parameter
        #   plaintext_in
        # Integrity guarantee can be dropped if:
        #   Anytime.
        # Reason:
        #   Data flow is directed. Integrity of an input parameter cannot be
        #   influenced by an output parameter or other input parameters.
        # Assertion:
        #   None
        assert (self.i.plaintext.i)

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
        assert (self.i.ctr.c)

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
        #   plaintext_in has no integrity guarantees
        # Reason:
        #   Counter mode encryption does not achieve integrity, hence integrity
        #   guarantees for the ciphertext can only be omitted if the plaintext
        #   had no integrity guaranteed in the first place.
        # Truth table:
        #   ciphertext_out_i plaintext_in_i result
        #   0                0              1
        #   0                1              0
        # Assertion:
        #   ciphertext_out_i ∨ ¬plaintext_in_i (equiv: plaintext_in_i ⇒ ciphertext_out_i)
        self.assert_and_track (Implies (self.i.plaintext.i, self.o.ciphertext.i), "ciphertext_out_i")

class Primitive_decrypt (Primitive):
    def __init__ (self, G, name, sink, source):
        super ().setup (G, name)
        raise  Exception ("Decrypt not implemented");

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
        #   Data flow is directed. Integrity of an input parameter cannot be
        #   influenced by an output parameter or other input parameters.
        # Assertion:
        #   None
        assert(self.i.data.i)

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
        #   to get propabilistic here, we just assume this is always possible.
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
        assert (self.o.hash.i)

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

def parse_graph (inpath, solver):
    try:
        root = ET.parse(inpath).getroot()
    except IOError as e:
        print("Error opening XML file: " + str(e))
        sys.exit(1)
    
    mdg = nx.MultiDiGraph()
    G   = Graph (mdg, solver)
    
    # read in graph
    for child in root:
    
        label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"
        name  = child.attrib["id"]

        mdg.add_node \
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
            mdg.add_edge (name, element.attrib['sink'], \
                sarg = sarg, \
                darg = darg, \
                labelfontsize = "8", \
                labelfontcolor="red", \
                arrowhead="vee", \
                labelfontname="Sans-Serif", \
                labeljust="r", \
                penwidth="3")

    # Initialize all objects
    for node in mdg.node:
        objname = "Primitive_" + mdg.node[node]['kind']
        sink   = mdg.in_edges (nbunch=node) and not mdg.out_edges (nbunch=node)
        source = mdg.out_edges (nbunch=node) and not mdg.in_edges (nbunch=node)
        mdg.node[node]['primitive'] = globals()[objname](G, node, sink, source)

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

def sec_color(guarantee):

    c = guarantee.val_c()
    i = guarantee.val_i()

    if c == None or i == None:
        return "orange"

    if c and i:
        return "purple"
    elif not c and not i:
        return "black"
    elif c:
        return "red"
    elif i:
        return "blue"

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
    print (subprocess.check_output (["xmllint", "--noout", "--schema", "spg.xsd", args.input[0]]))

    G = parse_graph (args.input[0], SPG_Solver())
    G.analyze()
    G.write ("Final", args.output[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPG Analyzer')
    parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
    parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');
    main(parser.parse_args ())
