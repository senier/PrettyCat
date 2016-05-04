#!/usr/bin/env python

import sys
import xml.etree.ElementTree as ET
import argparse
import subprocess
import os
sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *
import networkx as nx

def sec_empty():
    return set(())

def sec_f():
    return set(("f"))

def sec_c():
    return set(("c"))

def sec_i():
    return set(("i"))

def sec_ci():
    return sec_c() | sec_i()

def sec_cif():
    return sec_ci() | sec_f()

def sec_all():
    return sec_cif()

def fmtsec(sec):
    if not sec:
        #return "&empty;"
        return "&empty;"
    else:
        result = ""
        if "c" in sec:
            result += "c"
        if "i" in sec:
            if result:
                result += ","
            result += "i"
        if "a" in sec:
            if result:
                result += ","
            result += "a"
        if "f" in sec:
            if result:
                result += ","
            result += "f"
        if "C" in sec:
            if result:
                result += ","
            result += "C"
        if "I" in sec:
            if result:
                result += ","
            result += "I"
        if "F" in sec:
            if result:
                result += ","
            result += "F"
    return "{" + result + "}";

def convert_secset (attrib):
    result = sec_empty()
    if "confidentiality" in attrib and attrib["confidentiality"] == "True":
        result |= sec_c()
    if "integrity" in attrib and attrib["integrity"] == "True":
        result |= sec_i()
    if "freshness" in attrib and attrib["freshness"] == "True":
        result |= sec_f()
    return result

def sec_color (sec):
    if sec_cif() <= sec:
        return "cyan"
    if sec_ci() <= sec:
        return "purple"
    if sec_c() <= sec:
        return "red"
    if sec_i() <= sec:
        return "blue"
    return "black"

def colorize (G, nodelist):
    for node in nodelist:
        n = G.node[node]
        outsec = sec_empty()
        for (parent, child, data) in G.out_edges(nbunch=node, data=True):
            outsec |= data['sec']

        insec = sec_empty()
        for (parent, child, data) in G.in_edges(nbunch=node, data=True):
            insec |= data['sec']

        sec = insec | outsec
        if 'sec' in n and n['sec'] != None:
            sec |= n['sec']

        n['fontname'] = "Times Bold"
        n['fontcolor'] = "gray"
        n['style'] = "filled"
        n['gradientangle'] = "90"
        n['fillcolor'] = "\"" + sec_color(sec) + "\""

def parse_graph (inpath):
    try:
        root = ET.parse(inpath).getroot()
    except IOError as e:
        print("Error opening XML file: " + str(e))
        sys.exit(1)
    
    G = nx.MultiDiGraph();
    
    # read in graph
    for child in root:
    
        sec = None
        # FIXME: Detect duplicate argument
        args = []

        label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"
    
        if child.tag == "xform":
            sec = convert_secset(child.attrib)
            for arg in child.findall('arg'):
                args.append (arg.attrib['name'])

        if child.attrib["id"].startswith ("send_") or child.attrib["id"].startswith ("recv_"):
            shape = "invhouse"
        else:
            shape = "rectangle"

        G.add_node \
            (child.attrib["id"], \
             args=args, \
             kind=child.tag, \
             sec=sec, \
             label = label, \
             shape = shape, \
             penwidth = "0", \
             width = "2.5", \
             height = "0.6")
    
        for element in child.findall('flow'):
            sarg = element.attrib['sarg']
            darg = element.attrib['darg']
            G.add_edge (child.attrib['id'], element.attrib['sink'], \
                darg = darg, \
                sarg = sarg, \
                sec = sec_empty(), \
                labelfontsize = "8", \
                labelfontcolor="red", \
                arrowhead="vee", \
                labelfontname="Sans-Serif", \
                labeljust="r", \
                penwidth="3")

    return G

def write_graph(G, title, out):

    # add edge labels
    for (parent, child, data) in G.edges(data=True):
        data['xlabel']    = fmtsec(data['sec'])
        data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
        data['headlabel'] = data['darg']
        data['color']     = sec_color(data['sec'])
        data['fontcolor'] = sec_color(data['sec'])
    
    # color nodes according to security level
    colorize(G, nx.topological_sort (G))
    
    # add edge labels
    for (parent, child, data) in G.edges(data=True):
        if 'extralabel' in data:
            data['xlabel'] += data['extralabel']
        if 'unsat_in_c' in data:
            data['color'] = 'orange'
            data['xlabel'] += "\nIN/C"
        if 'unsat_in_i' in data:
            data['color'] = 'orange'
            data['xlabel'] += "\nIN/I"
        if 'unsat_in_f' in data:
            data['color'] = 'orange'
            data['xlabel'] += "\nIN/F"
        if 'unsat_out_c' in data:
            data['color'] = 'orange'
            data['xlabel'] += "\nOUT/C"
        if 'unsat_out_i' in data:
            data['color'] = 'orange'
            data['xlabel'] += "\nOUT/I"
        if 'unsat_out_f' in data:
            data['color'] = 'orange'
            data['xlabel'] += "\nOUT/F"
    
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

def set_in_c (G, node, darg, value):
    G.node[node][darg + "_in_c"] = value

def set_in_i (G, node, darg, value):
    G.node[node][darg + "_in_i"] = value

def set_in_f (G, node, darg, value):
    G.node[node][darg + "_in_f"] = value

def set_out_c (G, node, sarg, value):
    G.node[node][sarg + "_out_c"] = value

def set_out_i (G, node, sarg, value):
    G.node[node][sarg + "_out_i"] = value

def set_out_f (G, node, sarg, value):
    G.node[node][sarg + "_out_f"] = value

def get_out_c (G, node, sarg):
    result = G.node[node][sarg + "_out_c"]
    if result != None:
        return result
    raise Exception, "Node '" + node + "' does not have argument '" + sarg + "'"

def get_out_i (G, node, sarg):
    result = G.node[node][sarg + "_out_i"]
    if result != None:
        return result
    raise Exception, "Node '" + node + "' does not have argument '" + sarg + "'"

def get_out_f (G, node, sarg):
    result = G.node[node][sarg + "_out_f"]
    if result != None:
        return result
    raise Exception, "Node '" + node + "' does not have argument '" + sarg + "'"

def get_in_c (G, node, darg):
    result = G.node[node][darg + "_in_c"]
    if result != None:
        return result
    raise Exception, "Node '" + node + "' does not have argument '" + darg + "'"

def get_in_i (G, node, darg):
    result = G.node[node][darg + "_in_i"]
    if result != None:
        return result
    raise Exception, "Node '" + node + "' does not have argument '" + darg + "'"

def get_in_f (G, node, darg):
    result = G.node[node][darg + "_in_f"]
    if result != None:
        return result
    raise Exception, "Node '" + node + "' does not have argument '" + darg + "'"


def init_in_vars(G, node, db, solver, darg):
    for (parent, current, data) in G.in_edges(nbunch=node, data=True):
        if data['darg'] == darg:
            data['in_var_c'] = Bool(node + "_" + data['darg'] + "_in_c")
            data['in_var_i'] = Bool(node + "_" + data['darg'] + "_in_i")
            data['in_var_f'] = Bool(node + "_" + data['darg'] + "_in_f")

            assert_and_track (db, solver, data['out_var_c'] == data['in_var_c'], node + "_" + darg + "_inout_c")
            assert_and_track (db, solver, data['out_var_i'] == data['in_var_i'], node + "_" + darg + "_inout_i")
            assert_and_track (db, solver, data['out_var_f'] == data['in_var_f'], node + "_" + darg + "_inout_f")

def secset (c, i, f):
    result = sec_empty()
    if c == True:
        result |= sec_c()
    if i == True:
        result |= sec_i()
    if f == True:
        result |= sec_f()
    return result

def mark_unsat_core (G, uc):
    constraints = {}
    mark_expression (G, constraints, uc)
    for (child, parent, data) in G.edges (data=True):
        if str(data['in_var_c']) in constraints:
            data['unsat_in_c'] = True
        if str(data['in_var_i']) in constraints:
            data['unsat_in_i'] = True
        if str(data['in_var_f']) in constraints:
            data['unsat_in_f'] = True
        if str(data['out_var_c']) in constraints:
            data['unsat_out_c'] = True
        if str(data['out_var_i']) in constraints:
            data['unsat_out_i'] = True
        if str(data['out_var_f']) in constraints:
            data['unsat_out_f'] = True

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

def analyze_satisfiability (G):

    assert_db = {}
    s = Solver()
    s.set(unsat_core=True)

    for node in nx.topological_sort (G):
        analyze_sat (G, assert_db, node, s)

    if s.check() == sat:
        print "Solution found"
        m = s.model()
        for (parent, child, data) in G.in_edges(data=True):
            c = str(m.evaluate(get_in_c (G, child, data['darg']))) == "True"
            i = str(m.evaluate(get_in_i (G, child, data['darg']))) == "True"
            f = str(m.evaluate(get_in_f (G, child, data['darg']))) == "True"
            data['sec'] = secset (c, i, f)
        for (parent, child, data) in G.out_edges(data=True):
            c = str(m.evaluate(get_out_c (G, parent, data['sarg']))) == "True"
            i = str(m.evaluate(get_out_i (G, parent, data['sarg']))) == "True"
            f = str(m.evaluate(get_out_f (G, parent, data['sarg']))) == "True"
            data['sec'] = secset (c, i, f)
    else:
        print "No solution"
        unsat_core = []
        for p in s.unsat_core():
            unsat_core.append (simplify(assert_db[str(p)]))
        mark_unsat_core (G, And(unsat_core))

def assert_and_track (db, s, cond, name):
    db[name] = cond
    s.assert_and_track (cond, name)

def analyze_sat (G, db, node, s):

    n = G.node[node]
    kind = n['kind']

    # Initialize all input arguments for this node
    for (parent, current, data) in G.in_edges(nbunch=node, data=True):
        darg = data['darg']
        sarg = data['sarg']

        set_in_c (G, current, darg, Bool(current + "_" + darg + "_in_c"))
        set_in_i (G, current, darg, Bool(current + "_" + darg + "_in_i"))
        set_in_f (G, current, darg, Bool(current + "_" + darg + "_in_f"))

        handle = parent + "_" + current + "_" + sarg + "_" + darg
        assert_and_track (db, s, get_out_c (G, parent, sarg) == get_in_c (G, current, darg), handle + "_c")
        assert_and_track (db, s, get_out_i (G, parent, sarg) == get_in_i (G, current, darg), handle + "_i")
        assert_and_track (db, s, get_out_f (G, parent, sarg) == get_in_f (G, current, darg), handle + "_f")

    # Initialize all output arguments for this node
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        set_out_c (G, node, data['sarg'], Bool(node + "_" + data['sarg'] + "_out_c"))
        set_out_i (G, node, data['sarg'], Bool(node + "_" + data['sarg'] + "_out_i"))
        set_out_f (G, node, data['sarg'], Bool(node + "_" + data['sarg'] + "_out_f"))

    if kind == "permute":

        c = []
        i = []
        f = []

        for (parent, current, data) in G.in_edges(nbunch=node, data=True):
            if data['darg'] != "order":
                c.append (get_in_c (G, node, data['darg']))
                i.append (get_in_i (G, node, data['darg']))
                f.append (get_in_f (G, node, data['darg']))

        for (current, child, data) in G.out_edges(nbunch=node, data=True):
            if c: set_out_c (G, node, data['sarg'], Or(c))
            if i: set_out_i (G, node, data['sarg'], And(i))
            if f: set_out_f (G, node, data['sarg'], And(f))

    elif kind == "xform":

        has_source = False
        has_sink   = False

        c = []
        i = []
        f = []

        for (parent, current, data) in G.in_edges(nbunch=node, data=True):
            has_source = True
            c.append (get_in_c (G, node, data['darg']))
            i.append (get_in_i (G, node, data['darg']))
            f.append (get_in_f (G, node, data['darg']))

        for (current, child, data) in G.out_edges(nbunch=node, data=True):
            has_sink = True
            if c: set_out_c (G, node, data['sarg'], Or(c))
            if i: set_out_i (G, node, data['sarg'], And(i))
            if f: set_out_f (G, node, data['sarg'], And(f))

        if has_source and has_sink:
            # ordinary xforms don't have security labels
            pass
        elif has_source:
            # Sink:
            # Assert all incoming edges to have at least the sinks security level
            for (parent, current, data) in G.in_edges(nbunch=node, data=True):
                darg = data['darg']
                c = Bool(node + "_" + darg + "_sink_c")
                i = Bool(node + "_" + darg + "_sink_i")
                f = Bool(node + "_" + darg + "_sink_f")
                assert_and_track (db, s, Implies (get_in_c (G, node, darg), c), current + "_xform_" + darg + "_in_c")
                assert_and_track (db, s, Implies (get_in_c (G, node, darg), i), current + "_xform_" + darg + "_in_i")
                assert_and_track (db, s, Implies (get_in_c (G, node, darg), f), current + "_xform_" + darg + "_in_f")
                val_c = c if 'c' in n['sec'] else Not(c)
                val_i = i if 'i' in n['sec'] else Not(i)
                val_f = f if 'f' in n['sec'] else Not(f)
                assert_and_track (db, s, val_c, current + "_sink_" + darg + "_sec_c")
                assert_and_track (db, s, val_i, current + "_sink_" + darg + "_sec_i")
                assert_and_track (db, s, val_f, current + "_sink_" + darg + "_sec_f")

        elif has_sink:
            # Source:
            # Assert all outgoing edges to have at most the sources security level
            for (current, child, data) in G.out_edges(nbunch=node, data=True):
                sarg = data['sarg']
                c = Bool(node + "_" + sarg + "_source_c")
                i = Bool(node + "_" + sarg + "_source_i")
                f = Bool(node + "_" + sarg + "_source_f")
                assert_and_track (db, s, get_out_c (G, node, sarg) == c, current + "_xform_" + sarg + "_out_c")
                assert_and_track (db, s, get_out_i (G, node, sarg) == i, current + "_xform_" + sarg + "_out_i")
                assert_and_track (db, s, get_out_f (G, node, sarg) == f, current + "_xform_" + sarg + "_out_f")
                val_c = c if 'c' in n['sec'] else Not(c)
                val_i = i if 'i' in n['sec'] else Not(i)
                val_f = f if 'f' in n['sec'] else Not(f)
                assert_and_track (db, s, val_c, current + "_source_" + sarg + "_sec_c")
                assert_and_track (db, s, val_i, current + "_source_" + sarg + "_sec_i")
                assert_and_track (db, s, val_f, current + "_source_" + sarg + "_sec_f")
        else:
            # no incoming and no outgoing edges? This is an error.
            raise Exception, "xform with no edges: " + node

    elif kind == "const":
        pass

    elif kind == "rng":
        # Do we need a seed as input (i.e. is the seed ever used in a security protocol)?
        # FIXME: Maybe a PRNG later?

        # Length input parameter needs integrity
        assert_and_track (db, s, get_in_i (G, node, "len"), node + "_rand_len_in_i")

        # Output data parameter provides confidentiality, integrity and freshness
        assert_and_track (db, s, get_out_c (G, node, "data"), node + "_rand_data_out_c")
        assert_and_track (db, s, get_out_i (G, node, "data"), node + "_rand_data_out_i")
        assert_and_track (db, s, get_out_f (G, node, "data"), node + "_rand_data_out_f")

    elif kind == "dhpub":
        # Generator needs integrity
        assert_and_track (db, s, get_in_i (G, node, "gen"), node + "_dhpub_gen_in_i")

        # Secret psec requires confidentiality, integrity and freshness
        assert_and_track (db, s, get_in_c (G, node, "psec"), node + "_dhpub_psec_in_c")
        assert_and_track (db, s, get_in_i (G, node, "psec"), node + "_dhpub_psec_in_i")
        assert_and_track (db, s, get_in_f (G, node, "psec"), node + "_dhpub_psec_in_f")

        # Output secret psec only guarantees confidentiality and integrity
        assert_and_track (db, s, get_out_c (G, node, "psec"), node + "_dhpub_psec_out_c")
        assert_and_track (db, s, get_out_i (G, node, "psec"), node + "_dhpub_psec_out_i")

    elif kind == "dhsec":
        # Input secret psec requires confidentiality and integrity
        assert_and_track (db, s, get_in_c (G, node, "psec"), node + "_dhsec_psec_in_c")
        assert_and_track (db, s, get_in_i (G, node, "psec"), node + "_dhsec_psec_in_i")

        # Output secret ssec requires confidentiality
        assert_and_track (db, s, get_out_c (G, node, "ssec"), node + "dhsec_ssec_out_c")

        assert_and_track (db, s, get_in_i (G, node, "pub") == get_out_i (G, node, "ssec"), node + "dhsec_ssec_inout_i")
        assert_and_track (db, s, get_in_f (G, node, "pub") == get_out_f (G, node, "ssec"), node + "dhsec_ssec_inout_f")

    elif kind == "hash":
        # FIXME: Which kind of hash? Universal/cryptographic/...?
        assert_and_track (db, s, Implies (get_in_i (G, node, "msg"), get_out_i (G, node, "hash")), node + "_hash_hash_out_i")
        # Hash cannot create freshness, i.e. the freshness of the hash equals the freshness of msg
        # FIXME: Check for other primitives
        assert_and_track (db, s, get_in_f (G, node, "msg") == get_out_f (G, node, "hash"), node + "_hash_hash_out_f")

    elif kind == "encrypt":
        # Output ciphertext does not have confidentiality requirement if:
        #       key is confidential and
        #       key is of integrity and
        #       iv is of integrity and
        #       either key or iv are fresh
        security  = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"), get_in_i (G, node, "iv"))
        freshness = Or (get_in_f (G, node, "iv"), get_in_f (G, node, "key"))

        # FIXME:
        # This does not seem to model encryption correctly, yet. What if the plaintext had no security
        # requirements in the first place? Then, encryption with a known key or without freshness would be OK
        assert_and_track (db, s, Not(get_out_c (G, node, "ciphertext")) == And (security, freshness), node + "_encrypt_ciphertext_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "plaintext"), get_out_i (G, node, "ciphertext")), node + "_encrypt_ciphertext_i")

        # Does it make sense that encryption has no influence on freshness???
        assert_and_track (db, s, Implies (get_in_f (G, node, "plaintext"), get_out_f (G, node, "ciphertext")), node + "_encrypt_ciphertext_f" )

    elif kind == "decrypt":
        security  = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"), get_in_i (G, node, "iv"))
        freshness = Or (get_in_f (G, node, "iv"), get_in_f (G, node, "key"))
        assert_and_track (db, s, Implies (get_out_c (G, node, "plaintext"), And (security, freshness)), node + "_decrypt_plaintext_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "ciphertext"), get_out_i (G, node, "plaintext")), node + "_decrypt_plaintext_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "ciphertext"), get_out_f (G, node, "plaintext")), node + "_decrypt_plaintext_f" )

    elif kind == "verify_hash":
        # FIXME: Could be composed of hash and comparator
        assert_and_track (db, s, Implies (get_in_c (G, node, "hash"), get_out_c (G, node, "msg")), node + "_verify_hash_msg_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "hash"), get_out_i (G, node, "msg")), node + "_verify_hash_msg_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "hash"), get_out_f (G, node, "msg")), node + "_verify_hash_msg_f")

    elif kind == "verify_hmac":
        security = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"))
        assert_and_track (db, s, Implies (get_out_i (G, node, "msg"), security), node + "_verify_hmac_msg_i")
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "msg")), node + "_verify_hmac_msg_c")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "msg")), node + "_verify_hmac_msg_f")

    elif kind == "hmac":
        security = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"))
        assert_and_track (db, s, security, node + "_hmac_security")
        #assert_and_track (db, s, Implies (get_in_i (G, node, "msg"), security), node + "_hmac_msg_i")

    elif kind == "hmac_inline":
        security = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"))
        assert_and_track (db, s, security, node + "_hmac_inline_security")
        #assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "msg")), node + "_hmac_inline_msg_c")
        #assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "msg")), node + "_hmac_inline_msg_f")

    elif kind == "sign":
        security = And (get_in_c (G, node, "skey"), get_in_i (G, node, "skey"), get_in_i (G, node, "pkey"))
        assert_and_track (db, s, Implies (get_out_i (G, node, "auth"), security), node + "_sign_auth_i")
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "auth")), node + "_sign_auth_c")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "auth")), node + "_sign_auth_f")

    elif kind == "verify_sig":
        assert_and_track (db, s, Implies (get_out_i (G, node, "msg"), get_in_i (G, node, "pkey")), node + "_verify_sig_msg_i")
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "msg")), node + "_verify_sig_msg_c")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "msg")), node + "_verify_sig_msg_f")

    elif kind == "release":
        assert_and_track (db, s, Implies (get_out_c (G, node, "data"), get_in_c (G, node, "data")), node + "_release_data_c")
        assert_and_track (db, s, Implies (get_out_i (G, node, "data"), get_in_i (G, node, "data")), node + "_release_data_i")
        assert_and_track (db, s, Implies (get_out_f (G, node, "data"), get_in_f (G, node, "data")), node + "_release_data_f")

    elif kind == "guard":
        assert_and_track (db, s, get_in_i (G, node, "cond"), node + "_guard_cond_i")
        assert_and_track (db, s, get_in_c (G, node, "data") == get_out_c (G, node, "data"), node + "_guard_data_c")
        assert_and_track (db, s, get_in_i (G, node, "data") == get_out_i (G, node, "data"), node + "_guard_data_i")
        assert_and_track (db, s, get_in_f (G, node, "data") == get_out_f (G, node, "data"), node + "_guard_data_f")

    elif kind == "counter":
        assert_and_track (db, s, get_in_i (G, node, "init"), node + "_counter_init_i")

        assert_and_track (db, s, get_in_c (G, node, "key") == get_out_c (G, node, "key"), node + "_counter_key_c")
        assert_and_track (db, s, get_in_i (G, node, "key") == get_out_i (G, node, "key"), node + "_counter_key_i")
        assert_and_track (db, s, get_in_f (G, node, "key") == get_out_f (G, node, "key"), node + "_counter_key_f")

        assert_and_track (db, s, Or (get_out_f (G, node, "ctr"), get_out_f (G, node, "key")), node + "_counter_ctr_or_key_f")

        # FIXME: Implement comperator
    else:
        raise Exception, "Unhandled primitive '" + kind + "'"

def main(args):

    # validate input XML
    print subprocess.check_output (["xmllint", "--noout", "--schema", "spg.xsd", args.input[0]]);

    G = parse_graph (args.input[0])
    analyze_satisfiability(G)
    write_graph(G, "Final", args.output[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPG Analyzer')
    parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
    parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');
    parser.add_argument('--incremental', action='store_true', help='Create incremental PDF', dest='incremental');
    main(parser.parse_args ())
