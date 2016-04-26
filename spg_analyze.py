#!/usr/bin/env python

import xml.etree.ElementTree as ET
import networkx as nx
import sys
import argparse
import subprocess
import os
from z3 import *

iteration = 0
output = ""
pdfs = []

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

def maybe_c():
    return set(("C"))

def maybe_i():
    return set(("I"))

def maybe_f():
    return set(("F"))

def maybe_ci():
    return maybe_c() | maybe_i()

def maybe_cif():
    return maybe_ci() | maybe_f()

def maybe(s):
    result = set(())
    if sec_c() <= s or maybe_c() <= s:
        result |= maybe_c()
    if sec_i() <= s or maybe_i() <= s:
        result |= maybe_i()
    if sec_f() <= s or maybe_f() <= s:
        result |= maybe_f()
    return result

def freeze(s):
    result = set(())
    if sec_c() <= s or maybe_c() <= s:
        result |= sec_c()
    if sec_i() <= s or maybe_i() <= s:
        result |= sec_i()
    if sec_f() <= s or maybe_f() <= s:
        result |= sec_f()
    return result

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

def get_outputs(G, node, arglist):
    result = {}

    # retrieve output security sets from out edges
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        sarg = data['sarg']
        if not sarg in arglist:
            raise Exception, "Node '" + node + "' has invalid output parameter '" + str(sarg) + "'"
        if sarg in result:
            result[sarg] |= data['sec']
        else:
            result[sarg] = data['sec']

    # is something missing
    for arg in arglist:
        if not arg in result.keys():
            raise Exception, "Argument '" + arg + "' not found for node '" + node + "'"

    return result

def set_outputs (G, node, argmap):

    changes = 0
    seen = {}

    # retrieve output security sets from out edges
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        sarg = data['sarg']
        darg = data['darg']
        if not sarg in argmap:
            raise Exception, "Node '" + current + "' passes invalid output parameter '" + sarg + "' to '" + child + "'"

        if data['sec'] != argmap[sarg]:
            data['sec'] = argmap[sarg]
            changes += 1

        seen[sarg] = True

    for s in seen:
        del argmap[s]

    if argmap:
        raise Exception, "Node '" + node + "' has no arguments " + str(list(argmap.keys()))

    return changes

def set_pre (G, node, argmap):
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']

        if not darg in argmap:
            raise Exception, "Setting invalid pred '" + darg + "' for node " + node

        if argmap[darg] == None:
            data['pre_c'] = Bool(current + "_pre_c")
            data['pre_i'] = Bool(current + "_pre_i")
            data['pre_f'] = Bool(current + "_pre_f")
        else:
            data['pre_c'] = Bool(True) if 'c' in argmap[darg] else Bool(current + "_pre_c")
            data['pre_i'] = Bool(True) if 'i' in argmap[darg] else Bool(current + "_pre_i")
            data['pre_f'] = Bool(True) if 'f' in argmap[darg] else Bool(current + "_pre_f")

def set_post (G, node, argmap):
    
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        sarg = data['sarg']

        if not sarg in argmap:
            raise Exception, "Setting invalid pred '" + sarg + "' for node " + node

        if argmap[sarg] == None:
            data['post_c'] = Bool(current + "_post_c")
            data['post_i'] = Bool(current + "_post_i")
            data['post_f'] = Bool(current + "_post_f")
        else:
            data['post_c'] = Bool(True) if 'c' in argmap[sarg] else Bool(current + "_post_c")
            data['post_i'] = Bool(True) if 'i' in argmap[sarg] else Bool(current + "_post_i")
            data['post_f'] = Bool(True) if 'f' in argmap[sarg] else Bool(current + "_post_f")

def freeze_node (G, node):
    changes = 0
    n = G.node[node]
    frozen = freeze(n['sec'])
    if  frozen != n['sec']:
        n['sec'] = frozen
        changes += 1
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        frozen = freeze(data['sec'])
        if frozen != data['sec']:
            data['sec'] = frozen
            changes += 1
    return changes

def get_inputs (G, node, arglist):
    result = {}

    # retrieve security sets from in edges
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']
        if not darg in arglist:
            raise Exception, "Node '" + node + "' has invalid input parameter '" + darg + "'"
        if darg in result:
            raise Exception, "Duplicate input for node '" + node + "', argument '" + darg + "'"
        result[darg] = data['sec']

    # is something missing
    for arg in arglist:
        if not arg in result.keys():
            raise Exception, "Argument '" + arg + "' not found for node '" + node + "'"

    return result

def set_inputs (G, node, argmap):

    changes = 0
    seen = {}

    # retrieve input security sets from in edges
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']
        if darg in seen:
            raise Exception, "Node '" + current + "' receives duplicate input parameter '" + darg + "'"
        if not darg in argmap:
            raise Exception, "Node '" + current + "' receives invalid input parameter '" + darg + "' from '" + parent + "'"
        if data['sec'] != argmap[darg]:
            data['sec'] = argmap[darg]
            changes += 1
        del argmap[darg]
        seen[darg] = True

        if data['sec'] == None:
            data['sec'] = sec_empty();

    if argmap:
        raise Exception, "Node '" + node + "' has no flow for arguments " + str(list(argmap.keys()))

    return changes

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

def check_input (G, node, args, param, threshold): 
    if args[param] > threshold:
        print "ERROR: Security guarantees of '" + param + "' input parameter exceeded for '" + node + "' (" + fmtsec(args[param]) + " < " + fmtsec(threshold) + ")"
        for (parent, current, data) in G.in_edges(nbunch=node, data=True):
            if data['darg'] == param:
                data['extralabel'] = "\n[" + fmtsec(threshold) + " > " + fmtsec(args[param]) + "]"
                data['color'] = "orange"

def check_output (G, node, args, param, threshold):
    if not args[param] <= threshold:
        print "ERROR: Security guarantees of '" + param + "' output parameter exceeded for '" + node + "' (" + fmtsec(args[param]) + " < " + fmtsec(threshold) + ")"
        for (current, child, data) in G.out_edges(nbunch=node, data=True):
            if data['darg'] == param:
                data['extralabel'] = "\n[" + fmtsec(threshold) + " > " + fmtsec(args[param]) + "]"
                data['color'] = "orange"

def validate_graph (G):

    for node in G:
        for (parent, node, data) in G.in_edges(nbunch=node, data=True):
            if "extralabel" in data:
                del data["extralabel"]
            if "style" in data:
                del data["style"]
        for (node, child, data) in G.in_edges(nbunch=node, data=True):
            if "extralabel" in data:
                del data["extralabel"]
            if "style" in data:
                del data["style"]

    for node in G:
        n = G.node[node]
        kind = n['kind']
        present_args = []
        used_args = {}

        if 'args' in n:
            for pa in n['args']:
                present_args.append(pa)

        for (parent, current, data) in G.in_edges(nbunch=node, data=True):
            used_args[data['darg']] = parent

        if kind == 'const':

            pass
            # All outgoing environments must at least guarantee the const sec set
            # for (current, child, data) in G.out_edges(nbunch=node, data=True):
            #     if "c" in n['sec'] and not "c" in data['sec']:
            #         print "ERROR: confidentiality not guaranteed between '" + current + "' and '" + child + "'"
            #         data['color'] = 'orange'
            #         data['extralabel'] = "\n[" + fmtsec(n['sec']) + ">" + fmtsec(data['sec']) + "]"

        elif kind == 'xform':

            # TODO: Right now I have no good understanding of how to validate this
            pass

        elif kind == 'guard':

            present_args += ['data', 'cond']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['data'])
            check_input (G, node, inputs, 'cond', sec_i());
            check_output (G, node, outputs, 'data', inputs['data'])

        elif kind == 'rand':

            present_args += ['len']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['data'])
            check_input (G, node, inputs, 'len', sec_i())
            check_output (G, node, outputs, 'data', sec_cif())

        elif kind == 'hash':

            present_args += ['msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['hash'])
            # FIXME: No useful checks possible here?

        elif kind == 'verify_hash':

            present_args += ['hash', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg'])
            check_input (G, node, inputs, 'hash', sec_empty())
            check_input (G, node, inputs, 'msg', outputs['msg'])

        elif kind == 'hmac':

            present_args += ['key', 'msg']
            inputs = get_inputs(G, node, present_args)
            check_input (G, node, inputs, 'key', sec_ci())

        elif kind == 'hmac_inline':

            present_args += ['key', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg', 'auth'])
            check_input (G, node, inputs, 'key', sec_ci())

        elif kind == 'verify_hmac':

            present_args += ['key', 'auth', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg'])
            check_input (G, node, inputs, 'key', sec_ci())
            check_input (G, node, inputs, 'msg', outputs['msg'] - sec_i())

        elif kind == 'sign':

            present_args += ['pkey', 'skey', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['auth'])
            check_input (G, node, inputs, 'pkey', sec_i())
            check_input (G, node, inputs, 'skey', sec_ci())
            #check_input (G, node, inputs, 'msg', outputs['auth'] - sec_i())

        elif kind == 'verify_sig':

            present_args += ['pkey', 'auth', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg'])
            check_input (G, node, inputs, 'pkey', sec_i())
            #check_input (G, node, inputs, 'msg', outputs['msg'] | sec_i())

        elif kind == 'dhpub':

            present_args += ['gen', 'psec']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['pub', 'psec'])
            check_input (G, node, inputs, 'gen', sec_i())
            check_input (G, node, inputs, 'psec', sec_cif())
            check_output (G, node, outputs, 'psec', sec_ci())

        elif kind == 'dhsec':

            present_args += ['pub', 'psec']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['ssec'])
            check_input (G, node, inputs, 'psec', sec_ci())

        elif kind == 'encrypt':

            present_args += ['iv', 'key', 'plaintext']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['ciphertext'])

            if sec_ci() <= inputs['key']:
                sec_iv = sec_i()
                delta_pt = sec_ci()
            else:
                sec_iv = sec_empty()
                delta_pt = sec_empty()

            check_input (G, node, inputs, 'iv', sec_iv)
            check_output (G, node, outputs, 'ciphertext', inputs['plaintext'] - delta_pt);

        elif kind == 'decrypt':

            present_args += ['iv', 'key', 'ciphertext']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['plaintext'])

            if "c" in outputs['plaintext']:
                delta_ct = sec_c()
                sec_iv = sec_i()
            else:
                delta_ct = sec_empty()
                sec_iv = sec_empty()

            check_input (G, node, inputs, 'iv', sec_iv);
            check_output (G, node, outputs, 'plaintext', inputs['ciphertext'] | delta_ct);

        elif kind == 'release':

            present_args += ['data']

        else:
            raise Exception, "ERROR: unhandled " + kind

        for pa in present_args:
            if not pa in used_args:
                print "ERROR: Node '" + node + "' has unused argument '" + pa + "'"
        for ua in used_args:
            if not ua in present_args:
                print "ERROR: Parent '" + used_args[ua] + "' uses non-existent argument '" + ua + "' of node '" + node + "'"

        # Check for edges still having unfrozen security sets
        for (parent, child, data) in G.edges(data=True):
            frozen = freeze(data['sec'])
            if data['sec'] != frozen and not 'extralabel' in data:
                data['color'] = "orange"
                data['extralabel'] = "\n[UNFROZEN]"

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

def write_graph(G, title):

    global iteration
    global output 
    global pdfs
    out = "graph_" + str(iteration).zfill(4) + "_" + output
    iteration += 1

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
    
    pd = nx.drawing.nx_pydot.to_pydot(G)
    pd.set_name("sdg")
    pd.set ("splines", "ortho")
    pd.set ("forcelabels", "true")
    pd.set ("nodesep", "0.5")
    pd.set ("pack", "true")
    pd.set ("size", "15.6,10.7")
    pd.set ("label", title + "/" + str(iteration))
    pd.set ("labelloc", "t")
    pd.write(out + ".dot")
    subprocess.check_output (["dot", "-T", "pdf", "-o", out, out + ".dot"]);
    pdfs.append(out)
    #os.remove (out + ".dot")

def set_out_c (G, node, sarg, value):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            data['out_var_c'] = value

def set_out_i (G, node, sarg, value):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            data['out_var_i'] = value

def set_out_f (G, node, sarg, value):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            data['out_var_f'] = value

def get_out_c (G, node, sarg):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            return data['out_var_c']

def get_out_i (G, node, sarg):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            return data['out_var_i']

def get_out_f (G, node, sarg):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            return data['out_var_f']

def get_in_c (G, node, darg):
    for (current, child, data) in G.in_edges(nbunch=node, data=True):
        if data['darg'] == darg:
            return data['in_var_c']

def get_in_i (G, node, darg):
    for (current, child, data) in G.in_edges(nbunch=node, data=True):
        if data['darg'] == darg:
            return data['in_var_i']

def get_in_f (G, node, darg):
    for (current, child, data) in G.in_edges(nbunch=node, data=True):
        if data['darg'] == darg:
            return data['in_var_f']

def init_in_vars(G, node, db, solver, darg):
    for (parent, current, data) in G.in_edges(nbunch=node, data=True):
        if data['darg'] == darg:
            data['in_var_c'] = Bool(node + "_" + data['darg'] + "_in_c")
            data['in_var_i'] = Bool(node + "_" + data['darg'] + "_in_i")
            data['in_var_f'] = Bool(node + "_" + data['darg'] + "_in_f")

            assert_and_track (db, solver, data['out_var_c'] == data['in_var_c'], node + "_" + darg + "_inout_c")
            assert_and_track (db, solver, data['out_var_i'] == data['in_var_i'], node + "_" + darg + "_inout_i")
            assert_and_track (db, solver, data['out_var_f'] == data['in_var_f'], node + "_" + darg + "_inout_f")

def init_out_vars(G, node, solver, sarg):
    for (current, child, data) in G.out_edges(nbunch=node, data=True):
        if data['sarg'] == sarg:
            data['out_var_c'] = Bool(node + "_" + data['darg'] + "_out_c")
            data['out_var_i'] = Bool(node + "_" + data['darg'] + "_out_i")
            data['out_var_f'] = Bool(node + "_" + data['darg'] + "_out_f")

def secset (c, i, f):
    result = sec_empty()
    if c == True:
        result |= sec_c()
    if i == True:
        result |= sec_i()
    if f == True:
        result |= sec_f()
    return result

def analyze_satisfiability (G):

    assert_db = {}
    s = Solver()
    s.set(unsat_core=True)

    for node in nx.topological_sort (G):
        analyze_sat (G, assert_db, node, s)

    if s.check() == sat:
        print "Solution found"
        m = s.model()
        for (parent, child, data) in G.edges(data=True):
            c = str(m.evaluate(data['out_var_c'])) == "True"
            i = str(m.evaluate(data['out_var_i'])) == "True"
            f = str(m.evaluate(data['out_var_f'])) == "True"
            data['sec'] = secset (c, i, f)
    else:
        print "No solution"
        for p in s.unsat_core():
            print "   " + str(simplify(assert_db[str(p)]))

def assert_and_track (db, s, cond, name):
    db[name] = cond
    s.assert_and_track (cond, name)

def analyze_sat (G, db, node, s):

    n = G.node[node]
    kind = n['kind']

    if kind == "xform":

        has_source = False
        has_sink   = False

        c = []
        i = []
        f = []

        for (parent, current, data) in G.in_edges(nbunch=node, data=True):
            has_source = True
            init_in_vars (G, node, db, s, data['darg'])
            c.append (get_in_c (G, node, data['darg']))
            i.append (get_in_i (G, node, data['darg']))
            f.append (get_in_f (G, node, data['darg']))

        for (current, child, data) in G.out_edges(nbunch=node, data=True):
            has_sink = True
            init_out_vars (G, node, s, data['sarg'])
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
                sarg = data['sarg']
                c = Bool(node + "_" + sarg + "_sink_c")
                i = Bool(node + "_" + sarg + "_sink_i")
                f = Bool(node + "_" + sarg + "_sink_f")
                assert_and_track (db, s, Implies (data['in_var_c'], c), current + "_xform_" + sarg + "_in_c")
                assert_and_track (db, s, Implies (data['in_var_i'], i), current + "_xform_" + sarg + "_in_i")
                assert_and_track (db, s, Implies (data['in_var_f'], f), current + "_xform_" + sarg + "_in_f")
                val_c = c if 'c' in n['sec'] else Not(c)
                val_i = i if 'i' in n['sec'] else Not(i)
                val_f = f if 'f' in n['sec'] else Not(f)
                assert_and_track (db, s, val_c, current + "_sink_" + sarg + "_sec_c")
                assert_and_track (db, s, val_i, current + "_sink_" + sarg + "_sec_i")
                assert_and_track (db, s, val_f, current + "_sink_" + sarg + "_sec_f")

        elif has_sink:
            # Source:
            # Assert all outgoing edges to have at most the sources security level
            for (current, child, data) in G.out_edges(nbunch=node, data=True):
                darg = data['darg']
                c = Bool(node + "_" + darg + "_source_c")
                i = Bool(node + "_" + darg + "_source_i")
                f = Bool(node + "_" + darg + "_source_f")
                assert_and_track (db, s, data['out_var_c'] == c, current + "_xform_" + darg + "_out_c")
                assert_and_track (db, s, data['out_var_i'] == i, current + "_xform_" + darg + "_out_i")
                assert_and_track (db, s, data['out_var_f'] == f, current + "_xform_" + darg + "_out_f")
                val_c = c if 'c' in n['sec'] else Not(c)
                val_i = i if 'i' in n['sec'] else Not(i)
                val_f = f if 'f' in n['sec'] else Not(f)
                assert_and_track (db, s, val_c, current + "_source_" + darg + "_sec_c")
                assert_and_track (db, s, val_i, current + "_source_" + darg + "_sec_i")
                assert_and_track (db, s, val_f, current + "_source_" + darg + "_sec_f")
        else:
            # no incoming and no outgoing edges? This is an error.
            raise Exception, "xform with no edges: " + node

    elif kind == "const":
        init_out_vars (G, node, s, "const")

    elif kind == "rand":
        init_in_vars (G, node, db, s, "len")
        init_out_vars (G, node, s, "data")

        # Length input parameter needs integrity
        assert_and_track (db, s, get_in_i (G, node, "len"), node + "_rand_len_in_i")

        # Output data parameter provides confidentiality, integrity and freshness
        assert_and_track (db, s, get_out_c (G, node, "data"), node + "_rand_data_out_c")
        assert_and_track (db, s, get_out_i (G, node, "data"), node + "_rand_data_out_i")
        assert_and_track (db, s, get_out_f (G, node, "data"), node + "_rand_data_out_f")

    elif kind == "dhpub":
        init_in_vars (G, node, db, s, "gen")
        init_in_vars (G, node, db, s, "psec")
        init_out_vars (G, node, s, "pub")
        init_out_vars (G, node, s, "psec")

        # Generator needs integrity
        assert_and_track (db, s, get_in_i (G, node, "gen"), node + "_dhpub_gen_in_i")

        # Secret psec requires confidentiality, integrity and freshness
        assert_and_track (db, s, get_in_c (G, node, "psec"), node + "_dhpub_psec_in_c")
        assert_and_track (db, s, get_in_i (G, node, "psec"), node + "_dhpub_psec_in_j")
        assert_and_track (db, s, get_in_f (G, node, "psec"), node + "_dhpub_psec_in_f")

        # Output secret psec only guarantees confidentiality, integrity
        assert_and_track (db, s, get_out_c (G, node, "psec"), node + "_dhpub_psec_out_c")
        assert_and_track (db, s, get_out_i (G, node, "psec"), node + "_dhpub_psec_out_i")

    elif kind == "dhsec":
        init_in_vars (G, node, db, s, "pub")
        init_in_vars (G, node, db, s, "psec")
        init_out_vars (G, node, s, "ssec")

        # Input secret psec requires confidentiality and integrity
        assert_and_track (db, s, get_in_c (G, node, "psec"), node + "_dhsec_psec_in_c")
        assert_and_track (db, s, get_in_i (G, node, "psec"), node + "_dhsec_psec_in_i")

        # Output secret ssec requires confidentiality
        assert_and_track (db, s, get_out_c (G, node, "ssec"), node + "dhsec_ssec_out_c")
        assert_and_track (db, s, get_in_i (G, node, "pub") == get_out_i (G, node, "ssec"), node + "dhsec_ssec_inout_i")
        assert_and_track (db, s, get_in_f (G, node, "pub") == get_out_f (G, node, "ssec"), node + "dhsec_ssec_inout_f")

    elif kind == "hash":
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "hash")

        # FIXME: How about situations where confidentiality is removed by hashing (e.g. passwords)?
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "hash")), node + "_hash_hash_out_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "msg"), get_out_i (G, node, "hash")), node + "_hash_hash_out_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "hash")), node + "_hash_hash_out_f")

    elif kind == "encrypt":
        init_in_vars (G, node, db, s, "iv")
        init_in_vars (G, node, db, s, "key")
        init_in_vars (G, node, db, s, "plaintext")
        init_out_vars (G, node, s, "ciphertext")

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
        assert_and_track (db, s, Implies (get_in_f (G, node, "plaintext"), get_out_f (G, node, "ciphertext")), node + "_encrypt_ciphertext_f" )

    elif kind == "decrypt":
        init_in_vars (G, node, db, s, "iv")
        init_in_vars (G, node, db, s, "key")
        init_in_vars (G, node, db, s, "ciphertext")
        init_out_vars (G, node, s, "plaintext")

        security  = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"), get_in_i (G, node, "iv"))
        freshness = Or (get_in_f (G, node, "iv"), get_in_f (G, node, "key"))
        assert_and_track (db, s, Implies (get_out_c (G, node, "plaintext"), And (security, freshness)), node + "_decrypt_plaintext_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "ciphertext"), get_out_i (G, node, "plaintext")), node + "_decrypt_plaintext_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "ciphertext"), get_out_f (G, node, "plaintext")), node + "_decrypt_plaintext_f" )

    elif kind == "verify_hash":
        init_in_vars (G, node, db, s, "hash")
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "msg")
        assert_and_track (db, s, Implies (get_in_c (G, node, "hash"), get_out_c (G, node, "msg")), node + "_verify_hash_msg_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "hash"), get_out_i (G, node, "msg")), node + "_verify_hash_msg_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "hash"), get_out_f (G, node, "msg")), node + "_verify_hash_msg_f")

    elif kind == "verify_hmac":
        init_in_vars (G, node, db, s, "key")
        init_in_vars (G, node, db, s, "auth")
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "msg")

        security = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"))
        assert_and_track (db, s, Implies (get_out_i (G, node, "msg"), security), node + "_verify_hmac_msg_i")
        assert_and_track (db, s, Implies (get_in_i (G, node, "msg"), get_out_i (G, node, "msg")), node + "_verify_hmac_msg_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "msg")), node + "_verify_hmac_msg_f")

    elif kind == "hmac":
        init_in_vars (G, node, db, s, "key")
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "auth")

        security = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"))
        assert_and_track (db, s, Implies (get_in_i (G, node, "msg"), security), node + "_hmac_msg_i")

    elif kind == "hmac_inline":
        init_in_vars (G, node, db, s, "key")
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "msg")
        init_out_vars (G, node, s, "auth")

        # FIXME: Check!
        security = And (get_in_c (G, node, "key"), get_in_i (G, node, "key"))
        assert_and_track (db, s, Implies (And (security, get_in_i (G, node, "msg")), Not (get_out_i (G, node, "msg"))), node + "_hmac_msg_i")
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "msg")), node + "_hmac_inline_msg_c")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "msg")), node + "_hmac_inline_msg_f")

    elif kind == "sign":
        init_in_vars (G, node, db, s, "pkey")
        init_in_vars (G, node, db, s, "skey")
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "auth")

        security = And (get_in_c (G, node, "skey"), get_in_i (G, node, "skey"), get_in_i (G, node, "pkey"))
        assert_and_track (db, s, Implies (get_out_i (G, node, "auth"), security), node + "_sign_auth_i")
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "auth")), node + "_sign_auth_c")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "auth")), node + "_sign_auth_f")

    elif kind == "verify_sig":
        init_in_vars (G, node, db, s, "pkey")
        init_in_vars (G, node, db, s, "auth")
        init_in_vars (G, node, db, s, "msg")
        init_out_vars (G, node, s, "msg")

        assert_and_track (db, s, Implies (get_out_i (G, node, "msg"), get_in_i (G, node, "pkey")), node + "_verify_sig_msg_i")
        assert_and_track (db, s, Implies (get_in_c (G, node, "msg"), get_out_c (G, node, "msg")), node + "_verify_sig_msg_c")
        assert_and_track (db, s, Implies (get_in_f (G, node, "msg"), get_out_f (G, node, "msg")), node + "_verify_sig_msg_f")

    elif kind == "release":
        init_in_vars (G, node, db, s, "data")
        init_out_vars (G, node, s, "data")

        assert_and_track (db, s, Implies (get_in_c (G, node, "data"), Not(get_out_c (G, node, "data"))), node + "_release_data_c")
        assert_and_track (db, s, Implies (get_in_i (G, node, "data"), Not(get_out_i (G, node, "data"))), node + "_release_data_i")
        assert_and_track (db, s, Implies (get_in_f (G, node, "data"), Not(get_out_f (G, node, "data"))), node + "_release_data_f")

    elif kind == "guard":
        init_in_vars (G, node, db, s, "data")
        init_in_vars (G, node, db, s, "cond")
        init_out_vars (G, node, s, "data")

        assert_and_track (db, s, get_in_i (G, node, "cond"), node + "_guard_cond_i")
        assert_and_track (db, s, get_in_c (G, node, "data") == get_out_c (G, node, "data"), node + "_guard_data_c")
        assert_and_track (db, s, get_in_i (G, node, "data") == get_out_i (G, node, "data"), node + "_guard_data_i")
        assert_and_track (db, s, get_in_f (G, node, "data") == get_out_f (G, node, "data"), node + "_guard_data_f")

    else:
        raise Exception, "Unhandled primitive '" + kind + "'"

def main(args):
    global output

    # validate graph
    print subprocess.check_output (["xmllint", "--noout", "--schema", "spg.xsd", args.input[0]]);

    G = parse_graph (args.input[0])
    output = args.output[0]

    validate_graph (G)
    analyze_satisfiability(G)
    write_graph(G, "Final")

    print "PDFs: " + str(pdfs)

    a = ["pdftk"] + pdfs + ["cat", "output", args.output[0]]
    subprocess.check_output (a)
    for pdf in pdfs:
        os.remove (pdf)

parser = argparse.ArgumentParser(description='SPG Analyzer')
parser.add_argument('--input', action='store', nargs=1, required=True, help='Input file', dest='input');
parser.add_argument('--output', action='store', nargs=1, required=True, help='Output file', dest='output');
parser.add_argument('--incremental', action='store_true', help='Create incremental PDF', dest='incremental');
main(parser.parse_args ())
