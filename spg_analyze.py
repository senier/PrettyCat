#!/usr/bin/python

import xml.etree.ElementTree as ET
import networkx as nx
import sys

free_arguments = {
    'xform':        None,
    'send':         ['msg'],
    'guard':        ['data'],
    'hash':         ['msg'],
    'verify_hash':  ['msg'],
    'hmac':         ['msg'],
    'hmac_inline':  ['msg'],
    'verify_hmac':  ['msg'],
    'sign':         ['msg'],
    'verify_sig':   ['msg'],
    'dhsec':        ['pub'],
    'encrypt':      ['plaintext'],
    'decrypt':      ['ciphertext'],
    'release':      ['data']
}

def sec_empty():
    return set(())

def sec_f():
    return set(("f"))

def sec_c():
    return set(("c"))

def sec_i():
    return set(("i"))

def sec_ci():
    return set(("c", "i"))

def sec_cif():
    return set(("c", "i", "f"))

def sec_max():
    return set(("f", "c", "i"))

def fmtsec(sec):
    if not sec:
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
    return "{" + result + "}";

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

    seen = {}

    # retrieve output security sets from out edges
    for (current, child, data) in G.out_edges (nbunch=node, data=True):
        sarg = data['sarg']
        darg = data['darg']
        if not sarg in argmap:
            raise Exception, "Node '" + current + "' passes invalid output parameter '" + sarg + "' to '" + child + "'"

        if data['sec'] < argmap[sarg]:
            # Upgrading is always OK, as it just increases the security requirements imposed on the environment
            data['sec'] = argmap[sarg]
        elif data['sec'] > argmap[sarg]:
            kind = G.node[child]['kind']
            if kind in free_arguments and (free_arguments[kind] == None or darg in free_arguments[kind]):
                data['sec'] = argmap[sarg]
            else:
                # Downgrade is allowed only for 'free' parameters
                print "ERROR: Downgrade required between " + current + " ===> " + child

        seen[sarg] = True

    for s in seen:
        del argmap[s]

    if argmap:
        raise Exception, "Node '" + node + "' has no arguments " + str(list(argmap.keys()))

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

    seen = {}

    # retrieve input security sets from in edges
    for (parent, current, data) in G.in_edges (nbunch=node, data=True):
        darg = data['darg']
        if darg in seen:
            raise Exception, "Node '" + current + "' receives duplicate input parameter '" + darg + "'"
        if not darg in argmap:
            raise Exception, "Node '" + current + "' receives invalid input parameter '" + darg + "' from '" + parent + "'"
        data['sec'] = argmap[darg]
        del argmap[darg]
        seen[darg] = True

    if argmap:
        raise Exception, "Node '" + node + "' has no flow for arguments " + str(list(argmap.keys()))

def analyze(G, start):

    # Get node attribute set
    node = G.node[start]
    kind = node['kind']

    if kind == "send":
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            G.node[parent]['sec'] = node['sec']

    elif kind == "xform":
        sec = sec_empty()
        for (parent, child, data) in G.out_edges(nbunch=start, data=True):
            sec |= data['sec']
        for (parent, child, data) in G.in_edges(nbunch=start, data=True):
            data['sec'] = sec

    elif kind == "guard":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'data': out['data'], 'cond': sec_i()})

    elif kind == "sign":
        out = get_outputs (G, start, ['auth'])
        set_inputs (G, start, {'skey': sec_ci(), 'pkey': sec_i(), 'msg': sec_i()})

    elif kind == "verify_sig":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'pkey': sec_i(), 'auth': sec_empty(), 'msg': out['msg'] - sec_i()})

    elif kind == "hmac":
        out = get_outputs (G, start, ['auth'])
        set_inputs (G, start, {'key': sec_ci(), 'msg': sec_empty()})

    elif kind == "hmac_inline":
        out = get_outputs (G, start, ['auth', 'msg'])
        set_inputs (G, start, {'key': sec_ci(), 'msg': out['msg'] | sec_i()})

    elif kind == "verify_hmac":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'key': sec_ci(), 'auth': sec_empty(), 'msg': out['msg'] - sec_i()})

    elif kind == "encrypt":
        out = get_outputs (G, start, ['ciphertext'])
        set_inputs (G, start, {'key': sec_ci(), 'iv': sec_i(), 'plaintext': out['ciphertext'] | sec_c()})

    elif kind == "decrypt":
        out = get_outputs (G, start, ['plaintext'])

        if sec_c() in out['plaintext']:
            iv_sec = sec_i()
            key_sec = sec_ci()
        else:
            iv_sec = sec_empty()
            key_sec = sec_empty()

        set_inputs (G, start, {'key': key_sec, 'iv': iv_sec, 'ciphertext': out['plaintext'] - sec_c()})

    elif kind == "hash":
        out = get_outputs (G, start, ['hash'])
        set_inputs (G, start, {'msg': out['hash'] | sec_c()})

    elif kind == "verify_hash":
        out = get_outputs (G, start, ['msg'])
        set_inputs (G, start, {'hash': sec_empty(), 'msg': out['msg']})

    elif kind == "dhsec":
        out = get_outputs (G, start, ['ssec'])
        set_inputs (G, start, {'pub': sec_i(), 'psec': sec_ci()})

    elif kind == "dhpub":
        out = get_outputs (G, start, ['pub', 'psec'])
        set_inputs (G, start, {'gen': sec_i(), 'psec': sec_cif()})

    elif kind == "rand":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'len': sec_i()})

    elif kind == "release":
        out = get_outputs (G, start, ['data'])
        set_inputs (G, start, {'data': sec_ci()})

    elif kind == "const":

        sec = sec_empty()
        for (parent, child, data) in G.out_edges(nbunch=start, data=True):
            sec |= data['sec']
        node['sec'] = sec

    elif kind == "receive":
        pass

    else:
        raise Exeception, "Unknown kind: " + str(kind)

    for (parent, current, data) in G.in_edges(nbunch=start, data=True):
        analyze(G, parent);

def convert_setset (attrib):
    result = sec_empty()
    if "confidentiality" in attrib and attrib["confidentiality"] == "True":
        result |= sec_c()
    if "integrity" in attrib and attrib["integrity"] == "True":
        result |= sec_i()
    if "freshness" in attrib and attrib["freshness"] == "True":
        result |= sec_f()
    return result

def forward_adjust (G, node):

    n = G.node[node]
    kind = n['kind']

    if kind == "receive":
        for (current, parent, data) in G.out_edges (nbunch=node, data=True):
            if n['sec'] <= data['sec']:
                data['sec'] = n['sec']

    elif kind == "xform":
        sec = sec_empty()
        for (parent, current, data) in G.in_edges (nbunch=node, data=True):
            sec |= data['sec']
        for (parent, current, data) in G.out_edges (nbunch=node, data=True):
            data['sec'] = sec

    elif kind == "const":
        for (parent, current, data) in G.out_edges (nbunch=node, data=True):
            data['sec'] = n['sec'] 

    elif kind == "decrypt":
        inputs = get_inputs (G, node, ['iv', 'key', 'ciphertext'])
        delta  = sec_c() if sec_ci() <= inputs['key'] else sec_empty()
        set_outputs (G, node, { 'plaintext': inputs['ciphertext'] | delta})

    elif kind == "encrypt":
        inputs = get_inputs (G, node, ['iv', 'key', 'plaintext'])
        delta = sec_c() if sec_ci() <= inputs['key'] else sec_empty()
        set_outputs (G, node, { 'ciphertext': inputs['plaintext'] - delta})

    elif kind == "verify_sig":
        inputs = get_inputs (G, node, ['pkey', 'auth', 'msg'])
        set_outputs (G, node, { 'msg': inputs['msg'] | sec_i()})

    elif kind == "hmac_inline":
        inputs = get_inputs (G, node, ['key', 'msg'])
        set_outputs (G, node, { 'auth': sec_empty(), 'msg': inputs['msg'] - sec_i()})

    elif kind == "verify_hmac":
        inputs = get_inputs (G, node, ['key', 'auth', 'msg'])
        set_outputs (G, node, { 'msg': inputs['msg'] | sec_i()})

    elif kind == "hash":
        inputs = get_inputs (G, node, ['msg'])
        set_outputs (G, node, { 'hash': inputs['msg'] - sec_c()})

    elif kind == "verify_hash":
        inputs = get_inputs (G, node, ['hash', 'msg'])
        set_outputs (G, node, { 'msg': inputs['msg']})

    elif kind == "guard":
        inputs = get_inputs (G, node, ['data', 'cond'])
        set_outputs (G, node, { 'data': inputs['data']})

    elif kind == "dhsec":
        inputs = get_inputs (G, node, ['pub', 'psec'])
        set_outputs (G, node, { 'ssec': sec_ci()})

    elif kind == "rand":
        set_outputs (G, node, { 'data': sec_cif()})

    elif kind == "release":
        inputs = get_inputs (G, node, ['data'])
        set_outputs (G, node, { 'data': sec_empty()})

    elif kind == "dhpub":
        inputs = get_inputs (G, node, ['gen', 'psec'])
        set_outputs (G, node, { 'pub': sec_empty(), 'psec': sec_ci()})

    elif kind == "sign":
        pass

    elif kind == "hmac":
        pass

    elif kind == "send":
        pass

    else:
        raise Exception, "Unhandled node kind: " + kind

def analyze_forward (G, start, nodelist):
    forward_adjust (G, start)
    for node in nodelist:
        forward_adjust (G, node)

def analyze_backwards (G, start):

    n = G.node[start]
    kind = n['kind']

    if kind == "decrypt":
        inputs = get_inputs (G, start, ['iv', 'key', 'ciphertext'])
        ivsec = sec_i() if sec_ci() <= inputs['key'] else sec_empty()
        set_inputs (G, start, {'iv': ivsec, 'key': inputs['key'], 'ciphertext': inputs['ciphertext']})

    elif kind == "const":
        outputs = get_outputs (G, start, ['const'])
        n['sec'] = outputs['const']

    for (parent, current, data) in G.in_edges(nbunch=start, data=True):
        analyze_backwards (G, parent);

def sec_color (sec):
    if sec == sec_empty():
        return "black"
    if sec == sec_i():
        return "blue"
    if sec == sec_c():
        return "red"
    if sec == sec_ci():
        return "purple"
    if sec == sec_cif():
        return "cyan"
    else:
        print "Missing color: " + fmtsec(sec)
        return "white"

def colorize (G, start, nodelist):
    for node in nodelist:
        n = G.node[node]
        kind = n['kind']

        if kind == "send" or kind == "const":
            outsec = n['sec']
        else:
            outsec = sec_empty()
            for (parent, child, data) in G.out_edges(nbunch=node, data=True):
                outsec |= data['sec']

        if kind == "receive" or kind == "const":
            insec = n['sec']
        else:
            insec = sec_empty()
            for (parent, child, data) in G.in_edges(nbunch=node, data=True):
                insec |= data['sec']

        n['fontname'] = "Times Bold"
        n['fontcolor'] = "gray"
        n['style'] = "filled"
        n['gradientangle'] = "90"
        n['fillcolor'] = "\"" + sec_color(insec | outsec) + "\""

def check_input (node, args, param, threshold): 
    if args[param] < threshold:
        print "ERROR: Security guarantees of '" + param + "' input parameter exceeded for '" + node + "' (" + fmtsec(args[param]) + " < " + fmtsec(threshold) + ")"
        for (parent, current, data) in G.in_edges(nbunch=node, data=True):
            if data['darg'] == param:
                data['extralabel'] = "\n[" + fmtsec(threshold) + " > " + fmtsec(args[param]) + "]"
                data['style'] = "dashed"

def check_output (node, args, param, threshold):
    if args[param] < threshold:
        print "ERROR: Security guarantees of '" + param + "' output parameter exceeded for '" + node + "' (" + fmtsec(args[param]) + " < " + fmtsec(threshold) + ")"
        for (current, child, data) in G.out_edges(nbunch=node, data=True):
            if data['darg'] == param:
                data['extralabel'] = "\n[" + fmtsec(threshold) + " > " + fmtsec(args[param]) + "]"
                data['style'] = "dashed"

def validate_graph (G):
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

        if kind == 'send':

            # All incoming edge sec sets must be a subset of send element sec set
            for (parent, current, data) in G.in_edges(nbunch=node, data=True):
                if not data['sec'] <= n['sec']:
                    print "ERROR: '" + parent + "' exceeds security guarantees of '" + current + "'"
                    data['style'] = 'dashed'
                    data['extralabel'] = "\n[" + fmtsec(data['sec']) + ">" + fmtsec(n['sec']) + "]"

        elif kind == 'receive' or kind == 'const':

            # All outgoing environments must at least guarantee the receive elements sec set
            for (current, child, data) in G.out_edges(nbunch=node, data=True):
                if not n['sec'] <= data['sec']:
                    print "ERROR: '" + child + "' exceeds security guarantees of '" + current + "'"
                    data['style'] = 'dashed'
                    data['extralabel'] = "\n[" + fmtsec(n['sec']) + ">" + fmtsec(data['sec']) + "]"

        elif kind == 'xform':

            # The outgoing environments must at least guarantee the union of all input security sets
            inputsec = sec_empty()
            for (parent, current, data) in G.in_edges(nbunch=node, data=True):
                inputsec |= data['sec']
            for (current, child, data) in G.out_edges(nbunch=node, data=True):
                if not inputsec <= data['sec']:
                    print "ERROR: '" + child + "' exceeds security guarantees of '" + current + "'"
                    data['style'] = 'dashed'
                    data['extralabel'] = "\n[" + fmtsec(inputsec) + ">" + fmtsec(data['sec']) + "]"

        elif kind == 'guard':

            present_args += ['data', 'cond']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['data'])
            check_input (node, inputs, 'cond', sec_i());
            check_output (node, outputs, 'data', inputs['data'])

        elif kind == 'rand':

            present_args += ['len']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['data'])
            check_input (node, inputs, 'len', sec_i())
            check_output (node, outputs, 'data', sec_cif())

        elif kind == 'hash':

            present_args += ['msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['hash'])
            check_input (node, inputs, 'msg', outputs['hash'] - sec_c())

        elif kind == 'verify_hash':

            present_args += ['hash', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg'])
            check_input (node, inputs, 'hash', sec_empty())
            check_input (node, inputs, 'msg', outputs['msg'])

        elif kind == 'hmac':

            present_args += ['key', 'msg']
            inputs = get_inputs(G, node, present_args)
            check_input (node, inputs, 'key', sec_ci())

        elif kind == 'hmac_inline':

            present_args += ['key', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg', 'auth'])
            check_input (node, inputs, 'key', sec_ci())
            check_input (node, inputs, 'msg', outputs['msg'] | sec_i())

        elif kind == 'verify_hmac':

            present_args += ['key', 'auth', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg'])
            check_input (node, inputs, 'key', sec_ci())
            check_input (node, inputs, 'msg', outputs['msg'] - sec_i())

        elif kind == 'sign':

            present_args += ['pkey', 'skey', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['auth'])
            check_input (node, inputs, 'pkey', sec_i())
            check_input (node, inputs, 'skey', sec_ci())
            check_input (node, inputs, 'msg', outputs['auth'] - sec_i())

        elif kind == 'verify_sig':

            present_args += ['pkey', 'auth', 'msg']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['msg'])
            check_input (node, inputs, 'pkey', sec_i())
            #check_input (node, inputs, 'msg', outputs['msg'] | sec_i())

        elif kind == 'dhpub':

            present_args += ['gen', 'psec']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['pub', 'psec'])
            check_input (node, inputs, 'gen', sec_i())
            check_input (node, inputs, 'psec', sec_cif())
            check_output (node, outputs, 'psec', sec_ci())

        elif kind == 'dhsec':

            present_args += ['pub', 'psec']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['ssec'])
            check_input (node, inputs, 'psec', sec_ci())

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

            check_input (node, inputs, 'iv', sec_iv)
            check_output (node, outputs, 'ciphertext', inputs['plaintext'] - delta_pt);

        elif kind == 'decrypt':

            present_args += ['iv', 'key', 'ciphertext']
            inputs = get_inputs(G, node, present_args)
            outputs = get_outputs(G, node, ['plaintext'])

            if sec_c() in outputs['plaintext']:
                delta_ct = sec_c()
                sec_iv = sec_i()
            else:
                delta_ct = sec_empty()
                sec_iv = sec_empty()

            check_input (node, inputs, 'iv', sec_iv);
            check_output (node, outputs, 'plaintext', inputs['ciphertext'] | delta_ct);

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

def parse_graph (path):
    try:
        root = ET.parse(path).getroot()
    except IOError as e:
        print("Error opening XML file: " + str(e))
        sys.exit(1)
    
    G = nx.MultiDiGraph();
    
    # read in graph
    for child in root:
    
        sec = None
        args = []
    
        if child.tag == "send" or child.tag == "receive":
            sec = convert_setset(child.attrib)
    
        label = "<" + child.tag + "<sub>" + child.attrib['id'] + "</sub>>"
    
        if child.tag == "xform" or child.tag == 'send':
            for arg in child.findall('arg'):
                args.append (arg.attrib['name'])

        if child.tag == "receive" or child.tag == "send":
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

G = parse_graph (sys.argv[1])

# Backwards-analyze all source nodes
for node in G.nodes():
    if not G.out_edges(nbunch=node):
        analyze(G, node)

# Forward analyse
analyze_forward(G, node, nx.topological_sort (G))

# Backwards-analyze all source nodes
for node in G.nodes():
    if not G.out_edges(nbunch=node):
        analyze_backwards(G, node)

# add edge labels
for (parent, child, data) in G.edges(data=True):
    data['xlabel']     = fmtsec(data['sec'])
    data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
    data['headlabel'] = data['darg']
    data['color'] = sec_color(data['sec'])
    data['fontcolor'] = sec_color(data['sec'])

# color nodes according to security level
colorize(G, node, nx.topological_sort (G))

validate_graph (G)

# add edge labels
for (parent, child, data) in G.edges(data=True):
    if 'extralabel' in data:
        data['xlabel'] += data['extralabel']

pd = nx.drawing.nx_pydot.to_pydot(G)
pd.set_name("sdg")
#pd.set ("size", "11.7,8.3")
pd.set ("splines", "ortho")
pd.set ("forcelabels", "true")
pd.set ("nodesep", "0.5")
pd.set ("pack", "true")
pd.set ("size", "15.6,10.7")
pd.write(sys.argv[2])
