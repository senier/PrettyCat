import networkx as nx
import spg.graph

class Layout (spg.graph.Graph):

    def __init__ (self, inpath):
        super().__init__ (inpath)

        G = self.graph
        for node in G.node:

            if G.node[node]['kind'] == "env":
                G.node[node]['shape'] = "invhouse"
            else:
                G.node[node]['shape'] = "rectangle"

            G.node[node]['label'] = "<<b>" + G.node[node]['kind'] + ": </b>" + node + ">"

            val_c = False
            val_i = False

            for (name, guarantee) in G.node[node]['inputs']:
                if guarantee.get_conf_val():
                    val_c = True
                if guarantee.get_intg_val():
                    val_i = True

            for (name, guarantee) in G.node[node]['outputs']:
                if guarantee.get_conf_val():
                    val_c = True
                if guarantee.get_intg_val():
                    val_i = True

            self.set_style (G.node[node], val_c, val_i)

        # add edge labels
        for (parent, child, data) in G.edges(data=True):

            # sarg guarantees of parent should are the same as darg guarantees of child
            darg = data['darg']
            sarg = data['sarg']

            data['taillabel'] = data['sarg'] if data['sarg'] != None else ""
            data['headlabel'] = data['darg']
            data['tooltip'] = parent + ":" + data['sarg'] + " ==> " + child + ":" + data['darg']

            pg = G.node[parent]['outputs'][sarg]
            cg = G.node[child]['inputs'][darg]
            self.set_style (data, pg.get_conf_val() and cg.get_conf_val(), pg.get_intg_val() and cg.get_intg_val())

        # Mark  unsat core if present
        #if self.unsat:
        #    for node in self.unsat:
        #        intg = False
        #        conf = False
        #        if 'input' in self.unsat[node]:
        #            for arg in self.unsat[node]['input']:
        #                a = self.unsat[node]['input'][arg]
        #                intg |= 'intg' in a
        #                conf |= 'conf' in a
        #        if 'output' in self.unsat[node]:
        #            for arg in self.unsat[node]['output']:
        #                a = self.unsat[node]['output'][arg]
        #                intg |= 'intg' in a
        #                conf |= 'conf' in a

        #        set_style (G.node[node], intg, conf, 'dashed' if intg or conf else 'filled')

        self.pd = nx.drawing.nx_pydot.to_pydot(self.graph)
        self.pd.set_name("sdg")

        # Choose fixed rng start value to get deterministic layout
        self.pd.set ("start", "1")

        self.pd.set ("sep", "+50,20")
        self.pd.set ("esep", "+10,4")
        self.pd.set ("splines", "ortho")
        self.pd.set ("size", "15.6,10.7")
        self.pd.set ("labelloc", "t")
        self.pd.set ("concentrate", "true")

    def set_style (self, o, c, i, style = None):

        if style:
            o['style'] = style
    
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
    
