import sys
import os

import networkx as nx

from lxml import etree
from io   import StringIO

from spg.error import info, warn, err

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

class Graph:
    
    def __init__ (self, inpath):

        self.graph = None
        self.fail  = False

        try:
            schema_doc = etree.parse(schema_src)
            self.schema = etree.XMLSchema (schema_doc)
        except etree.XMLSchemaParseError as e:
            err ("Error compiling schema: " + str(e))
            raise
    
        try:
            tree = etree.parse (inpath)
        except (IOError, etree.XMLSyntaxError) as e:
            err (inpath + ": " + str(e))
            raise
    
        if not self.schema.validate (tree):
            err (inpath + self.schema.error_log.last_error)
            raise
    
        root = tree.getroot()
        if 'assert_fail' in root.attrib and root.attrib['assert_fail'] == 'true':
            self.fail = True
    
        if 'code' in root.attrib:
            self.code = root.attrib['code']
        else:
            self.code = os.path.splitext(os.path.basename (inpath))[0]
    
        self.graph = nx.MultiDiGraph()
    
        # read in graph
        for child in root.iterchildren(tag = etree.Element):
    
            name = child.attrib["id"]
            desc = child.find('description')
            kind = child.tag
            code = child.attrib['code'] if 'code' in child.attrib else None
    
            config     = child.find('config')
            guarantees = self.__parse_guarantees (child.attrib)
    
            self.graph.add_node \
                (name, \
                 kind       = kind, \
                 classname  = code, \
                 config     = config, \
                 guarantees = guarantees, \
                 arguments  = [ arg.attrib['name'] for arg in child.findall('arg')],
                 controlled = [ arg.attrib['name'] for arg in child.findall('arg') if 'controlled' in arg.attrib],
                 outputs    = [ arg.attrib['sarg'] for arg in child.findall('flow')],
                 desc       = desc)
    
            for element in child.findall('flow'):
                sarg       = element.attrib['sarg']
                darg       = element.attrib['darg']
    
                assertion = None
    
                for ass in element.findall('assert'):
                    assertion = self.__parse_guarantees (ass.attrib)
    
                self.graph.add_edge (name, element.attrib['sink'], \
                    sarg = sarg, \
                    darg = darg, \
                    assertion = assertion)

    def __parse_bool (self, attrib, name):
        if not name in attrib:
            return None
        if attrib[name] == "true":
            return True
        if attrib[name] == "false":
            return False
        raise Exception ("Invalid boolean value for '" + name + "'")

    def __parse_guarantees (self, attribs):
        return {
            'c': self.__parse_bool (attribs, 'confidentiality'),
            'i': self.__parse_bool (attribs, 'integrity'),
        }

    def num_nodes (self):
        return len(self.graph.node)

    def __set_bool (self, value):
        return 'true' if value else 'false'

    def __add_guarantees (self, attrib, guarantees):

        if 'c' in guarantees:
            c = guarantees['c']
            if not c is None:
                attrib['confidentiality'] = self.__set_bool (c)

        if 'i' in guarantees:
            i = guarantees['i']
            if not i is None:
                attrib['integrity'] = self.__set_bool (i)

    def write (self, outpath):

        G = self.graph
        attrib = {}

        if 'assert_fail' in G:
            attrib['assert_fail'] = self.__set_bool (G['assert_fail'])

        if 'code' in G:
            attrib['code'] = G['code']

        root = etree.Element('spg', attrib = attrib)

        for node in sorted(G.node):

            attrib = {'id': node}

            if 'classname' in G.node[node] and G.node[node]['classname'] != None:
                attrib['code'] = G.node[node]['classname']

            self.__add_guarantees (attrib, G.node[node]['guarantees'])

            n = etree.SubElement (root, G.node[node]['kind'], attrib = attrib)
            n.append (G.node[node]['desc'])

            if not G.node[node]['config'] is None:
                n.append (G.node[node]['config'])

            for (parent, child, data) in sorted(G.out_edges (nbunch = node, data = True), key=(lambda e: e[1] + e[2]['darg'])):
                flow = etree.SubElement (n, 'flow', attrib = {'sarg': data['sarg'], 'sink': child, 'darg': data['darg']})
                if 'assertion' in data and not data['assertion'] is None:
                    assert_attrib = {}
                    self.__add_guarantees (assert_attrib, data['assertion'])
                    etree.SubElement (flow, 'assert', attrib = assert_attrib)

            for arg in sorted([arg for arg in G.node[node]['arguments'] if arg not in G.node[node]['controlled']]):
                etree.SubElement (n, 'arg', attrib = {'name': arg})
            for arg in sorted(G.node[node]['controlled']):
                etree.SubElement (n, 'arg', attrib = {'name': arg, 'controlled': 'true'})

        if not self.schema.validate (root):
            raise InternalError ("Output document does not validate: " + self.schema.error_log.last_error)

        doc = etree.ElementTree (root)
        doc.write (outpath, encoding='UTF-8', xml_declaration=True)
