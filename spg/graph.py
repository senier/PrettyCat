import os
import networkx as nx

from lxml import etree
from io   import StringIO

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
        if 'assert_fail' in root.attrib and root.attrib['assert_fail'] == 'true':
            self.fail = True
    
        if 'code' in root.attrib:
            self.code = root.attrib['code']
        else:
            self.code = os.path.splitext(os.path.basename (inpath))[0]
    
        self.graph = nx.MultiDiGraph()
    
        # read in graph
        for child in root.iterchildren(tag = etree.Element):
    
            name  = child.attrib["id"]
    
            descnode = child.find('description')
            # if descnode is not None:
            #     desc = "<" + child.tag + ":&#10;" + re.sub ('\n\s*', '&#10;', descnode.text.strip()) + ">"
            # else:
            #     warn ("No description for " + name)
            #     desc = "<No description&#10;available.>"
    
            kind       = child.tag
            classname  = child.attrib['code'] if 'code' in child.attrib else None
    
            config     = child.find('config')
            guarantees = self.parse_guarantees (child.attrib)
    
            self.graph.add_node \
                (name, \
                 kind       = kind, \
                 classname  = classname, \
                 config     = config, \
                 guarantees = guarantees, \
                 arguments  = [ arg.attrib['name'] for arg in child.findall('arg')],
                 controlled = [ arg.attrib['name'] for arg in child.findall('arg') if 'controlled' in arg.attrib],
                 outputs    = [ arg.attrib['sarg'] for arg in child.findall('flow')],
                 desc       = descnode)
    
            for element in child.findall('flow'):
                sarg       = element.attrib['sarg']
                darg       = element.attrib['darg']
    
                assert_c = None
                assert_i = None
    
                for assertion in element.findall('assert'):
                    assert_c = self.parse_bool (assertion.attrib, 'confidentiality')
                    assert_i = self.parse_bool (assertion.attrib, 'integrity')
    
                self.graph.add_edge (name, element.attrib['sink'], \
                    sarg = sarg, \
                    darg = darg, \
                    assert_c = assert_c, \
                    assert_i = assert_i)

    def parse_bool (self, attrib, name):
        if not name in attrib:
            return None
        if attrib[name] == "true":
            return True
        if attrib[name] == "false":
            return False
        raise Exception ("Invalid boolean value for '" + name + "'")

    def parse_guarantees (self, attribs):
        return {
            'c': self.parse_bool (attribs, 'confidentiality'),
            'i': self.parse_bool (attribs, 'integrity'),
        }

    def num_nodes (self):
        return len(self.graph.node)

