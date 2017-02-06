#!/usr/bin/env python3

import re
import sys

class LineCount:

    def __init__ (self):

        self.current = None
        self.classes = {}

    def reset (self, name, deps):
        self.current = name

        if name in self.classes:
            raise Exception ("Encountered class '" + name + "' twice!")

        self.classes[name]         = {}
        self.classes[name]['deps'] = deps
        self.classes[name]['sloc'] = 0

    def analyze_line (self, line):

        # Ignore empty lines and comments
        if re.match ('^\s*$', line) or re.match('^\s*#', line):
            return

        match = re.match ('^(\s*)class ([A-Za-z_0-9]+)\s*(\(([^)]+)\))?\s*:', line)
        if match:
            deps = match.group(4) if match.group(4) else ""
            # Ignore exception classes
            if deps == 'Exception':
                return
            self.reset (match.group(2), [x.strip() for x in deps.split(',') if x != ''])
            self.indent = len(match.group(1))
            return

        # Ignore preamble (we saw no class, yet)
        if not self.current:
            return

        match = re.match ('^(\s*).*', line)
        if not match:
            print ("INVALID LINE: " + line)
            return

        if len(match.group(1)) <= self.indent:
            print ("INVALID INDENT: " + line)
            return

        self.classes[self.current]['sloc'] += 1

    def analyze_file (self, filename):

        with open (filename) as f:
            for line in f:
                self.analyze_line (line)

    def sloc_hier (self, name):

        if not name in self.classes:
            print ("WARNING: Class " + name + " not found - assuming 0");
            return 0

        sloc = self.classes[name]['sloc']
        for d in self.classes[name]['deps']:
            sloc += self.sloc_hier(d)
        return sloc

    def statistics (self):
        for name in self.classes:
            c = self.classes[name]
            print ("Found class: " + name)
            print ("  SLOC: " + str(c['sloc']) + " SLOC/hier: " + str(self.sloc_hier (name)))
            print ("  Derived from: " + str(c['deps']))

lc = LineCount()

for filename in sys.argv[1:]:
    lc.analyze_file (filename)

lc.statistics()
