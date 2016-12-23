#    Copyright 2012 Kjell Braden <afflux@pentabarf.de>
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

from Crypto import Cipher

def AESCTR(key, counter=0):
    if not isinstance(counter, Counter):
        raise TypeError
    return Cipher.AES.new(key, Cipher.AES.MODE_CTR, counter=counter)

class Counter(object):
    def __init__(self, prefix):
        if isinstance(prefix, bytes):
            self.prefix = int.from_bytes (prefix, byteorder='big')
        else:
            self.prefix = prefix
        self.val = 0

    def inc(self):
        self.prefix += 1
        self.val = 0

    def __setattr__(self, attr, val):
        if attr == 'prefix':
            self.val = 0
        super(Counter, self).__setattr__(attr, val)

    def __repr__(self):
        return '<Counter(p={p!r},v={v!r})>'.format(p=self.prefix, v=self.val)

    def to_bytes(self):
        byteprefix = self.prefix.to_bytes (8, byteorder='big')
        bytesuffix = self.val.to_bytes (8, byteorder='big')
        return byteprefix + bytesuffix

    def prefix_bytes(self):
        b = self.to_bytes()
        return self.prefix.to_bytes (8, byteorder='big')

    def __call__(self):
        b = self.to_bytes()
        self.val += 1
        return b
