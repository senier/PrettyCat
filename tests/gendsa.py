#!/usr/bin/env python3

from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
import binascii

def mpi (key):
    hexkey = str(hex (key)[2:])
    keylen = int(len(hexkey)/2)
    return format (keylen, '08x') + hexkey

message = "Hello"
key = DSA.generate(1024)

h = SHA.new(message.encode()).digest()
k = random.StrongRandom().randint(1,key.q-1)
sig = key.sign(h,k)

if key.verify(h,sig):
    print ("Input:   " + ''.join('{:02x}'.format(x) for x in h))
    print ("Params:  " + mpi(key.p) + mpi(key.q) + mpi(key.g) + mpi(key.y))
    print ("Private: " + str (hex (key.x))[2:])
    print ("Sig:     " + str (hex(sig[0])[2:]) + str (hex(sig[1])[2:]))
else:
    print ("Incorrect signature")
