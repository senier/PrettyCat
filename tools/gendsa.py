#!/usr/bin/env python3

from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
import binascii

def hexstring (buf):
    return str(hex(buf)[2:])

def mpi (key):
    hexkey = hexstring(key)
    keylen = len(hexkey)//2
    if keylen % 2 == 1:
        return format (keylen + 1, '08x') + '0' + hexkey
    else:
        return format (keylen, '08x') + hexkey

message = "Hello"
key = DSA.generate(1024)

h = SHA.new(message.encode()).digest()
k = random.StrongRandom().randint(1,key.q-1)
sig = key.sign(h,k)

if key.verify(h,sig):
    print ("# P:       " + mpi (key.p))
    print ("# Q:       " + mpi (key.q))
    print ("# G:       " + mpi (key.g))
    print ("# Y:       " + mpi (key.y))
    print ("# OTR Key: " + format (0, '04x') + mpi(key.p) + mpi(key.q) + mpi(key.g) + mpi(key.y))
    print ("# X:       " + hexstring (key.x))
else:
    print ("Incorrect signature")
