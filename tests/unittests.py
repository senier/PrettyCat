#!/usr/bin/env python3

import os
import pathlib
import filecmp
import tempfile
import spg.graph
import libspg
from Crypto import Random

class TestMPI (libspg.MPI):

    def __init__ (self):
        self.encode_decode()
        self.leading_0s()

    def leading_0s (self):
        libspg.info ("MPI: Leading 0s")
        num_tests = 50000
        leading_0 = 0
        for x in range(1,num_tests):
            num = int.from_bytes (Random.get_random_bytes (20), byteorder='big')
            mpi = self.encode_mpi (num)
            if mpi[4] == 0:
                leading_0 += 1
        if leading_0 > 0:
            libspg.err ("%d%% of MPIs have leading 0" % (100*leading_0/num_tests))
            raise Exception ("Leading 0 in MPIs")

    def encode_decode (self):
        libspg.info ("MPI: Encode/decode")
        num_tests = 50000
        for x in range(1,num_tests):
            num = int.from_bytes (Random.get_random_bytes (20), byteorder='big')
            (num_dec, dummy) = self.decode_mpi (self.encode_mpi (num))
            if num != num_dec:
                raise Exception ("Encode/decode failed: %d != %d", num, num_dec)

class TestGraphTranscode ():

    def __init__ (self):

        self.identity()

    def identity (self):

        tests = pathlib.Path ('tests')
        for test in tests.glob ('*.spg'):
            self.__check_identity (test.as_posix())

    def __check_identity (self, model):

        firstname  = tempfile.mktemp (prefix = 'first', suffix = '.spg')
        secondname = tempfile.mktemp (prefix = 'second', suffix = '.spg')

        libspg.info ("GraphTranscode: Identity for '" + model + "'")
        first = spg.graph.Graph (model)
        first.write (firstname)
        second = spg.graph.Graph (firstname)
        second.write (secondname)

        equal = filecmp.cmp (firstname, secondname)
        os.remove (firstname)
        os.remove (secondname)

        if not equal:
            raise Exception ("Transformed XML output does not equal XML input '" + model + "'")

TestGraphTranscode()
TestMPI()
