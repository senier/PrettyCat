# FIXME: The Z3 package is not found my Debian. Investigate.
import sys
sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")

from spg.error import AssertionFailed
from z3 import Bool, is_true

class Guarantees:

    def __init__ (self, name, conf = None, intg = None, data = None):

        self.__name = name
        self.__data = data

        # Rules defining integrity and confidentiality
        # This is assigned by the primitive init function
        self.__conf_rule  = None
        self.__intg_rule  = None

        # Z3 variables representing confidentiality and
        # integrity within the solver. These values are
        # used in the rules.
        self.__conf_var = Bool (name + ">conf")
        self.__intg_var = Bool (name + ">intg")

        # The actual boolean value. This is filled in from
        # a valid model found by the solver or initialized
        # from config
        self.__conf_val = conf
        self.__intg_val = intg

    def __str__ (self):

        return self.name() + ": c=" + str(self.__conf_val) + " i=" + str(self.__intg_val)

    def conf (self, value):
        if self.__conf_rule != None:
            raise PrimitiveDuplicateConfRule (self.name)
        self.__conf_rule = value

    def intg (self, value):
        if self.__intg_rule != None:
            raise PrimitiveDuplicateIntgRule (self.name)
        self.__intg_rule = value

    def get_conf_var (self):
        return self.__conf_var

    def get_intg_var (self):
        return self.__intg_var

    def name (self):
        return self.__name

    def data (self):
        return self.__data

    def get_intg_rule (self):
        return self.__intg_rule

    def get_conf_rule (self):
        return self.__conf_rule

    def get_conf_val (self):
        return self.__conf_val

    def get_intg_val (self):
        return self.__intg_val

    def update (self, model):
        self.__conf_val = is_true(model[self.__conf_var])
        self.__intg_val = is_true(model[self.__intg_var])

    def check (self):
        data = self.data()
        if data != None and 'assertion' in data and data['assertion'] != None:
            ass = data['assertion']

            val_i = self.get_intg_val()
            if ass['i'] != None and val_i != None and val_i != ass['i']:
                raise AssertionFailed (self.name(), 'integrity', val_i, ass['i'], ass['description'])

            val_c = self.get_conf_val()
            if ass['c'] != None and val_c != None and val_c != ass['c']:
                raise AssertionFailed (self.name(), 'confidentiality', val_c, ass['c'], ass['description'])
    
def Intg (guarantee):
    return guarantee.get_intg_var()

def Conf (guarantee):
    return guarantee.get_conf_var()
