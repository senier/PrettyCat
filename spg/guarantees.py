from z3 import Bool, is_true

class Guarantees:

    def __init__ (self, name):
        self.name  = name

        # Rules defining integrity and confidentiality
        # This is assigned by the primitive init function
        self.__conf  = None
        self.__intg  = None

        # Z3 variables representing confidentiality and
        # integrity within the solver. These values are
        # used in the rules.
        self.__c   = Bool(name + ">conf")
        self.__i   = Bool(name + ">intg")

        # The actual boolean value. This is filled in from
        # a valid model found by the solver
        self.__val_c = None
        self.__val_i = None

    def conf (self, value):
        if self.__conf != None:
            raise PrimitiveDuplicateConfRule (self.name)
        self.__conf = value

    def intg (self, value):
        if self.__intg != None:
            raise PrimitiveDuplicateIntgRule (self.name)
        self.__intg = value

    def get_conf (self):
        return self.__conf

    def get_intg (self):
        return self.__intg

    def name (self):
        return name

    def get_i (self):
        return self.__i

    def get_c (self):
        return self.__c

    def val_c (self):
        return self.__val_c

    def val_i (self):
        return self.__val_i

    def update (self, model):
        self.__val_c = is_true(model[self.__c])
        self.__val_i = is_true(model[self.__i])
    
def Intg (guarantee):
    return guarantee.get_i()

def Conf (guarantee):
    return guarantee.get_c()


