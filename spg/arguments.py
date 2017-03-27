import spg.guarantees

class Args:

    def __init__ (self, name):
        raise Exception ("Abstract")

    def setup (self, name):
        self._name   = name

    def add_guarantee (self, name):
        self.__dict__.update (**{name: spg.guarantees.Guarantees (self._name + ">" + name)})

    def guarantees (self):
        return { k: v for k, v in self.__dict__.items() if not k.startswith("_") }

class Input_Args (Args):

    def __init__ (self, name):
        super().setup (name + ">input")

class Output_Args (Args):

    def __init__ (self, name):
        super().setup (name + ">output")


