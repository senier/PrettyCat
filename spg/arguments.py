import spg.guarantees

class Args:

    def __init__ (self, name):
        self._name   = name

    def __iter__ (self):
        return { (k, v) for k, v in self.__dict__.items() if not k.startswith("_") }.__iter__()

    def __len__ (self):
        return len([(k, v) for k, v in self.__dict__.items() if not k.startswith("_")])

    def __contains__ (self, name):
        return name in self.__dict__

    def __getitem__ (self, name):
        return self.__dict__[name]

class Input_Args (Args):

    def __init__ (self, name):
        super().__init__ (name + ">input")

    def add_arg (self, name, conf = None, intg = None):
        self.__dict__.update (**{name: spg.guarantees.Guarantees (name = self._name + ">" + name, conf = conf, intg = intg)})

class Output_Args (Args):

    def __init__ (self, name):
        super().__init__ (name + ">output")

    def add_arg (self, name, sink, darg, conf, intg, assertion = None):
        self.__dict__.update (**{name: spg.guarantees.Guarantees (name = self._name + ">" + name, conf = conf, intg = intg, data = {'sink': sink, 'darg': darg, 'assertion': assertion})})
