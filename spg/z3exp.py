import sys
import re

sys.path.append ("/home/alex/.python_venv/lib/python2.7/site-packages/")
from z3 import *

class Z3Expr:

    def __init__ (self, exp):
        self.exp = exp

    def handle_and_pre     (self, level, num_args): pass
    def handle_and_elem    (self, level, arg_no):   pass
    def handle_and_post    (self, level, num_args): pass
    def handle_or_pre      (self, level, num_args): pass
    def handle_or_elem     (self, level, arg_no):   pass
    def handle_or_post     (self, level, num_args): pass
    def handle_eq_op       (self, level, num_args): pass
    def handle_implies_op  (self, level, num_args): pass
    def handle_neg_op      (self, level, num_args): pass
    def handle_invalid_op  (self, level, num_args): pass
    def handle_const_op    (self, exp, level, num_args): pass

    def __iterate__ (self, exp, level = 0):

        num_args  = exp.num_args()
        if is_and (exp):
            self.handle_and_pre (level, num_args)
            for idx in range (0, num_args):
                self.handle_and_elem (level, idx)
                self.__iterate__ (exp.arg(idx), level + 1)
            self.handle_and_post (level, num_args)
        elif is_or (exp):
            self.handle_or_pre (level, num_args)
            for idx in range (0, num_args):
                self.handle_or_elem (level, idx)
                self.__iterate__ (exp.arg(idx), level + 1)
            self.handle_or_post (level, num_args)
        elif is_eq(exp):
            self.__iterate__ (exp.arg(0), level + 1)
            self.handle_eq_op (level, num_args)
            self.__iterate__ (exp.arg(1), level + 1)
        elif is_app_of(exp, Z3_OP_IMPLIES):
            self.__iterate__ (exp.arg(0), level + 1)
            self.handle_implies_op (level, num_args)
            self.__iterate__ (exp.arg(1), level + 1)
        elif is_not(exp):
            self.handle_neg_op (level, num_args)
            self.__iterate__ (exp.arg(0), level + 1)
        elif is_const(exp):
            self.handle_const_op (exp, level, num_args)
        elif exp == None:
            self.handle_invalid_op (level, num_args)
        else:
            raise Exception ("Unhandled expression: " + str(exp))
class Z3Latex (Z3Expr):

    def __init__ (self, exp):
        super().__init__ (exp)

    def str (self, prefix = None, label = False):
        self.prefix = prefix
        self.label  = label
        self.result = ""
        self.__iterate__ (self.exp)
        return self.result

    def handle_and_elem (self, level, arg_no):
        if arg_no != 0:
            if level == 0:
                if self.prefix and self.label:
                    result += "\\label{eq:" + prefix + "_" + str(arg_no) + "}"
                self.result += "\\\\ &"
            self.result += "\land{}"

    def handle_and_post (self, level, num_args):
        if level == 0 and self.prefix and self.label:
            self.result += "\\label{eq:" + self.prefix + "_" + str(num_args) + "}"

    def handle_or_pre (self, level, num_args):
        if num_args > 1:
            self.result += "("

    def handle_or_elem (self, level, arg_no):
        if arg_no != 0:
            self.result += "\lor{}"

    def handle_or_post  (self, level, num_args):
        if num_args > 1:
            self.result += ")"

    def handle_eq_op (self, level, num_args):
        self.result += " \equiv{} "

    def handle_implies_op (self, level, num_args):
        self.result += " \\rightarrow{} "

    def handle_neg_op (self, level, num_args):
        self.result += " \\neg{} "

    def handle_invalid_op (self, level, num_args):
        self.result += "\Downarrow"

    def handle_const_op (self, exp, level, num_args):

        var = str(exp)

        if var == "True" or var == "False":
            self.result += var
        else:
            (name, inout, arg, kind) = var.split ('>')

            texname = {"input": "invar", "output": "outvar"}

            if kind != 'intg' and kind != 'conf':
                raise Exception ("Invalid variable " + var + ": neither integrity nor confidentiality")

            if inout != 'input' and inout != 'output':
                raise Exception ("Invalid variable " + var + ": neither input nor output")

            name = name.capitalize()
            name = re.sub ('>', '\>', name)
            name = re.sub ('_', '\_', name)

            self.result += "\\" + kind + "{\\" + texname[inout] + "{" + name + "}}"

class Z3Unsat (Z3Expr):

    def __init__ (self, exp):
        self.unsat = None
        self.__iterate__ (exp)

    def get_unsat (self):
        return self.unsat

    def handle_const_op (self, exp, level, num_args):

        var = str(exp)
        (name, inout, arg, kind) = var.split ('>')

        if self.unsat == None:
            self.unsat = {}

        if not name in self.unsat:
            self.unsat[name] = {}

        if not inout in self.unsat[name]:
            self.unsat[name][inout] = {}

        if not arg in self.unsat[name][inout]:
            self.unsat[name][inout][arg] = {}

        self.unsat[name][inout][arg][kind] = True

class Z3Text (Z3Expr):

    def __init__ (self, exp):
        super().__init__ (exp)

    def str (self, prefix = None, label = False):
        self.prefix = prefix
        self.label  = label
        self.result = ""
        self.__iterate__ (self.exp)
        return self.result

    def handle_and_elem (self, level, arg_no):
        if arg_no != 0: self.result += " ∧ "
        if level == 0: self.result += "\n   "

    def handle_or_pre (self, level, num_args):
        if num_args > 1: self.result += "("

    def handle_or_elem (self, level, arg_no):
        if arg_no != 0: self.result += " ∨ "

    def handle_or_post  (self, level, num_args):
        if num_args > 1: self.result += ")"

    def handle_eq_op (self, level, num_args):
        self.result += " ⇔ "

    def handle_implies_op (self, level, num_args):
        self.result += " ⇒ "

    def handle_neg_op (self, level, num_args):
        self.result += "¬"

    def handle_invalid_op (self, level, num_args):
        self.result += " ⊥ "

    def handle_const_op (self, exp, level, num_args):

        var = str(exp)

        if var == "True" or var == "False":
            self.result += var
        else:
            (name, inout, arg, kind) = var.split ('>')

            textname = {"input": "", "output": "⁰", "intg": "₁", "conf": "₍"}

            if kind != 'intg' and kind != 'conf':
                raise Exception ("Invalid variable " + var + ": neither integrity nor confidentiality")

            if inout != 'input' and inout != 'output':
                raise Exception ("Invalid variable " + var + ": neither input nor output")

            name = name.capitalize()
            name = re.sub ('>', '\>', name)
            name = re.sub (' ', '_', name)

            self.result += name + textname[inout] + textname[kind]
