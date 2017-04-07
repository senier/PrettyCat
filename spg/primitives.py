from z3 import Or, And, Implies, Not
from spg.guarantees import Intg, Conf
from spg.error import *
import spg.arguments

class Primitive:
    """
    An "abstract" class implementing generic methods for a Primitive
    """

    def __init__ (self, G, name):
        raise Exception ("Abstract")

    def setup (self, name, G, attributes, interfaces = { 'inputs': None, 'outputs': None} ):

        self.name   = name
        self._rule  = []
        self.interfaces = interfaces

        # FIXME: Remove
        self.G = G

        self.attributes = attributes
        self.config     = attributes['config']
        self.output     = attributes['outputs']
        self.input      = attributes['inputs']

        if interfaces['inputs'] != None:

            for inp in self.interfaces['inputs']:
                self.input.add_arg (inp)

            if self.input:
                missing_args = [arg[0] for arg in self.input if not arg[0] in interfaces['inputs']]
                if len(missing_args) > 0: raise MissingIncomingEdges (name, missing_args)

        if interfaces['outputs'] != None:
            if self.output:
                missing_args = [outp[0] for outp in self.output if not outp[0] in interfaces['outputs']]
                if len(missing_args) > 0: raise MissingOutgoingEdges (name, missing_args)

    def rule (self):
        return And (self._rule)

    def append_rule (self, rule):
        self._rule.append (rule)

    def prove (self, solver):
        solver.assert_and_track (And (self._rule), "RULE>" + self.name)
        if solver.check() != sat:
            raise PrimitiveInvalidRule (self.__class__.__name__, self.name)
        del solver

class Primitive_env (Primitive):
    """
    The env primitive

    Denotes one source/sink outside the model. Fixed guarantees are defined here.
    """

    def __init__ (self, G, name, attributes):
        super ().setup (name, G, attributes)

class Primitive_xform (Primitive):
    """
    The xform primitive

    This mainly identifies sources and sinks and sets the fixed
    guarantees according to the XML definition.
    """

    def __init__ (self, G, name, attributes):
        super ().setup (name, G, attributes)

        # Input from a source lacking integrity guarantees can influence
        # any output of an xform in undetermined ways. Hence, integrity
        # guarantees cannot be maintained for any output interface.
        #
        # Integrity can be maintained if the input interfaces is
        # controlled by the xform implementation, i.e. it is guaranteed
        # that it can influence the output only in well-defined ways
        # (permutation, fixed output position).
        #
        # (Intg(output_if) ⇒ Intg(input_if)) ∨ Controlled (input_if)

        for (unused, input_if) in self.input:
            input_if_rules = []
            for (unused, output_if) in self.output:
                input_if_rules.append (Or (Implies (Intg(output_if), Intg(input_if))))
            self.append_rule (And (input_if_rules))

        # Input from a source demanding confidentiality guarantees can
        # influence any output of an xform in undetermined ways. Hence,
        # confidentiality must be guaranteed by all output interfaces.
        #
        #   Conf(input_if) -> Conf(output_if)
        for (unused, output_if) in self.output:
            output_if_rules = []
            for (unused, input_if) in self.input:
                output_if_rules.append (Implies (Conf(input_if), Conf(output_if)))
            self.append_rule (And (output_if_rules))

class Primitive_const (Primitive):
    """
    The const primitive
    """

    def __init__ (self, G, name, attributes):
        interfaces = { 'inputs': [], 'outputs': ['const'] }
        super ().setup (name, G, attributes, interfaces)

        # Constants can never be confidential
        self.append_rule (Not (Conf(self.output.const)))

class Primitive_rng (Primitive):
    """
    Primitive for a true (hardware) random number generator

    This RNG is not seeded. It has an input parameter len, determining how
    many bits we request from it.
    """

    def __init__ (self, G, name, attributes):
        interfaces = { 'inputs': ['len'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        # input.len: If an attacker can choose the length requested from an RNG,
        # too short keys would be generated.
        self.append_rule (Intg(self.input.len))

        # output.data: We assume that this RNG is always used to produce keys which
        # need to be confidential.
        self.append_rule (Conf (self.output.data))

        # Discussion:
        # If required, we can introduce a nonce generator later which does not imply
        # confidentiality guarantees for its output. The RNG # should be safe, as the
        # worst thing that may happen is that confidentiality is required unnecessarily.
        # Most likely this will result in a conflict in nonce case, as those are
        # typically passed to domains without confidentiality guarantees.

class Primitive_dhpub (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['modulus', 'generator', 'psec'], 'outputs': ['pub'] }
        super ().setup (name, G, attributes, interfaces)

        # With knowledge of g^y and psec_in (x in DH terms) an attacker can
        # calculate the shared secret g^y^x
        self.append_rule (Conf(self.input.psec))

        # If an attacker can choose psec_in (x in DH terms) and knows g^y,
        # she can calculate the shared secret g^yx
        self.append_rule (Intg(self.input.psec))

        # Parameters are public, but an attacker may not chose a weak ones.
        # Hence, integrity must be guaranteed
        self.append_rule (And (Intg(self.input.modulus), Intg(self.input.generator)))

class Primitive_dhsec (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['modulus', 'generator', 'pub', 'psec'], 'outputs': ['ssec'] }
        super ().setup (name, G, attributes, interfaces)

        # With knowledge of pub (g^y) and psec_in (x) an attacker can
        # calculate ssec (the shared secret g^yx ≡ g^xy)
        self.append_rule (Conf(self.input.psec))

        # If the shared secret shall be confidential, then psec must not be chosen
        # by an attacker
        self.append_rule (Intg(self.input.psec))

        # No weak parameters must be chosen by an attacker
        self.append_rule (Intg(self.input.modulus))
        self.append_rule (Intg (self.input.generator))

        # Confidentiality must be guaranteed for shared secret
        self.append_rule (Conf(self.output.ssec))

        # If shared secret requires integrity, so does modulus, generator, pub and psec
        # self.append_rule (Implies (Intg(self.output.ssec), Intg(self.input.modulus)))
        # self.append_rule (Implies (Intg(self.output.ssec), Intg(self.input.generator)))
        # self.append_rule (Implies (Intg(self.output.ssec), Intg(self.input.pub)))
        # self.append_rule (Implies (Intg(self.output.ssec), Intg(self.input.psec)))


class Primitive_encrypt (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['plaintext', 'key', 'ctr'], 'outputs': ['ciphertext'] }
        super ().setup (name, G, attributes, interfaces)

        # Counter mode encryption does not achieve integrity, hence an attacker
        # could change plaintext_in to influence the integrity of
        # ciphertext_out. If integrity must be guaranteed for ciphertext_out,
        # it also must be guaranteed for plaintext_in.
        self.append_rule (Implies (Intg(self.output.ciphertext), Intg(self.input.plaintext)))

        # Integrity and confidentiality of input key must always be guaranteed
        self.append_rule (And (Intg (self.input.key), Conf (self.input.key)))

        # Integrity of the counter must be guaranteed, otherwise an attacker
        # could break the encryption by making the component reuse a counter/key
        # pair
        self.append_rule (Intg(self.input.ctr))

class Primitive_encrypt_ctr (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['plaintext', 'key', 'ctr'], 'outputs': ['ciphertext', 'ctr'] }
        super ().setup (name, G, attributes, interfaces)

        # Counter mode encryption does not achieve integrity, hence an attacker
        # could change plaintext_in to influence the integrity of
        # ciphertext_out. If integrity must be guaranteed for ciphertext_out,
        # it also must be guaranteed for plaintext_in.
        self.append_rule (Implies (Intg(self.output.ciphertext), Intg(self.input.plaintext)))

        # Integrity and confidentiality of input key must always be guaranteed
        self.append_rule (And (Intg (self.input.key), Conf (self.input.key)))

        # Integrity of the counter must be guaranteed, otherwise an attacker
        # could break the encryption by making the component reuse a counter/key
        # pair
        self.append_rule (Intg(self.input.ctr))

        # If confidentiality is guaranteed for initial counter, confidentiality must be guaranteed for output counter
        self.append_rule (Implies (Conf(self.input.ctr), Conf(self.output.ctr)))

class Primitive_decrypt (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['ciphertext', 'key', 'ctr'], 'outputs': ['plaintext'] }
        super ().setup (name, G, attributes, interfaces)

        # If the plaintext is confidential, the key must be confidential, too.
        # FIXME: What happens when an attacker can chose a key for decryption?
        self.append_rule (Implies (Conf(self.output.plaintext), Conf(self.input.key)))

class Primitive_hash (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data'], 'outputs': ['hash'] }
        super ().setup (name, G, attributes, interfaces)

        # Using a cryptographically secure hash makes no sense with non-integer data.
        self.append_rule (Intg(self.input.data))

        #   Even with a cryptographically secure hash function, an attacker
        #   may be able to recover data_in from hash_out, depending on the
        #   resource available and the structure of data_in. As we don't want
        #   to get probabilistic here, we just assume this is always possible.
        #   FIXME: It may become hard to cope with protocols where the
        #   infeasibility of reversing the hash is used, e.g. password
        #   authentication.
        self.append_rule (Implies (Conf(self.input.data), Conf(self.output.hash)))

class Primitive_hmac (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['key', 'msg'], 'outputs': ['auth'] }
        super ().setup (name, G, attributes, interfaces)

        # If integrity is not guaranteed for the input data, HMAC cannot
        # protect anything.
        self.append_rule (Conf(self.input.key))
        self.append_rule (Intg(self.input.key))

        # We assume that an HMAC component is only used when integrity must
        # be guaranteed for the msg_in.
        self.append_rule (Intg (self.input.msg))

class Primitive_hmac_out (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['key', 'msg'], 'outputs': ['auth', 'msg'] }
        super ().setup (name, G, attributes, interfaces)

        # If integrity is not guaranteed for the input data, HMAC cannot
        # protect anything. Hence, it does not harm if the key is released
        # to or chosen by an attacker.
        self.append_rule (Conf(self.input.key))
        self.append_rule (Intg(self.input.key))

        # We assume that an HMAC component is only used when integrity must
        # be guaranteed for the msg_in.
        self.append_rule (Intg (self.input.msg))

        # HMAC does not achieve confidentiality.
        self.append_rule (Implies (Conf(self.input.msg), Conf(self.output.msg)))

class Primitive_sign (Primitive):

    """
    The sign primitive

    Creates an asymmetric digital signature for a message using a given set of
    public and secret keys.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'pubkey', 'privkey', 'rand'], 'outputs': ['auth'] }
        super ().setup (name, G, attributes, interfaces)

        # The private key must stay confidential
        self.append_rule (Conf (self.input.privkey))

        # An attacker must not chose the private key
        self.append_rule (Intg (self.input.privkey))

        # An attacker must not chose the public key
        self.append_rule (Intg (self.input.pubkey))

        # Random number x must be confidential and not chosen by attacker
        self.append_rule (Intg (self.input.rand))
        self.append_rule (Conf (self.input.rand))

        # Even with a cryptographically secure hash function, an attacker
        # may be able to recover data_in from auth_out, depending on the
        # resource available and the structure of msg_in. As we don't want
        # to get probabilistic here, we just assume this is always possible.
        self.append_rule (Implies (Conf(self.input.msg), Conf(self.output.auth)))

class Primitive_verify_sig (Primitive):

    """
    The signature verification primitive

    Checks whether an auth value represents a valid message signature by a given public key.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'auth', 'pubkey'], 'outputs': ['result'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can modify the result of a verify operation, she could
        # as well chose an own public key for which she has the secret key available
        # (and thus can create a valid signature yielding a positive result)
        self.append_rule (Intg(self.input.pubkey))

        # If confidentiality is to be guaranteed for msg, this may also apply for
        # the fact whether it was signed with pubkey.
        self.append_rule (Implies (Conf(self.input.msg), Conf(self.output.result)))

class Primitive_verify_hmac (Primitive):

    """
    HMAC verification primitive

    Checks whether a given pair (msg, auth) was MAC'ed with key.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'auth', 'key'], 'outputs': ['result'] }
        super ().setup (name, G, attributes, interfaces)

        # An attacker must not chose the integrity verification key.
        self.append_rule (Intg(self.input.key))

        # If the input message is confidential, the result is confidential, too.
        self.append_rule  (Implies (Conf(self.input.msg), Conf(self.output.result)))

class Primitive_verify_hmac_out (Primitive):

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['msg', 'auth', 'key'], 'outputs': ['msg'] }
        super ().setup (name, G, attributes, interfaces)

        # An attacker must not chose the integrity verification key.
        self.append_rule (Intg(self.input.key))

        #   The HMAC does not achieve confidentiality.
        self.append_rule (Implies (Conf(self.input.msg), Conf(self.output.msg)))

class Primitive_guard (Primitive):

    """
    Guard primitive

    This primitive guards the control the data flow in a protocol. Input data is
    only transferred to the output interfaces if the condition on the input interfaces is
    true.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data', 'cond'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        #   Guard can be used to coordinate protocol steps, e.g. to send a reply
        #   only if the signature of a previous message was OK. Hence, the
        #   integrity requirements are at protocol level and cannot be derived
        #   from the primitive (or other primitives)
        #   FIXME: Is it true we cannot derive it from primitives? Should we make this configurable then?
        self.append_rule (Intg (self.input.cond))

        # Guard does nothing to integrity.
        self.append_rule (Implies (Intg(self.output.data), Intg(self.input.data)))

        # Guard does nothing to confidentiality.
        self.append_rule (Implies (Conf(self.input.data), Conf(self.output.data)))

class Primitive_release (Primitive):

    """
    Release primitive

    This primitive allows to drop all security guarantees.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        # An attacker must not control which data is released
        self.append_rule (Intg(self.input.data))

class Primitive_comp (Primitive):

    """
    Comp primitive

    This primitive compares two arbitrary inputs and outputs a boolean value
    indicating whether both inputs were identical or not.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data1', 'data2'], 'outputs': ['result'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker knows data1 and data2 she can derive result_out by comparing both values
        # FIXME: Need both input values be confidential or is confidentiality for on input sufficient
        # (we assume the latter right now)
        self.append_rule (Implies (Or (Conf (self.input.data1), Conf (self.input.data2)), Conf(self.output.result)))

class Primitive_verify_commit (Primitive):
    """
    Primitive for a verifying a commitment.

    This primitives verifies a commitment using a cryptographic hash function. It
    takes a hash value h and a data value d. If the hash value is received prior to
    the data value and the hash(d) == h, then the primitive outputs d.
    """

    def __init__ (self, G, name, attributes):

        interfaces = { 'inputs': ['data', 'hash'], 'outputs': ['data'] }
        super ().setup (name, G, attributes, interfaces)

        # If an attacker can chose input data, she may change the output data.
        self.append_rule (Implies (Intg(self.output.data), Intg(self.input.data)))

        # If input data is confidential, confidentiality must be guaranteed for output data
        self.append_rule (Implies (Conf(self.input.data), Conf(self.output.data)))
