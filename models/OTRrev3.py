import libspg
import base64

def parse_data (data):
    result['protocol_version']     = int.form_bytes(data[0:2],   byteorder='big')
    result['message_type']         = int.form_bytes(data[2:3],   byteorder='big')
    result['sender_instance']      = int.form_bytes(data[3:7],   byteorder='big')
    result['receiver_instance']    = int.form_bytes(data[7:11],  byteorder='big')
    result['flags']                = data[11:12]
    result['sender_keyid']         = int.form_bytes(data[12:16], byteorder='big')
    result['recipient_keyid']      = int.form_bytes(data[16:20], byteorder='big')
    (result['dh_y'], rest)         = decode_mpi (data[20:])
    result['counter']              = int.from_byates(rest[0:8], byteorder='big')
    (result['enc_data'], rest)     = decode_data (rest[8:])
    result['mac']                  = rest[0:20]
    return result

class not_implemented (libspg.SPG_base):

    def __init__ (self, name, config, arguments, needconfig = False):
        raise libspg.NotImplemented (name)


class xform_ake_state (not_implemented): pass

class xform_data_r (libspg.SPG_base):

    def recv_data (self, data):
        parsed = parse_data (data)

        self.send['protocol_version'] (parsed['protocol_version'])
        self.send['message_type'] (parsed['message_type'])
        self.send['sender_instance_tag'] (parsed['sender_instance'])
        self.send['receiver_instance_tag'] (parsed['receiver_instance'])
        self.send['flags'] (parsed['flags'])
        self.send['sender_keyid#1'] (parsed['sender_keyid'])
        self.send['sender_keyid#2'] (parsed['sender_keyid'])
        self.send['recipient_keyid#1'] (parsed['recipient_keyid'])
        self.send['recipient_keyid#2'] (parsed['recipient_keyid'])
        self.send['dh_y#1'] (parsed['dh_y'])
        self.send['dh_y#2'] (parsed['dh_y'])
        self.send['top_half_of_counter_init#1'] (parsed['counter'])
        self.send['top_half_of_counter_init#2'] (parsed['counter'])
        self.send['encrypted_message'] (parsed['enc_data'])
        self.send['authenticator'] (parsed['mac'])

class xform_data_s (libspg.SPG_xform):

    def finish (self):
        self.send['data'] \
            (self.args['protocol_version'] + \
             self.args['message_type'] + \
             self.args['sender_instance_tag'] + \
             self.args['receiver_instance_tag'] + \
             self.args['flags'] + \
             self.args['sender_keyid'] + \
             self.args['recipient_keyid'] + \
             self.args['dh_y'] + \
             self.args['top_half_of_counter_init'] + \
             self.args['encrypted_message'] + \
             self.args['authenticator'] + \
             self.args['old_mac_keys'])

class xform_derive_keys (not_implemented): pass

class xform_determine_end (not_implemented): pass

class xform_dh_commit_r (libspg.SPG_base):

    def recv_dhcm (self, dhcm):
        # hashed_gx should exactly be the remainder from extracting encrypted g^x DATA
        (encrypted_gx, hashed_gx) = decode_data (dhcm)
        self.send['encrypted_g^x'] (encrypted_gx)
        self.send['hashed_g^x'] (hashed_gx)

class xform_dh_commit_s (not_implemented): pass
class xform_dh_key_r (not_implemented): pass
class xform_dh_key_s (not_implemented): pass
class xform_mpi (not_implemented): pass

class xform_network_input_mux (libspg.SPG_base):

    def recv_msg (self, msg):
        message_type = int.from_bytes (msg[2:3], byteorder='big')
        if (message_type == 0x02):
            output = 'dhcm'
        elif (message_type == 0x0a):
            output = 'dhkm'
        elif (message_type == 0x11):
            output = 'rvsm'
        elif (message_type == 0x12):
            output = 'sigm'
        elif (message_type == 0x03):
            output = 'data'
        else:
            # Ignore invalid message types
            warn ("Invalid message type " + str(message_type))
            return

        self.send[output] (msg[12:])

class xform_network_output_mux (libspg.SPG_base):

    def _encode (raw):
        return ("?OTR:" + base64.b64encode(raw) + ".")

    def recv_dhkm (self, dhkm):
        self.send['msg'] (_encode(dhkm))

    def recv_dhcm (self, dhcm):
        self.send['msg'] (_encode(dhcm))

    def recv_rvsm (self, rvsm):
        self.send['msg'] (_encode(rvsm))

    def recv_sigm (self, sigm):
        self.send['msg'] (_encode(sigm))

    def recv_data (self, data):
        self.send['msg'] (_encode(data))

class xform_reveal_old_mac_keys (libspg.SPG_xform):

    def finished (self, data):
        error ("Revealing old MAC keys not implemented")

class xform_reveal_signature_r (libspg.SPG_base):

    def recv_rvsm (self, rvsm):
        (revealed_key, rest)                 = libspg.decode_data (rvsm)
        (encrypted_signature, mac_signature) = libspg.decode_data (rest)

        self.send['revealed_key'] (revealed_key)
        self.send['encrypted_signature#1'] (encrypted_signature)
        self.send['encrypted_signature#2'] (encrypted_signature)
        self.send['macd_signature'] (macd_signature)

class xform_reveal_signature_s (not_implemented): pass
class xform_select_local_pubkey (not_implemented): pass
class xform_select_remote_pubkey (not_implemented): pass
class xform_select_secret_key (not_implemented): pass
class xform_signature_r (not_implemented): pass
class xform_signature_s (not_implemented): pass
class xform_split_local_pubkeys (not_implemented): pass

class xform_split_x (libspg.SPG_base):

    def recv_data (self, data):
        pubkey_type = int.from_bytes (data[0:4], byteorder='big')
        if (pubkey_type != 0):
            raise Exception ("Unsupported pubkey type " + str (pubkey_type))

        (pubkey, rest) = libspg.decode_pubkey (data[4:])
        keyid = int.from_byte (rest[0:4], byteorder='big')
        sig = rest[4:45]

        self.send['pub#1'] (pubkey)
        self.send['pub#2'] (pubkey)
        self.send['signature'] (sig)
        self.send['keyid'] (keyid)

class xform_verify_counter (libspg.SPG_base):

    def __init__ (self, name, config, arguments):
        super().__init__ (name, config, arguments)

        self.last_counter         = 0
        self.last_recipient_keyid = 0
        self.last_sender_keyid    = 0

    def recv_data (self, data):
        parsed = parse_data (data)

        # recipient_keyid must be monotonic
        if parsed['recipient_keyid'] < self.last_recipient_keyid:
            return

        # sender_keyid must be monotonic
        if parsed['sender_keyid'] < self.last_sender_keyid:
            return

        # The same (recipient_keyid, sender_keyid, counter) pair must
        # not be used twice
        if parsed['recipient_keyid'] == self.last_recipient_keyid and \
           parsed['sender_keyid']    == self.last_sender_keyid and \
           parsed['counter']         == self.last_counter:
            return

        self.last_counter         = parsed['counter']
        self.last_recipient_keyid = parsed['recipient_keyid']
        self.last_sender_keyid    = parsed['sender_keyid']

        self.send['data'] (parsed['enc_data'])
        self.send['recipient_keyid#1'] (parsed['recipient_keyid'])
        self.send['recipient_keyid#2'] (parsed['recipient_keyid'])
