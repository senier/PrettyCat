import libspg
from libspg import info, warn, err
import base64
import re

def parse_data (data):
    result['protocol_version']     = int.form_bytes(data[0:2],   byteorder='big')
    result['message_type']         = int.form_bytes(data[2:3],   byteorder='big')
    result['sender_instance']      = int.form_bytes(data[3:7],   byteorder='big')
    result['receiver_instance']    = int.form_bytes(data[7:11],  byteorder='big')
    result['flags']                = data[11:12]
    result['sender_keyid']         = int.form_bytes(data[12:16], byteorder='big')
    result['recipient_keyid']      = int.form_bytes(data[16:20], byteorder='big')
    (result['dh_y'], rest)         = libspg.decode_mpi (data[20:])
    result['counter']              = int.from_byates(rest[0:8], byteorder='big')
    (result['enc_data'], rest)     = decode_data (rest[8:])
    result['mac']                  = rest[0:20]
    return result

class not_implemented (libspg.SPG_base):

    def __init__ (self, name, config, arguments, needconfig = False):
        raise libspg.NotImplemented (name + " (" + self.__class__.__name__ + ")")


class xform_ake_state (libspg.SPG_base):

    def recv_responder_state (self, state):
        self.send ('encrypted', state)

    def recv_initiator_state (self, state):
        self.send ('encrypted', state)

class xform_data_r (libspg.SPG_base):

    def recv_data (self, data):
        parsed = parse_data (data)

        self.send ('protocol_version', parsed['protocol_version'])
        self.send ('message_type', parsed['message_type'])
        self.send ('sender_instance_tag', parsed['sender_instance'])
        self.send ('receiver_instance_tag', parsed['receiver_instance'])
        self.send ('flags', parsed['flags'])
        self.send ('sender_keyid#1', parsed['sender_keyid'])
        self.send ('sender_keyid#2', parsed['sender_keyid'])
        self.send ('recipient_keyid#1', parsed['recipient_keyid'])
        self.send ('recipient_keyid#2', parsed['recipient_keyid'])
        self.send ('dh_y#1', parsed['dh_y'])
        self.send ('dh_y#2', parsed['dh_y'])
        self.send ('top_half_of_counter_init#1', parsed['counter'])
        self.send ('top_half_of_counter_init#2', parsed['counter'])
        self.send ('encrypted_message', parsed['enc_data'])
        self.send ('authenticator', parsed['mac'])

class xform_data_s (libspg.SPG_xform):

    def finish (self):
        self.send ('data', \
             self.args['protocol_version'] + \
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

class xform_derive_keys (libspg.SPG_base):

    def _send_ssec (self, ssecmpi):
        self.send ('secbytes#1', ssecmpi)
        self.send ('secbytes#2', ssecmpi)
        self.send ('secbytes#3', ssecmpi)
        self.send ('secbytes#4', ssecmpi)
        self.send ('secbytes#5', ssecmpi)
        self.send ('secbytes#6', ssecmpi)

    def recv_responder_ssec (self, ssec):
        ssecmpi = libspg.encode_mpi (ssec)
        self._send_ssec (ssecmpi)

    def recv_initiator_ssec (self, ssec):
        ssecmpi = libspg.encode_mpi (ssec)
        self._send_ssec (ssecmpi)

class xform_dh_commit_r (libspg.SPG_base):

    def recv_dhcm (self, dhcm):
        # hashed_gx should exactly be the remainder from extracting encrypted g^x DATA
        (encrypted_gx, hashed_gx) = decode_data (dhcm)
        self.send ('encrypted_g^x', encrypted_gx)
        self.send ('hashed_g^x', hashed_gx)

class xform_dh_key_r (libspg.SPG_base):

    def recv_dhkm (self, dhkm):
        self.send ('g^y', dhkm)

class xform_network_mux (libspg.SPG_base):


    def __init__ (self, name, config, arguments):
        super().__init__ (name, config, arguments)

        self.match_query    = re.compile ("\?OTR\??([^\?]*)\?")
        self.match_otr      = re.compile ("\?OTR:(.*)$")
        self.match_v3       = re.compile ("^v.*3.*$")
        self.dhcm_received  = False
        self.query_received = False

    def _encode (self, raw):
        return ("?OTR:" + base64.b64encode(raw).decode ("utf-8") + ".").encode ("utf-8")

    def recv_msg (self, data):

        warn ("Got message len=" + str(len(data)))
        msg = data.decode ()

        # Check for OTR message types
        query_match = self.match_query.match (msg)
        if query_match:
            version = query_match.group (1)
            version_match = self.match_v3.match (version)

            if not version_match:
                warn ("Invalid version: " + version)
                return

            warn ("OTR version " + version + " requested")
            self.query_received = True
            if self.dhcm:
                warn ("Sending queued DHCM")
                self.send ('msg', self.dhcm)
                self.query_received = False
                self.dhcm = None
            return

        otr_match = self.match_otr.match (msg)
        if not otr_match:
            warn ("Not an OTR message: " + msg)
            return

        payload = otr_match.group(1).encode ("utf-8")
        try:
            data = base64.b64decode(payload)
        except:
            warn ("Invalid base64 encoding: " + msg)
            return

        message_type = int.from_bytes (data[2:3], byteorder='big')
        if (message_type == 0x02):
            output = 'dhcm'
            if self.dhkm != None:
                self.send ('msg', self.dhkm)
                self.dhkm = None
                self.dhcm_received = False
            else:
                self.dhcm_received = True
        elif (message_type == 0x0a):
            output = 'dhkm'
            sender_instance_tag = data[3:7]
            # Set sender_instance_tag of D-H Key message as outgoing receiver
            # instance tag for subsequent Reveal Signature messages
            print ("Setting remote receiver instance tag to " + str(sender_instance_tag))
            self.send ('rit', sender_instance_tag)

        elif (message_type == 0x11):
            output = 'rvsm'
        elif (message_type == 0x12):
            output = 'sigm'
        elif (message_type == 0x03):
            output = 'data'
        else:
            # Ignore invalid message types
            libspg.warn ("Invalid message type " + str(message_type))
            return

        info ("Received " + output)
        self.send(output, data[11:])

    def recv_dhkm (self, dhkm):
        if self.dhcm_received:
            self.send ('msg', self.dhkm)
            self.dhkm = None
        else:
            self.dhkm = self._encode (dhkm)

    def recv_dhcm (self, dhcm):
        if self.query_received:
            self.send ('msg', self._encode(dhcm))
            self.query_received = False
        else:
            self.dhcm = self._encode(dhcm)

    def recv_rvsm (self, rvsm):
        self.send ('msg', self._encode(rvsm))

    def recv_sigm (self, sigm):
        self.send ('msg', self._encode(sigm))

    def recv_data (self, data):
        self.send ('msg', self._encode(data))

class xform_reveal_old_mac_keys (libspg.SPG_xform):

    def finished (self, data):
        error ("Revealing old MAC keys not implemented")

class xform_reveal_signature_r (libspg.SPG_base):

    def recv_rvsm (self, rvsm):
        (revealed_key, rest)                 = libspg.decode_data (rvsm)
        (encrypted_signature, mac_signature) = libspg.decode_data (rest)

        self.send ('revealed_key', revealed_key)
        self.send ('encrypted_signature#1', encrypted_signature)
        self.send ('encrypted_signature#2', encrypted_signature)
        self.send ('macd_signature', macd_signature)

class xform_select_pubkeys (libspg.SPG_base):

    def __init__ (self, name, config, arguments):
        super().__init__ (name, config, arguments)

        self.current_local       = None
        self.previous_local      = None
        self.local_keyid         = 0
        self.current_remote      = None
        self.remote_keyid        = None
        self.latest_remote_keyid = None
        self.latest_local_keyid  = None

    def check_send_pubkey (self):

        if not self.current_local or \
            not self.local_keyid or \
            not self.remote_keyid or \
            not self.latest_remote_keyid or \
            not self.latest_local_keyid:
            return

        if self.latest_local_keyid == self.local_keyid:
            self.send ('current_pubkey', self.current_local)
        elif self.latest_local_keyid == self.local_keyid - 1:
            self.send ('current_pubkey', self.previous_local)
        else:
            error ("No local pubkey")
            return

        # send current local keyid
        self.send ('local_keyid#1', self.local_keyid)
        self.send ('local_keyid#2', self.local_keyid)
        self.send ('local_keyid#3', self.local_keyid)

        # Determine end and send start respective byte
        if self.current_local > self.current_remote:
            # 'High' end
            self.send ('sendbyte', 0x01)
            self.send ('recvbyte', 0x02)
        else:
            # 'Low' end
            self.send ('sendbyte', 0x02)
            self.send ('recvbyte', 0x01)

    def recv_initiator_pub_local (self, pub):
        self.current_local = pub
        self.local_keyid   = 1
        self.check_send_pubkey()

    def recv_responder_pub_local (self, pub):
        self.current_local = pub
        self.local_keyid   = 1
        self.check_send_pubkey()

    def recv_pub_local (self, pub):
        self.local_keyid = self.local_keyid + 1
        self.previous_local = self.current_local
        self.current_local  = pub
        self.check_send_pubkey()

    def recv_initiator_pub_remote (self, pub):
        self.current_remote = pub
        self.remote_keyid   = 1
        self.check_send_pubkey()

    def recv_responder_pub_remote (self, pub):
        self.current_remote = pub
        self.remote_keyid   = 1
        self.check_send_pubkey()

    def recv_pub_remote (self, pub):
        self.current_remote = pub
        self.check_send_pubkey()

    def recv_latest_local_keyid (self, keyid):
        self.latest_local_keyid = keyid
        self.check_send_pubkey()

    def recv_latest_remote_keyid (self, keyid):
        self.latest_remote_keyid = keyid
        self.check_send_pubkey()

class xform_select_secret_key (libspg.SPG_base):

    def __init__ (self, name, config, arguments):
        super().__init__ (name, config, arguments)

        current_keyid  = None
        current_psec   = None
        previous_psec  = None

    def recv_data_psec (self, psec):
        self.current_psec  = psec

    def recv_initiator_psec (self, psec):
        self.current_keyid = 1
        self.current_psec  = psec

    def recv_responder_psec (self, psec):
        self.current_keyid = 1
        self.current_psec  = psec

    def recv_current_keyid (self, keyid):
        self.current_keyid = keyid

class xform_signature_r (libspg.SPG_base):

    def recv_sigm (self, sigm):
        (encrypted_sig, macd_signature) = decode_data (sigm)
        self.send ('encrypted_signature', encrypted_sig)
        self.send ('macd_signature', macd_signature)

class xform_split_x (libspg.SPG_base):

    def recv_data (self, data):
        pubkey_type = int.from_bytes (data[0:4], byteorder='big')
        if (pubkey_type != 0):
            raise Exception ("Unsupported pubkey type " + str (pubkey_type))

        (pubkey, rest) = libspg.decode_pubkey (data[4:])
        keyid = int.from_byte (rest[0:4], byteorder='big')
        sig = rest[4:45]

        self.send ('pub#1', pubkey)
        self.send ('pub#2', pubkey)
        self.send ('signature', sig)
        self.send ('keyid', keyid)

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

        self.send ('data', parsed['enc_data'])
        self.send ('recipient_keyid#1', parsed['recipient_keyid'])
        self.send ('recipient_keyid#2', parsed['recipient_keyid'])

class xform_handle_query (libspg.SPG_xform):

    def finish (self):
        self.send ('len', self.args['recv_len'])
