import libspg
from libspg import info, warn, err
import base64
import re

class Data_parser (libspg.MPI):

    def parse_data (self, data):
        result = {}

        result['protocol_version']     = data[0:2]
        result['message_type']         = data[2:3]
        result['sender_instance']      = data[3:7]
        result['receiver_instance']    = data[7:11]
        result['flags']                = data[11:12]
        result['sender_keyid']         = data[12:16]
        result['recipient_keyid']      = data[16:20]

        (result['dh_y'], rest)         = self.extract_data(data[20:])
        result['counter']              = rest[0:8]
        (result['enc_data'], rest)     = self.decode_data (rest[8:])
        result['mac']                  = rest[0:20]
        return result

class not_implemented (libspg.SPG_base):

    def __init__ (self, name, attributes, needconfig = False):
        raise libspg.NotImplemented (name + " (" + self.__class__.__name__ + ")")


class xform_ake_state (libspg.SPG_base):

    def recv_responder_state (self, state):
        self.send ('encrypted', state)

    def recv_initiator_state (self, state):
        self.send ('encrypted', state)

class xform_data_r (libspg.SPG_base, Data_parser):

    def recv_data (self, data):
        parsed = self.parse_data (data)

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
        self.send ('top_half_of_counter_init', parsed['counter'])
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

class xform_derive_keys (libspg.SPG_base, libspg.MPI):

    def _send_ssec (self, ssecmpi):
        self.send ('secbytes#1', ssecmpi)
        self.send ('secbytes#2', ssecmpi)
        self.send ('secbytes#3', ssecmpi)
        self.send ('secbytes#4', ssecmpi)
        self.send ('secbytes#5', ssecmpi)
        self.send ('secbytes#6', ssecmpi)

    def recv_responder_ssec (self, ssec):
        ssecmpi = self.encode_mpi (ssec)
        self._send_ssec (ssecmpi)

    def recv_initiator_ssec (self, ssec):
        ssecmpi = self.encode_mpi (ssec)
        self._send_ssec (ssecmpi)

class xform_dh_commit_r (libspg.SPG_base, libspg.MPI):

    def recv_dhcm (self, dhcm):
        # hashed_gx should exactly be the remainder from extracting encrypted g^x DATA
        (encrypted_gx, hashed_gx) = self.decode_data (dhcm)
        self.send ('encrypted_g^x', encrypted_gx)
        self.send ('hashed_g^x', hashed_gx)

class xform_dh_key_r (libspg.SPG_base):

    def recv_dhkm (self, dhkm):
        self.send ('g^y', dhkm)

class xform_network_mux (libspg.SPG_base):


    def __init__ (self, name, arguments):
        super().__init__ (name, arguments)

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

        warn ("MESSAGE: " + libspg.dump (data))

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
            self.send ('rit', sender_instance_tag)

        elif (message_type == 0x11):
            output = 'rvsm'
        elif (message_type == 0x12):
            output = 'sigm'
        elif (message_type == 0x03):
            # Pass complete header to data as this info is MACd/signed
            self.send('data', data)
            return
        else:
            # Ignore invalid message types
            libspg.warn ("Invalid message type " + str(message_type))
            return

        info ("Received " + output + ": " + libspg.dump (data[11:]))
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

class xform_reveal_signature_r (libspg.SPG_base, libspg.MPI):

    def recv_rvsm (self, rvsm):
        (revealed_key, rest)                 = self.decode_data (rvsm)
        (encrypted_signature, mac_signature) = self.decode_data (rest)

        self.send ('revealed_key', revealed_key)
        self.send ('encrypted_signature#1', encrypted_signature)
        self.send ('encrypted_signature#2', encrypted_signature)
        self.send ('macd_signature', macd_signature)

class xform_select_pubkeys (libspg.SPG_base, libspg.MPI):

    def __init__ (self, name, arguments):
        super().__init__ (name, arguments)

        self.current_local       = None
        self.previous_local      = None
        self.local_keyid         = 0
        self.latest_local_keyid  = 0

        self.current_remote      = None
        self.remote_keyid        = None
        self.latest_remote_keyid = None

    def check_send_pubkey (self):

        info ("Checking pubkey")

        if self.current_remote == None:
            err ("No remote key")
            return

        if self.current_local == None:
            err ("No local key")
            return

        if self.latest_local_keyid == self.local_keyid:
            self.send ('current_pubkey', self.current_local)
        elif self.latest_local_keyid == self.local_keyid - 1:
            self.send ('current_pubkey', self.previous_local)
        else:
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
        (self.current_remote, unused) = self.decode_mpi(pub)
        self.remote_keyid   = 1
        self.check_send_pubkey()

    def recv_responder_pub_remote (self, pub):
        (self.current_remote, unused) = self.decode_mpi(pub)
        self.remote_keyid   = 1
        self.check_send_pubkey()

    def recv_pub_remote (self, pub):
        (self.current_remote, unused) = self.decode_mpi(pub)
        self.check_send_pubkey()

    def recv_latest_local_keyid (self, keyid):
        self.latest_local_keyid = keyid
        self.check_send_pubkey()

    def recv_latest_remote_keyid (self, keyid):
        self.latest_remote_keyid = keyid
        self.check_send_pubkey()

class xform_select_secret_key (libspg.SPG_base):

    def __init__ (self, name, arguments):
        super().__init__ (name, arguments)

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

class xform_signature_r (libspg.SPG_base, libspg.MPI):

    def recv_sigm (self, sigm):
        (encrypted_sig, macd_signature) = self.decode_data (sigm)
        self.send ('encrypted_signature#1', encrypted_sig)

        # MAC check required encrypted_sig with length header.
        length = len(encrypted_sig)
        self.send ('encrypted_signature#2', length.to_bytes (4, byteorder='big') + encrypted_sig)
        self.send ('macd_signature', macd_signature)

class xform_split_x (libspg.SPG_base):

    def next_offset (self, data, offset = 0):
        length = int.from_bytes (data[offset:offset+4], byteorder='big')
        if length > len(data[offset:]) - 4:
            raise libspg.InvalidData ("Data length header exceeds buffer size: hdr=" + str(length) + " len=" + str(len(data)))
        return (offset+length+4)

    def extract_pubkey (self, pubkey):

        qoff = self.next_offset (pubkey, 2)
        goff = self.next_offset (pubkey, qoff)
        yoff = self.next_offset (pubkey, goff)
        last = self.next_offset (pubkey, yoff)
        return (pubkey[0:last], pubkey[last:])

    def recv_data (self, data):
        (pubkey, remainder) = self.extract_pubkey (data)
        keyid = remainder[0:4]
        sig = remainder[4:45]

        self.send ('pub#1', pubkey)
        self.send ('pub#2', pubkey)
        self.send ('signature', sig)
        self.send ('keyid', keyid)

class xform_verify_counter (libspg.SPG_base, Data_parser):

    def __init__ (self, name, arguments):
        super().__init__ (name, arguments)

        self.last_counter         = 0
        self.last_recipient_keyid = 0
        self.last_sender_keyid    = 0

    def recv_data (self, data):
        parsed = self.parse_data (data)

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
