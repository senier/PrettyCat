import libspg

class not_implemented (libspg.SPG_base):

    def __init__ (self, name, config, arguments, needconfig = False):
        raise libspg.NotImplemented (name)


class xform_ake_state (not_implemented): pass
class xform_data_r (not_implemented): pass
class xform_data_s (not_implemented): pass
class xform_derive_keys (not_implemented): pass
class xform_dh_commit_r (not_implemented): pass
class xform_dh_commit_s (not_implemented): pass
class xform_dh_key_r (not_implemented): pass
class xform_dh_key_s (not_implemented): pass
class xform_mpi (not_implemented): pass
class xform_network_input_mux (not_implemented): pass
class xform_network_output_mux (not_implemented): pass
class xform_reveal_old_mac_keys (not_implemented): pass
class xform_reveal_signature_r (not_implemented): pass
class xform_reveal_signature_s (not_implemented): pass
class xform_select_remote_pubkey (not_implemented): pass
class xform_signature_r (not_implemented): pass
class xform_signature_s (not_implemented): pass
class xform_split_local_pubkeys (not_implemented): pass
class xform_split (not_implemented): pass
class xform_split_x (not_implemented): pass
class xform_verify_counter (not_implemented): pass

class layout_authenticator_s (not_implemented): pass
class layout_determine_end (not_implemented): pass
class layout_layout_m (not_implemented): pass
class layout_select_local_pubkey (not_implemented): pass
class layout_select_secret_key (not_implemented): pass
