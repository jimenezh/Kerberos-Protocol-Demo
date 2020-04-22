
class KDC:
    """ Database shared between Kerberos servers"""
    def __init__(self):
        self.users = {}
        self.tgt_nonce = None
        self.key = None
        self.tgs_session_key = None
        self.http_key = None
        self.http_session_key = None
        self.http_nonce = None
