from datetime import datetime
from encryption import encrypt, decrypt, create_random_16_bytes

class User:
    
    def __init__(self, ID, IP, password):
        self.ID = ID
        self.IP = IP
        self.password = password.encode()
        self.secret = hash(password)
        self.tgs_session_key = None
        self.tgt = None
        self.http_session_key = None
        self.http_ticket = None
        self.service_request = None
        self.current_authenticator = None
        self.nonce = None

    # to auth server
    def get_init_request(self, lifetime):
        """Returns the original request to the Kerberos server"""
        return [self.ID, self.IP, lifetime]
            
    def process_tgt(self, auth_return):
        """Documents the message returned by the auth server"""
        self.tgt = auth_return[0]
        self.tgs_session_key = decrypt(auth_return[1], self.password, auth_return[2])
     
    # To TGS
    def get_HTTP_request(self, http_service_type, lifetime):
        """
            Returns the HTTP request which will be sent to TGT server. This includes the service,
            the TGT, and an authenticator. Encrypted with tgs session key
        """
        self.service_request = http_service_type
        self.create_authenticator()
        self.nonce = create_random_16_bytes()
        return [http_service_type, self.tgt, encrypt(self.current_authenticator,self.tgs_session_key, self.nonce), self.nonce]
    def process_HTTP_ticket(self, http_return):
        """Documents the message returned by the TGT"""
        nonce = http_return[2]
        self.http_ticket = http_return[0]

        self.http_session_key = decrypt(http_return[1], self.tgs_session_key, nonce)
    # To HTTP server
    def contact_HTTP_server(self):
        """
            First message to the HTTP server. Includes an authenticator and the http ticket
            returned by the TGT. Encrypted with HTTP session key
        """
        self.create_authenticator()
        self.nonce = create_random_16_bytes()
        enc_auth = encrypt(self.current_authenticator, self.http_session_key, self.nonce)

        return [ enc_auth, self.http_ticket, self.nonce]
    def process_HTTP_server_contact(self, http_return):
        """Processing response by HTTP server. Should be an authenticator"""
        self.nonce = http_return[-1]
        self.http_auth= decrypt(http_return[0], self.http_session_key, self.nonce)
        
        req_type = self.http_auth[0]
        timestamp = datetime.fromisoformat(self.http_auth[1].decode())
    
        if req_type == hash(self.service_request):
            return (timestamp - self.current_authenticator[1]).total_seconds() <= 60
        return False

    def create_authenticator(self):
        self.current_authenticator = [self.ID,   datetime.now()]

