from datetime import datetime

class User:
    
    def __init__(self, ID, IP, password):
        self.ID = ID
        self.IP = IP
        self.password = password
        self.secret = hash(password)
        self.tgs_session_key = None
        self.tgt = None
        self.http_session_key = None
        self.http_ticket = None
        self.service_request = None
        self.current_authenticator = None

    # to auth server
    def get_init_request(self, lifetime):
        """Returns the original request to the Kerberos server"""
        return [self.ID, self.IP, lifetime, "TGS"]
            
    def process_tgt(self, auth_return):
        """Documents the message returned by the auth server"""
        self.tgt = auth_return[0]
        self.tgs_session_key = auth_return[1]  #abstract decrypt for now
    # To TGS
    def get_HTTP_request(self, http_service_type, lifetime):
        """
            Returns the HTTP request which will be sent to TGT server. This includes the service,
            the TGT, and an authenticator. Encrypted with tgs session key
        """
        self.service_request = http_service_type
        self.create_authenticator()
        return [http_service_type, self.tgt, self.current_authenticator]
    def process_HTTP_ticket(self, http_return):
        """Documents the message returned by the TGT"""
        self.http_ticket = http_return[0]
        self.http_session_key = http_return[1]
    # To HTTP server
    def contact_HTTP_server(self):
        """
            First message to the HTTP server. Includes an authenticator and the http ticket
            returned by the TGT. Encrypted with HTTP session key
        """
        self.create_authenticator()
        return [self.current_authenticator, self.http_ticket]
    def process_HTTP_server_contact(self, http_return):
        """Processing response by HTTP server. Should be an authenticator"""
        req_type = http_return[0]
        timestamp = http_return[1]
        if req_type == hash(self.service_request):
            return (timestamp - self.current_authenticator[1]).total_seconds() <= 60
        return False

    def create_authenticator(self):
        self.current_authenticator = [self.ID,   datetime.now()]

