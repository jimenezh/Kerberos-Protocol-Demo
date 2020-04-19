from datetime import datetime
from encryption import decrypt, encrypt, create_nonce
class HTTP_Server:
    def __init__(self, name, secret_key,nonce):
        self.name = name
        self.ID = hash(name)
        self.secret_key = secret_key
        self.session_key = None
        self.past_authenticators = {}
        self.current_authenticator = None
        self.nonce = nonce
    
    def process_client_request(self, client_request):
        """ Verifies that the client request is valid. Extracts https session key"""
        client_nonce = client_request[-1]
        http_ticket = decrypt( client_request[1], self.secret_key, self.nonce)
        
        self.session_key = http_ticket[-1]
        client_authenticator = decrypt( client_request[0], self.session_key, client_nonce)
        
        if(client_authenticator[0] not in self.past_authenticators):
            # add to past authenticators
            if(self.verify_ticket(client_authenticator, http_ticket)  ):
                self.create_authenticator()
                nonce = create_nonce()
                enc_auth = encrypt(self.current_authenticator, self.session_key, nonce)
                return [enc_auth, nonce]

        return None   

    def verify_ticket(self, auth, http_ticket):
        if(auth[0] == http_ticket[1]):
            t1 = datetime.fromisoformat(  http_ticket[3].decode())
            t2 = datetime.fromisoformat(auth[-1].decode())
            return (t2-t1).total_seconds() <= 60



    def contact_client(self):
        """ Final step in authentication. Sends back authenticator encrypted with session key"""
        self.create_authenticator()
        return self.current_authenticator

    def create_authenticator(self):
        """Creates authenticator with ID and timestamp"""
        self.current_authenticator=  [self.ID, datetime.now()]
