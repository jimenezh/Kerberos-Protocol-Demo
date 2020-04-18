from datetime import datetime
class HTTP_Server:
    def __init__(self, name, secret_key):
        self.name = name
        self.ID = hash(name)
        self.secret_key = secret_key
        self.session_key = None
        self.past_authenticator = {}
        self.current_authenticator = None
    
    def process_client_request(self, client_request):
        """ Verifies that the client request is valid. Extracts https session key"""
        http_ticket = client_request[1]
        self.session_key = http_ticket[-1]
        client_authenticator = client_request[0]
        self.create_authenticator()
        return self.current_authenticator
        
    def contact_client(self):
        """ Final step in authentication. Sends back authenticator encrypted with session key"""
        self.create_authenticator()
        return self.current_authenticator

    def create_authenticator(self):
        """Creates authenticator with ID and timestamp"""
        self.current_authenticator=  [self.ID, datetime.now()]
