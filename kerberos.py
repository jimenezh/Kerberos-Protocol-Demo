from datetime import datetime
from encryption import encrypt, decrypt, create_random_16_bytes
from KDC import KDC

class Auth_Server:
    def __init__(self, database):
        self.database = database
    def process_request(self, request):
        # check if a user is valid
        if request[0] not in self.database.users:
            raise KeyError("Invalid User")
        # check lifetime validity
        t1 = datetime.fromisoformat(request[2])
        t2 = datetime.now()
        if (t2 - t1).total_seconds() > 60:
            raise Exception("Ticket has expired")
        

        # client ID, client IP, ticket lifetime, time, TGS session key
        self.database.tgs_session_key = create_random_16_bytes()
        tgt = [request[0], request[1], request[2], datetime.now(), self.database.tgs_session_key] # CHANGE!!!, encrypt stuff using secret
        
        self.database.tgt_nonce = create_random_16_bytes()

        enc_tgt = encrypt(tgt, self.database.key, self.database.tgt_nonce)
        enc_session_key = encrypt(self.database.tgs_session_key, self.database.users[request[0]], self.database.tgt_nonce)
    
        return (enc_tgt, enc_session_key, self.database.tgt_nonce) # encrypt tgs session key with client secret
   

class TGS:
    def __init__(self, database):
        self.database = database
    
    def process_request(self, request):
        http_service = request[0]
        tgt = request[1]
        authenticator = request[2]
        nonce = request[3]

        # check http service validity
        tgt = decrypt(tgt, self.database.key, self.database.tgt_nonce)
        
        authenticator = decrypt(authenticator, self.database.tgs_session_key, nonce)
        # check authenticator validity
        if authenticator[0] != tgt[0]:
            raise Exception("Invalid authenticator")
        # check lifetime validity
        t1 = datetime.fromisoformat(tgt[3])
        t2 = datetime.fromisoformat(authenticator[1])
        if (t2 - t1).total_seconds() > 30*5:
            raise Exception("Ticket has expired")

        self.database.http_session_key = create_random_16_bytes()
        http_ticket = [http_service, tgt[0], tgt[1], datetime.now(), tgt[2], self.database.http_session_key]

        self.database.http_nonce = create_random_16_bytes()
        enc_ticket = encrypt(http_ticket, self.database.http_key, self.database.http_nonce)

        enc_session_key = encrypt(self.database.http_session_key, self.database.tgs_session_key, self.database.http_nonce)
        return [enc_ticket, enc_session_key, self.database.http_nonce]




class Kerberos:
    # global users
    # users = {}

    def __init__(self):
        self.database = KDC()
        
        self.auth = Auth_Server(self.database)
        self.TGS = TGS(self.database)
        self.database.key = create_random_16_bytes() #secret server key
        self.database.http_key = create_random_16_bytes()
        
        
    

    def kinit(self, ID, password):
        self.database.users[ID] = password


    def process_request(self, request):
        # auth request
        if len(request) == 3:
            return self.auth.process_request(request)
        
        # tgs request
        if len(request) == 4:
       
            return self.TGS.process_request(request)


