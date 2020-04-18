from datetime import datetime

class Auth_Server:


    def process_request(self, request):
        # check if a user is valid
        if request[0] not in users:
            raise KeyError("Invalid User")
        # check lifetime validity


        # client ID, client IP, ticket lifetime, time, TGS session key
        session_key = b'1234'
        tgt = [request[0], request[1], request[2], datetime.now(), session_key] # CHANGE!!!, encrypt stuff using secret
        return (tgt, session_key) # encrypt tgs session key with client secret
   

class TGS:

    def process_request(self, request):
        http_service = request[0]
        tgt = request[1]
        authenticator = request[2]

        # check http service validity

        # tgt = decrypt(tgt, key)
        session_key = tgt[4]
        # authenticator = decrypt(authenticator, session_key)

        # check authenticator validity
        if authenticator[0] != tgt[0]:
            raise Exception("Invalid authenticator")
        # check lifetime validity

        http_key = b'333'
        http_ticket = [http_service, tgt[1], datetime.now(), tgt[2], http_key]

        return [http_ticket, http_key]




class Kerberos:
    global users
    users = {}

    def __init__(self):
        self.auth = Auth_Server()
        self.TGS = TGS()
        self.key = b'123456789' #secret server key
    

    def kinit(self, ID, password):
        users[ID] = password

    def process_request(self, request):
        # auth request
        if len(request) == 4:
            return self.auth.process_request(request)
        
        # tgs request
        if len(request) == 3:
            return self.TGS.process_request(request)

        # http request
        if len(request) == 2:
            print("MAGIC")


