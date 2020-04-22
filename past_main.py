from user import User
from kerberos import Kerberos
from http import HTTP_Server
import time

ticket_lifetime = 5*60

# init
server = Kerberos()
username = input("Welcome to the magical Kerberos simulation! \nThis is your first time using this service, so please provide us with your username: ")
password = ''
while(len(password) != 16):
    password = input("What would you like your password to be?\nIt must be 16 characters long: ")

user = User(username, "1.1.1.1", password)
server.kinit(user.ID, user.password)
time.sleep(1)
print("\n\nWelcome,", username + "! Your registration is successful :)")

# Initializing server request
service = input("\nWhat service would you like to access today?\n1. Email \n2. Printing \n3. Zoom\nEnter the name of the service here: ")

# enter user/password again??

# Sending oritinal request from user to Authenticating server
print("\nGenerating authentication request")
time.sleep(1)
init_request = user.get_init_request(ticket_lifetime)
time.sleep(1)
print("Sending the following request to the authenticating server:", init_request)
time.sleep(1)
print("Request received by the authenticating server. Processing request...")
time.sleep(2)
user.process_tgt(server.process_request(init_request))
print("You have been successfully authenticated as", username)
print("Sending back TGT to user...")
time.sleep(3)

# TGT
print("\n\nYou have received the an encrypted TGT and an encrypted TGS session key")
print("Here is your encrypted TGT: ", user.tgt)
print("\nUnencrypting TGS session key...")
time.sleep(1)
print("Here is your TGS sesison key", user.tgs_session_key)
time.sleep(3)

# TGS Server
print('\n\nGenerating', service,' Ticket...')
time.sleep(1)
http_request = user.get_HTTP_request(service, ticket_lifetime)
print("Sending", http_request,"encrpted with", user.tgs_session_key, "key to TGT Server..." )
time.sleep(1)
print("Request has been received by TGT server. Processing...")
response = server.process_request(http_request)
time.sleep(2)
print("TGT server is sending back the following response", response)
print("\nProcessing the response...")
time.sleep(2)
user.process_HTTP_ticket(response)
print('Your (encrypted) HTTP Ticket is:', user.http_ticket)
print("Decrypting the HTTP Session Key...")
time.sleep(1)
print("Your HTTP Session Key is:", user.http_session_key)
time.sleep(3)


# HTTP Server
print("\n\nWe can now contact the HTTP server.\nGenerating HTTP Request...")
time.sleep(1)
http = HTTP_Server(service, server.database.http_key, server.database.http_nonce)
message = user.contact_HTTP_server()
print("Sending the request for", service, 'with unique ID', hash(service))
time.sleep(2)
print( "The HTTP server has received the following request from %s:".format(username) , message)
response = http.process_client_request(message)
print("HTTP server has verified your identity")
time.sleep(1)
print("HTTP server has responded with proof of its identity")
time.sleep(2)
print("Verifying identity of server...")
time.sleep(3)

if user.process_HTTP_server_contact(response):
    print('Here are the server\'s credentials:', user.http_auth)
    print('\n\n\nCongratulations! You have successfully connected with the HTTP Server\n\n\n')
else:
    print('\nOops! Seems like someone tried to tamper with your connection :(')


