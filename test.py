from user import User
from kerberos import Kerberos
from http import HTTP_Server

ticket_lifetime = 5*60

# init
server = Kerberos()
username = 'alice'
password = 'p'*16
user = User(username, "1.1.1.1", password)
server.kinit(user.ID, user.password)

# print("Welcome,", username + "! Your registration is successful :)")

# Initializing server request
service = 'zoom'

# enter user/password again??

# Sending oritinal request from user to Authenticating server
# print("\nGenerating init request")
init_request = user.get_init_request(ticket_lifetime)
# print("Process init request")
print("Communication with Kerberos server...")
user.process_tgt(server.process_request(init_request))
print("You have been successfully authenticated as", username)
print("\nHere is your encrypted TGT: ", user.tgt)
print("Here is your TGS Session Key: ", user.tgs_session_key)


print('\n\nRequesting', service,' Ticket from the TGS...')
http_request = user.get_HTTP_request(service, ticket_lifetime)
response = server.process_request(http_request)
user.process_HTTP_ticket(response)
print('Your (encrypted) HTTP Ticket is:', user.http_ticket)
print("Your HTTP Session Key:", user.http_session_key)

print("\n\nContacting the HTTP Service...")
http = HTTP_Server(service, server.database.http_key, server.database.http_nonce)
message = user.contact_HTTP_server()
print("Sending request for", service, 'with unique ID', hash(service))
response = http.process_client_request(message)

if user.process_HTTP_server_contact(response):
    print('\nCongratulations! You have successfully connected with the HTTP Server')
    print('Here are the server\'s credentials:', user.http_auth)
else:
    print('\nOops! Seems like someone tried to tamper with your connection :(')
