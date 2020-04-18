from user import User
from kerberos import Kerberos
from http import HTTP_Server

ticket_lifetime = 5*60

# init
server = Kerberos()
username = input("Welcome to the magical Kerberos simulation! \nThis is your first time using this service, so please provide us with your username: ")
password = input("What would you like your password to be? ")
user = User(username, "1.1.1.1", password)
server.kinit(user.ID, user.password)
print("Welcome,", username + "! Your registration is successful :)")

# Initializing server request
service = input("\nWhat service would you like to access today?\n1. Email \n2. Printing \n3. Zoom\nEnter the name of the service here: ")

# enter user/password again??

# Sending oritinal request from user to Authenticating server
print("\nGenerating init request")
init_request = user.get_init_request(ticket_lifetime)
print("Process init request")
print("Communication with Kerberos server...")
user.process_tgt(server.process_request(init_request))
print("You have been successfully authenticated as", username)
print("\nHere is your encrypted TGT: ", user.tgt)
print("Here is your TGS Session Key: ", user.tgs_session_key)

# TGS Server
print('Requesting', service,' Ticket from the TGS...')
http_request = user.get_HTTP_request(service, ticket_lifetime)
response = server.process_request(http_request)
user.process_HTTP_ticket(response)
print('Your HTTP Ticket is:', user.http_ticket)
print("Your HTTP Session Key:", user.http_session_key)

# HTTP Server
print("Contacting the HTTP Service...")
http = HTTP_Server(service, '0000')
message = user.contact_HTTP_server()
print("Sending request:", message)
response = http.process_client_request(message)
print(response)
is_valid = user.process_HTTP_server_contact(response)
print(is_valid)


