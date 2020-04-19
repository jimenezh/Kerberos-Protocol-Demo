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
service = input("\nWhat service would you like to access today?\n1. Email \n1. Printing \n1. Zoom\nEnter the name of the service here: ")

# enter user/password again??

# Sending oritinal request from user to Authenticating server
print("\nGenerating init request")
time.sleep(1)
init_request = user.get_init_request(ticket_lifetime)
print("Process init request")
time.sleep(1)
print("Communication with Kerberos server...")
time.sleep(1)
user.process_tgt(server.process_request(init_request))
print("You have been successfully authenticated as", username)
print("\nHere is your encrypted TGT: ", user.tgt)
print("Here is your TGS Session Key: ", user.tgs_session_key)

# TGS Server
print('\n\nRequesting', service,' Ticket from the TGS...')
time.sleep(2)
http_request = user.get_HTTP_request(service, ticket_lifetime)
response = server.process_request(http_request)
user.process_HTTP_ticket(response)
print('Your HTTP Ticket is:', user.http_ticket)
print("Your HTTP Session Key:", user.http_session_key)


# HTTP Server
print("\n\nContacting the HTTP Service...")
time.sleep(1)
http = HTTP_Server(service, server.database.http_key, server.database.http_nonce)
message = user.contact_HTTP_server()
print("Sending request for", service, 'with unique ID', hash(service))
time.sleep(1)
response = http.process_client_request(message)
time.sleep(1)

if user.process_HTTP_server_contact(response):
    print('\nCongratulations! You have successfully connected with the HTTP Server')
    print('Here are the server\'s credentials:', user.http_auth)
else:
    print('\nOops! Seems like someone tried to tamper with your connection :(')


