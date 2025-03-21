from socket import *

# server configuration
SERVER_NAME = '127.0.0.1' # server's address
SERVER_PORT = 11202 # port number to bind the server to (must be the same as in server.py)

BUFFER_SIZE = 2048 # receive buffer size

message = input('Enter your message: ')

with socket(AF_INET, SOCK_STREAM) as clientSocket:
    print(f'Connecting to {SERVER_NAME} on port {SERVER_PORT}.')
    clientSocket.connect((SERVER_NAME, SERVER_PORT))
    
    print(f'Sending message "{message}" to server.')
    clientSocket.sendall(message.encode()) # encode to bytes before sending
    
    response = clientSocket.recv(BUFFER_SIZE).decode() # decode back to str
    print(f'Received data from server: "{response}"')

    clientSocket.close() # close connection (or it can be done automatically for us by Python)
