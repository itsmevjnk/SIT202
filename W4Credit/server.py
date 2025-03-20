from socket import *

# server listening IP and port
SERVER_NAME = '' # IP address of interface to listen on, keep empty to listen on all network interfaces
SERVER_PORT = 11202 # must be the same as client.py

BUF_SIZE = 2048 # receive buffer size

print(f'Binding socket to port {SERVER_PORT}.')
serverSocket = socket(AF_INET, SOCK_DGRAM) # UDP socket
serverSocket.bind((SERVER_NAME, SERVER_PORT))

helloClients: set[tuple[str, int]] = set() # list of clients that sent Hello
# when the client has sent their name, we will remove them from the list (since communication is over at that stage)

while True:
    message, clientAddress = serverSocket.recvfrom(BUF_SIZE)
    messageStr = message.decode() # decode back to str
    print(f'Received message from {clientAddress}: {messageStr}')
    responseStr = ''
    if clientAddress not in helloClients: # initial communication - respond with "Hello, What's your name?"
        print('\t-> Hello message received.')
        helloClients.add(clientAddress)
        responseStr = 'Hello, What\'s your name?'
    else: # subsequent communication (name) - respond with "Hello {name}, Welcome to SIT202"
        print('\t-> Name message received.')
        helloClients.remove(clientAddress)
        responseStr = f'Hello {messageStr}, Welcome to SIT202'

    print(f'\t-> Response: {responseStr}')
    serverSocket.sendto(responseStr.encode(), clientAddress)
