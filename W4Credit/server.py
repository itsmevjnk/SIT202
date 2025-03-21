from socket import *
import select
import time

# server listening IP and port
SERVER_NAME = '' # IP address of interface to listen on, keep empty to listen on all network interfaces
SERVER_PORT = 11202 # must be the same as client.py

BUF_SIZE = 2048 # receive buffer size

CLIENT_TIMEOUT = 10.0 # client timeout duration
SELECT_TIMEOUT = 0.5 # timeout for select() call, so we don't end up sitting around forever waiting for data

with socket(AF_INET, SOCK_DGRAM) as serverSocket: # UDP socket
    serverSocket.setblocking(False) # disable blocking (so we can run client expiry code while waiting for packet)

    print(f'Binding socket to port {SERVER_PORT}.')
    serverSocket.bind((SERVER_NAME, SERVER_PORT))

    helloClients: dict[tuple[str, int], float] = dict() # list of clients that sent Hello
    # when the client has sent their name, we will remove them from the list (since communication is over at that stage)

    while True:
        readSockets, _, _ = select.select([serverSocket], [], [], SELECT_TIMEOUT) # check if socket has data to be read
        if serverSocket not in readSockets: # no data available - run client cleanup
            currentTime = time.time()
            removeClients = [] # list of clients to remove
            for client in helloClients:
                if helloClients[client] + CLIENT_TIMEOUT < currentTime: # this client timed out
                    print(f'Client {client} timed out')
                    removeClients.append(client)
            for client in removeClients:
                helloClients.pop(client) # finally remove the clients
            continue # do not read from socket, otherwise there'll be errors        
        
        message, clientAddress = serverSocket.recvfrom(BUF_SIZE)
        messageStr = message.decode() # decode back to str
        print(f'Received message from {clientAddress}: {messageStr}')
        responseStr = ''
        if clientAddress not in helloClients: # initial communication - respond with "Hello, What's your name?"
            print('\t-> Hello message received.')
            helloClients[clientAddress] = time.time()
            responseStr = 'Hello, What\'s your name?'
        else: # subsequent communication (name) - respond with "Hello {name}, Welcome to SIT202"
            print('\t-> Name message received.')
            helloClients.pop(clientAddress)
            responseStr = f'Hello {messageStr}, Welcome to SIT202'

        print(f'\t-> Response: {responseStr}')
        serverSocket.sendto(responseStr.encode(), clientAddress)
