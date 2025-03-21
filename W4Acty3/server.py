from socket import *

# server listening IP and port
SERVER_NAME = '' # IP address of interface to listen on, keep empty to listen on all network interfaces
SERVER_PORT = 11202 # must be the same as client.py

BUF_SIZE = 2048 # receive buffer size

with socket(AF_INET, SOCK_DGRAM) as serverSocket:
    print('Binding socket.')
    serverSocket.bind((SERVER_NAME, SERVER_PORT))

    while True:
        print('Awaiting message from client.')
        message, clientAddress = serverSocket.recvfrom(BUF_SIZE)
        messageStr = message.decode() # decode back to str
        print(f'\tReceived message from {clientAddress}: {messageStr}')
        print(f'\tMessage length: {len(messageStr)}')
        
        print(f'\tSending response to {clientAddress}.')
        serverSocket.sendto(f'{len(messageStr)},{messageStr.upper()}'.encode(), clientAddress)
