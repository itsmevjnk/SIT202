from socket import *

# server IP address and port
SERVER_NAME = '127.0.0.1'
SERVER_PORT = 11202 # must be the same as server.py

BUF_SIZE = 2048 # receive buffer size

print('Opening socket.')
with socket(AF_INET, SOCK_DGRAM) as clientSocket:
    message = input('Enter the message to be sent: ')

    print(f'Sending message "{message}" to server.')
    clientSocket.sendto(message.encode(), (SERVER_NAME, SERVER_PORT)) # messages must be sent out as bytes

    print('Awaiting response from server.')
    response, serverAddress = clientSocket.recvfrom(BUF_SIZE)
    print(f'Received response from {serverAddress}: {response.decode()}')

    print('Closing socket.')
    clientSocket.close() # or we can let Python do that for us
