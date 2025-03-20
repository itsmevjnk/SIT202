from socket import *
import os

# server IP address and port
SERVER_NAME = '127.0.0.1'
SERVER_PORT = 11202 # must be the same as server.py

BUF_SIZE = 2048 # receive buffer size

print('Opening socket.')
clientSocket = socket(AF_INET, SOCK_DGRAM) # UDP socket

def sendHello():
    print('Sending Hello to server.')
    clientSocket.sendto(b'Hello', (SERVER_NAME, SERVER_PORT)) # must be bytes

    response, serverAddress = clientSocket.recvfrom(BUF_SIZE)
    print(f'Received response from {serverAddress}: {response.decode()}')

CONTINUOUS = int(os.getenv('CONTINUOUS', '1'))
if CONTINUOUS == 0: # non-continuous communication (send Hello before asking for name - to demonstrate timeout)
    sendHello()

name = input('Enter your name: ')

if CONTINUOUS != 0: # continuous communication (to avoid timing out)
    sendHello()

print(f'Sending message "{name}" to server.')
clientSocket.sendto(name.encode(), (SERVER_NAME, SERVER_PORT))

response, serverAddress = clientSocket.recvfrom(BUF_SIZE)
print(f'Received response from {serverAddress}: {response.decode()}')

print('Closing socket.')
clientSocket.close()
