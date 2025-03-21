from socket import *

# server configuration
SERVER_NAME = '' # IP address to bind the server to (leave empty to bind to all network interfaces)
SERVER_PORT = 11202 # port number to bind the server to (must be the same as in client.py)
BACKLOG = 1 # number of unaccepted connections the server will allow before refusing
BUFFER_SIZE = 2048 # receive buffer size

with socket(AF_INET, SOCK_STREAM) as serverSocket:
    print(f'Binding to port {SERVER_PORT}.')
    serverSocket.bind((SERVER_NAME, SERVER_PORT))
    serverSocket.listen(BACKLOG)
    while True:
        conn, clientAddress = serverSocket.accept() # accept next client connection
        with conn:
            print(f'Connection initiated by {clientAddress}')
            data = conn.recv(BUFFER_SIZE).decode() # receive message from client and decode it back to str
            print(f'\tIncoming data: "{data}" ({len(data)} bytes)')
            response = f'{len(data)},{data.upper()}'
            print(f'\tSending response: "{response}"')
            conn.sendall(response.encode()) # encode back to bytes before sending
            # afterwards, the connection will be automatically closed for us
            # either that or the client closes the connection
