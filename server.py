
'''
*****************************************************************************
*****************************************************************************

Name: Kalsoom Tariq
Roll no: I21-2487
Section: CS-Z

*****************************************************************************
*****************************************************************************

'''

import os
import random
import hashlib
import csv
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Diffie-Hellman public parameters
P = 23
G = 5

# Server's private and public key generation
server_private_key = random.randint(1, P - 2)
server_public_key = pow(G, server_private_key, P)

# Global variables
logged_user = None

# AES encryption/decryption functions
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv + ciphertext


# Check username uniqueness and store credentials
def store_credentials(email, username, password):
    # Check if username exists
    with open('creds.csv', mode='a+', newline='') as file:
        file.seek(0)
        csv_reader = csv.reader(file)
        is_unique = all(row[1] != username for row in csv_reader)

    if not is_unique:
        return False, "Error: Username already exists. Please choose another."

    # Generate salt and hash password
    salt = os.urandom(4)
    salted_password = password.encode() + salt
    print("Password: ", password)
    print("Salted Password: ", salted_password)
    hashed_password = hashlib.sha256(salted_password).hexdigest()

    # Store credentials in creds.csv
    with open('creds.csv', mode='a', newline='') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([email, username, hashed_password, salt.hex()])
    
    return True, "Registration successful!"

def verify_credentials(username, password):
    with open('creds.csv', mode='r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            stored_username, stored_hash, stored_salt = row[1], row[2], bytes.fromhex(row[3])
            if stored_username == username:
                hashed_input_password = hashlib.sha256(password.encode() + stored_salt).hexdigest()
                return hashed_input_password == stored_hash
    return False

# Handle individual client connections
def handle_client(client_socket):
    global logged_user
    try:
        # Diffie-Hellman key exchange
        client_public_key = int(client_socket.recv(1024).decode())
        client_socket.sendall(str(server_public_key).encode())

        # Compute shared secret Kab
        Kab = pow(client_public_key, server_private_key, P)
        shared_key = hashlib.sha256(str(Kab).encode()).digest()[:16]

        # Receive the action (registration or login)
        action = client_socket.recv(1024).decode()

        # Registration process
        if action == 'register':
            data = client_socket.recv(4096).split(b'||')
            encrypted_email, encrypted_username, encrypted_password = data

            # Decrypt the credentials
            email = decrypt_data(encrypted_email, shared_key)
            username = decrypt_data(encrypted_username, shared_key)
            password = decrypt_data(encrypted_password, shared_key)

            # Store credentials and check username uniqueness
            success, message = store_credentials(email, username, password)
            client_socket.sendall(message.encode())
            print(message)

        # Login process
        elif action == 'login':
            data = client_socket.recv(4096).split(b'||')
            encrypted_username, encrypted_password = data

            # Decrypt the credentials
            username = decrypt_data(encrypted_username, shared_key)
            password = decrypt_data(encrypted_password, shared_key)

            # Verify credentials
            if verify_credentials(username, password):
                message = "Login successful! Welcome to the chat system."
                logged_user = username
            else:
                message = "Error: Login failed. Invalid username or password."
            
            client_socket.sendall(message.encode())
            print(message)

        if logged_user:
            # Establish new creds
            chat_server_private_key = random.randint(1, P - 2)
            chat_server_public_key = pow(G, chat_server_private_key, P)

            chat_client_public_key = int(client_socket.recv(1024).decode())
            client_socket.sendall(str(chat_server_public_key).encode())

            # Compute shared secret Kab
            Kab = pow(chat_client_public_key, chat_server_private_key, P)
            chat_key = hashlib.sha256(f'{logged_user}{Kab}'.encode()).digest()[:16]

            # Start Chatting...
            while True:
                encrypted_message = client_socket.recv(4096)
                if not encrypted_message:
                    break
                message = decrypt_data(encrypted_message, chat_key)
                print(f"Client: {message}")

                if message.lower() == "bye":
                    response = "Session ended."
                    encrypted_response = encrypt_data(response, chat_key)
                    client_socket.sendall(encrypted_response)
                    logged_user = None
                    break
                response = None
                response = input('Server: ')
                encrypted_response = encrypt_data(response, chat_key)
                client_socket.sendall(encrypted_response)
                print("Response sent.", response)

    finally:
        client_socket.close()

# Server socket setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5000))
server_socket.listen(5)
print("Server is listening for connections...")

# Accept multiple client connections
while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connected by {client_address}")
    # Start a new thread for each client
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
