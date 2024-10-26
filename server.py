import os
import random
import hashlib
import csv
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Diffie-Hellman public parameters
P = 23  # Example prime, replace with a large secure prime for production
G = 5   # Generator

# Server's private and public key generation
server_private_key = random.randint(1, P - 2)
server_public_key = pow(G, server_private_key, P)

# AES encryption/decryption functions
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

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
    salt = os.urandom(4)  # 32 bits salt
    salted_password = salt + password.encode()
    hashed_password = hashlib.sha256(salted_password).hexdigest()

    # Store credentials in creds.csv
    with open('creds.csv', mode='a', newline='') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([email, username, hashed_password, salt.hex()])
    
    return True, "Registration successful!"

# Server socket setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5000))
server_socket.listen(5)
print("Server is listening for connections...")

# Listen for client connections
while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connected by {client_address}")

    # Diffie-Hellman key exchange
    client_public_key = int(client_socket.recv(1024).decode())
    client_socket.sendall(str(server_public_key).encode())

    # Compute shared secret Kab
    Kab = pow(client_public_key, server_private_key, P)
    shared_key = hashlib.sha256(str(Kab).encode()).digest()[:16]  # 128-bit AES key

    # Receive encrypted credentials
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

    client_socket.close()
