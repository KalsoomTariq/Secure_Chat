from flask import Flask, render_template, request, flash, redirect, url_for
import sys
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import socket

# Diffie-Hellman public parameters
P = 23  # Example prime, replace with a large secure prime for production
G = 5   # Generator

app = Flask(__name__)
app.secret_key = "12345"

# Client's private and public key generation for Diffie-Hellman
client_private_key = random.randint(1, P - 2)
client_public_key = pow(G, client_private_key, P)

# Encrypt data with AES-128-CBC using the shared key
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv + ciphertext  # prepend IV for decryption on the server

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Set up connection with the main server for DH key exchange
        server_address = ('localhost', 5000)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(server_address)

        # Send client public key and receive server's public key
        client_socket.sendall(str(client_public_key).encode())
        server_public_key = int(client_socket.recv(1024).decode())

        # Compute shared secret Kab
        Kab = pow(server_public_key, client_private_key, P)
        shared_key = hashlib.sha256(str(Kab).encode()).digest()[:16]  # 128-bit AES key

        # Send action type 'register'
        client_socket.sendall(b'register')

        # Encrypt registration data
        encrypted_email = encrypt_data(email, shared_key)
        encrypted_username = encrypt_data(username, shared_key)
        encrypted_password = encrypt_data(password, shared_key)

        # Send encrypted data to the server
        client_socket.sendall(encrypted_email + b'||' + encrypted_username + b'||' + encrypted_password)

        # Receive server's response
        response = client_socket.recv(1024).decode()
        client_socket.close()

        flash(response)
        return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Set up connection with server for Diffie-Hellman key exchange
        server_address = ('localhost', 5000)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(server_address)

        # Generate public key and exchange keys with server
        client_socket.sendall(str(client_public_key).encode())
        server_public_key = int(client_socket.recv(1024).decode())

        # Calculate shared secret Kab
        Kab = pow(server_public_key, client_private_key, P)
        shared_key = hashlib.sha256(str(Kab).encode()).digest()[:16]

        # Send action type 'login'
        client_socket.sendall(b'login')

        # Encrypt username and password
        encrypted_username = encrypt_data(username, shared_key)
        encrypted_password = encrypt_data(password, shared_key)

        # Send encrypted credentials to the server
        client_socket.sendall(encrypted_username + b'||' + encrypted_password)

        # Receive server's response
        response = client_socket.recv(1024).decode()
        client_socket.close()

        if response == "Login successful! Welcome to the chat system.":
            flash("Login successful!")
            return redirect(url_for('home_page'))
        else:
            flash(response)

    return render_template('login.html')

@app.route('/home')
def home_page():
    return render_template('home.html')

if __name__ == '__main__':
    # Take the port as a command-line argument or set a default
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001  # default to 5001
    app.run(port=port)
