# File: server.py
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# 1. Generate RSA Keys and get the public key in PEM format
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 2. Set up the server socket
HOST = '127.0.0.1'
PORT = 65432

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print(f"[SERVER] Listening on {HOST}:{PORT}")
conn, addr = server_socket.accept()

with conn:
    print(f"[SERVER] Connected by {addr}")

    # 3. Send the public key to the client
    conn.sendall(pem_public_key)
    print("[SERVER] Public key sent to the client.")

    # 4. Receive data from the client
    data = conn.recv(1024)
    print(f"[SERVER] Received message from client: {data.decode()}")

    # 5. Sign the received message with the server's private key
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("[SERVER] Message signed.")

    # 6. Send the original message and the signature back for verification
    conn.sendall(data)
    conn.sendall(signature)
    print("[SERVER] Original message and signature sent to client.")

print("[SERVER] Connection closed.")
server_socket.close()