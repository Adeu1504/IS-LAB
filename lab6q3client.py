# Try the same in a client server-based scenario and record your observation and
# analysis.

# File: client.py
import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# 1. Set up the client socket
HOST = '127.0.0.1'
PORT = 65432

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print(f"[CLIENT] Connected to server at {HOST}:{PORT}")

# 2. Receive the server's public key
pem_public_key = client_socket.recv(1024)
public_key = serialization.load_pem_public_key(pem_public_key)
print("[CLIENT] Received public key from server.")

# 3. Send a message to the server to be signed
message = b"Please sign this message to confirm your identity."
client_socket.sendall(message)
print(f"[CLIENT] Sent message to server: {message.decode()}")

# 4. Receive the original message and the signature from the server
# The signature for RSA 2048 is 256 bytes long.
received_message = client_socket.recv(1024)
received_signature = client_socket.recv(1024)

print(f"[CLIENT] Received back message: {received_message.decode()}")
print(f"[CLIENT] Received signature (hex): {received_signature.hex()}")

# 5. Verify the signature using the server's public key
try:
    public_key.verify(
        received_signature,
        received_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\n[CLIENT] VERIFICATION RESULT: SUCCESS!")
    print("[CLIENT] The signature is valid. Message is authentic and unmodified.")

except InvalidSignature:
    print("\n[CLIENT] VERIFICATION RESULT: FAILED!")
    print("[CLIENT] The signature is invalid. The message may be compromised.")
except Exception as e:
    print(f"\n[CLIENT] An error occurred during verification: {e}")

print("[CLIENT] Closing connection.")
client_socket.close()