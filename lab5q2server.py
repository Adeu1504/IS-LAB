# Using socket programming in Python, demonstrate the application of hash functions
# for ensuring data integrity during transmission over a network. Write server and client
# scripts where the server computes the hash of received data and sends it back to the
# client, which then verifies the integrity of the data by comparing the received hash with
# the locally computed hash. Show how the hash verification detects data corruption
# or tampering during transmission.

# server.py

import socket
import hashlib

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def compute_hash(data):
    """
    Computes the SHA256 hash of the given data.
    Returns the hash digest as a hexadecimal string.
    """
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def main():
    """
    The main function for the server script.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind the socket to the host and port
        s.bind((HOST, PORT))
        print(f"Server listening on {HOST}:{PORT}")

        # Listen for incoming connections
        s.listen()
        conn, addr = s.accept()

        with conn:
            print(f"Connected by {addr}")

            # --- First transmission (successful) ---
            # Receive data from the client
            print("Receiving data from client...")
            data = conn.recv(1024)
            print(f"Received data: '{data.decode()}'")

            # Compute the hash of the received data
            data_hash = compute_hash(data)
            print(f"Computed hash: {data_hash}")

            # Send the computed hash back to the client
            conn.sendall(data_hash.encode())
            print("Sent hash back to client.")

            # --- Second transmission (simulated corruption) ---
            # Receive data from the client
            print("\nReceiving data for the second time...")
            data = conn.recv(1024)
            print(f"Received data: '{data.decode()}'")

            # Compute the hash of the received data
            data_hash = compute_hash(data)
            print(f"Computed hash: {data_hash}")

            # Send the computed hash back to the client
            conn.sendall(data_hash.encode())
            print("Sent hash back to client.")


if __name__ == "__main__":
    main()