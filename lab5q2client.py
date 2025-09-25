import socket
import hashlib

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432  # The port used by the server


def compute_hash(data):
    """
    Computes the SHA256 hash of the given data.
    Returns the hash digest as a hexadecimal string.
    """
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def verify_integrity(local_hash, received_hash):
    """
    Compares the two hashes to verify data integrity.
    """
    return local_hash == received_hash


def main():
    """
    The main function for the client script.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the server
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        # --- Scenario 1: Successful Transmission ---
        original_message = b"This is a secret message that must remain unchanged."
        print("\n--- Scenario 1: Verifying a clean message ---")
        print(f"Original message to send: '{original_message.decode()}'")

        # Compute the local hash of the original message
        local_hash = compute_hash(original_message)
        print(f"Local hash computed before sending: {local_hash}")

        # Send the message to the server
        s.sendall(original_message)
        print("Sent message to server.")

        # Receive the hash from the server
        received_hash = s.recv(1024).decode()
        print(f"Received hash from server: {received_hash}")

        # Verify integrity by comparing the hashes
        if verify_integrity(local_hash, received_hash):
            print("INTEGRITY CHECK PASSED: Data was transmitted successfully.")
        else:
            print("INTEGRITY CHECK FAILED: Data may have been tampered with or corrupted.")

        # --- Scenario 2: Simulated Data Corruption ---
        corrupted_message = b"This is a fake message."
        print("\n--- Scenario 2: Simulating data corruption ---")
        # In a real-world scenario, this 'corruption' might happen during transit.
        # Here, we'll intentionally compare the hash of a different message.
        print(f"Simulating a corrupted version of the data: '{corrupted_message.decode()}'")

        # Compute the local hash of the *corrupted* message
        local_hash_corrupted = compute_hash(corrupted_message)
        print(f"Local hash of corrupted data: {local_hash_corrupted}")

        # For this test, we'll send the *original* message again to the server.
        # This simulates receiving the hash of the *correct* message from a server
        # that thinks the transmission was fine, while our local copy is corrupted.
        s.sendall(original_message)
        print("Sent original message to server again.")

        # Receive the hash from the server (this hash is of the original message)
        received_hash_original = s.recv(1024).decode()
        print(f"Received hash from server (of the original message): {received_hash_original}")

        # Now, we compare the local hash of the *corrupted* message with the
        # hash received from the server (which is of the original message).
        if verify_integrity(local_hash_corrupted, received_hash_original):
            print("INTEGRITY CHECK PASSED: Data transmission appears fine.")
        else:
            print("INTEGRITY CHECK FAILED: The local data does not match the data received by the server.")
            print("Hash mismatch detected. The data was likely corrupted during transit.")


if __name__ == "__main__":
    main()