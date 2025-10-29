# IS LAB ENDSEM QUESTION : Client–Server Program for Seller and Payment Gateway
#
# Develop a client–server application that simulates transactions between multiple sellers and a payment gateway, as per the following specifications:
#
# 1. Sellers and Transactions
#
# Implement a minimum of two sellers.
#
# Each seller should perform at least two or more transactions.
#
#
#
# 2. Paillier Encryption for Transaction Amounts
#
# Each transaction amount must be encrypted using the Paillier encryption algorithm.
#
# The encrypted amounts should be added homomorphically to compute the total encrypted transaction amount for each seller.
#
# The total should then be decrypted to obtain the total decrypted amount.
#
#
#
# 3. Transaction Summary
#
# Maintain a transaction summary for all sellers containing the following details:
#
# Seller Name
#
# Individual Transaction Amounts
#
# Encrypted Transaction Amounts
#
# Decrypted Transaction Amounts
#
# Total Encrypted Transaction Amount
#
# Total Decrypted Transaction Amount
#
# Digital Signature Status
#
# Signature Verification Result
#
#
#
#
# 4. Digital Signature and Verification
#
# Generate and verify digital signatures using the RSA algorithm.
#
# Apply SHA-256 hashing on the entire transaction summary before signing and verifying.
#
#
#
# 5. Output Requirements
#
# Display the complete transaction summary for all sellers, including encryption, decryption, total amount computation, and signature verification results.

import socket
import pickle
from phe import paillier  # For Paillier encryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
HOST = 'localhost'
PORT = 9999
NUMBER_OF_SELLERS = 2


def generate_keys():
    """Generates Paillier and RSA key pairs."""
    print("Generating Paillier keypair (for encryption)...")
    paillier_pubkey, paillier_privkey = paillier.generate_paillier_keypair(n_length=1024)

    print("Generating RSA keypair (for digital signature)...")
    rsa_privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    rsa_pubkey = rsa_privkey.public_key()

    return paillier_pubkey, paillier_privkey, rsa_pubkey, rsa_privkey


def run_gateway():
    """Main server function."""

    # 1. Generate all cryptographic keys
    paillier_pubkey, paillier_privkey, rsa_pubkey, rsa_privkey = generate_keys()

    all_seller_data = []

    # 2. Setup socket server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(NUMBER_OF_SELLERS)
        print(f"\n✅ Payment Gateway is listening on {HOST}:{PORT}...")

        # 3. Accept connections from all sellers
        for i in range(NUMBER_OF_SELLERS):
            print(f"Waiting for seller {i + 1}/{NUMBER_OF_SELLERS}...")
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connection established with {addr}")

                # Step 3a: Send the Paillier public key to the seller
                conn.sendall(pickle.dumps(paillier_pubkey))

                # Step 3b: Receive the seller's data (name, encrypted_txs)
                data = conn.recv(4096)
                seller_name, encrypted_txs = pickle.loads(data)

                print(f"Received {len(encrypted_txs)} encrypted transactions from: {seller_name}")
                all_seller_data.append((seller_name, encrypted_txs))

    print("\nAll sellers have submitted. Processing transactions...")

    # 4. Process all transactions and build the summary
    transaction_summary = []

    for seller_name, encrypted_txs in all_seller_data:
        seller_record = {
            "Seller Name": seller_name,
            "Individual Transactions": [],
            "Total Encrypted Amount": None,
            "Total Decrypted Amount": None
        }

        # Use Paillier's homomorphic addition
        # Start with an encrypted zero
        total_encrypted = paillier_pubkey.encrypt(0)

        for enc_tx in encrypted_txs:
            # Decrypt individual transaction for the summary
            decrypted_amount = paillier_privkey.decrypt(enc_tx)

            seller_record["Individual Transactions"].append({
                "Encrypted Amount": enc_tx,  # This will be a large object
                "Decrypted Amount": decrypted_amount
            })

            # Homomorphically add to the total
            total_encrypted += enc_tx

        # Decrypt the final total
        total_decrypted = paillier_privkey.decrypt(total_encrypted)

        seller_record["Total Encrypted Amount"] = total_encrypted
        seller_record["Total Decrypted Amount"] = total_decrypted

        transaction_summary.append(seller_record)

    # 5. Digital Signature (Sign and Verify)

    # To sign, we must hash the *entire* summary.
    # We serialize it to bytes first.
    summary_bytes = pickle.dumps(transaction_summary)

    # Apply SHA-256 Hashing
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(summary_bytes)
    digest = hasher.finalize()

    print(f"\nGenerated SHA-256 Hash of summary: {digest.hex()}")

    # Sign the hash with the Gateway's RSA private key
    signature = rsa_privkey.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Gateway has signed the transaction summary.")

    # Verify the signature with the Gateway's RSA public key
    verification_result = "Failed"
    try:
        rsa_pubkey.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        verification_result = "Success"
        print("Signature verification successful.")
    except InvalidSignature:
        print("Signature verification failed!")

    # 6. Output Requirements: Display the complete summary
    print("\n" + "=" * 60)
    print("           COMPLETE TRANSACTION SUMMARY")
    print("=" * 60)

    for record in transaction_summary:
        print(f"\n--- Seller: {record['Seller Name']} ---")
        print("Individual Transactions:")
        for i, tx in enumerate(record['Individual Transactions']):
            # Print truncated encrypted data for readability
            enc_str = str(tx['Encrypted Amount'].ciphertext())[:30] + "..."
            print(f"  Tx {i + 1}:")
            print(f"    - Plaintext Amount (from decryption): {tx['Decrypted Amount']}")
            print(f"    - Encrypted Amount (truncated):       {enc_str}")

        print("\nTotals:")
        enc_total_str = str(record['Total Encrypted Amount'].ciphertext())[:30] + "..."
        print(f"  Total Encrypted (Homomorphic Sum): {enc_total_str}")
        print(f"  Total Decrypted (from Total):      {record['Total Decrypted Amount']}")

    print("\n" + "-" * 60)
    print("              SIGNATURE STATUS")
    print(f"  Digital Signature Status:       Signed by Payment Gateway")
    print(f"  Signature Verification Result:  {verification_result}")
    print("=" * 60)


if __name__ == "__main__":
    run_gateway()