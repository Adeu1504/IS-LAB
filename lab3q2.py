# Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure
# Transactions" with the public key. Then decrypt the ciphertext with the private key
# to verify the original message.

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key
)
from cryptography.fernet import Fernet


# --- Core Cryptographic Functions ---

def generate_ecc_keys():
    """
    Generates a new ECC private and public key pair.

    Returns:
        tuple: (private_key_object, public_key_object)
    """
    # Using SECP384R1, a standard and widely supported curve
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_ecc(recipient_public_key, message: bytes) -> tuple:
    """
    Encrypts a message using the ECIES scheme.

    Args:
        recipient_public_key: The public key object of the recipient.
        message (bytes): The message to encrypt.

    Returns:
        tuple: A tuple containing the ephemeral public key bytes and the ciphertext.
    """
    # 1. Generate an ephemeral key pair for this encryption session
    ephemeral_private_key = ec.generate_private_key(recipient_public_key.curve)
    ephemeral_public_key = ephemeral_private_key.public_key()

    # 2. Perform ECDH to get a shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # 3. Derive a symmetric key from the shared secret using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet keys are 32 bytes
        salt=None,
        info=b'ecc-ecies-encryption',
    )
    symmetric_key = hkdf.derive(shared_secret)

    # 4. Encrypt the message using the derived symmetric key (Fernet)
    f = Fernet(base64.urlsafe_b64encode(symmetric_key))
    ciphertext = f.encrypt(message)

    # 5. Serialize the ephemeral public key to send it with the ciphertext
    ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    return (ephemeral_public_key_bytes, ciphertext)


def decrypt_ecc(recipient_private_key, ciphertext_package: tuple) -> bytes:
    """
    Decrypts a message using the ECIES scheme.

    Args:
        recipient_private_key: The private key object of the recipient.
        ciphertext_package (tuple): The tuple received from the encrypt function.

    Returns:
        bytes: The original decrypted message.
    """
    ephemeral_public_key_bytes, ciphertext = ciphertext_package

    # 1. Load the ephemeral public key from bytes
    ephemeral_public_key = load_pem_public_key(ephemeral_public_key_bytes)

    # 2. Perform ECDH to recreate the same shared secret
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # 3. Derive the same symmetric key using the same HKDF parameters
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-ecies-encryption',
    )
    symmetric_key = hkdf.derive(shared_secret)

    # 4. Decrypt the ciphertext using the derived symmetric key
    f = Fernet(base64.urlsafe_b64encode(symmetric_key))
    decrypted_message = f.decrypt(ciphertext)

    return decrypted_message


# --- Main Demonstration ---
if __name__ == "__main__":
    print("--- ECC Encryption & Decryption using the 'cryptography' library ---")

    # 1. Generate keys for the receiver (Alice)
    alice_private_key, alice_public_key = generate_ecc_keys()
    print("\nStep 1: Generated keys for Alice (the receiver).")
    # Note: In a real app, Alice would share her public key with Bob.

    # 2. The message to be sent by Bob
    original_message = b"Secure Transactions"
    print(f"Step 2: Bob wants to send a secret message: '{original_message.decode()}'")

    # 3. Bob encrypts the message using Alice's public key
    ciphertext_package = encrypt_ecc(alice_public_key, original_message)
    print("\nStep 3: Bob encrypts the message using Alice's public key.")

    # For display purposes, let's look at the ciphertext components
    eph_pub_key_pem, ct = ciphertext_package
    print(f"  - An ephemeral public key was generated for this session.")
    print(f"  - The final ciphertext (authenticated) is: {base64.b64encode(ct).decode()[:40]}...")

    # 4. Alice decrypts the ciphertext package using her private key
    decrypted_message = decrypt_ecc(alice_private_key, ciphertext_package)
    print("\nStep 4: Alice decrypts the package using her own private key.")

    # 5. Verification
    print("\n--- Verification ---")
    print(f"Original message:   '{original_message.decode()}'")
    print(f"Decrypted message:  '{decrypted_message.decode()}'")

    assert original_message == decrypted_message
    print("\nSuccess! The message was decrypted correctly.")