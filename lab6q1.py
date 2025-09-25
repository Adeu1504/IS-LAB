# Try using the Elgammal, Schnor asymmetric encryption standard and verify the above
# steps.

# File: lab6_exercise1.py
# You may need to install the cryptography library:
# pip install cryptography

from cryptography.hazmat.primitives.asymmetric import dsa, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def demonstrate_dsa_signature():
    """
    Demonstrates the Digital Signature Algorithm (DSA), which is based on ElGamal.
    """
    print("--- Demonstrating DSA (ElGamal-based) Signature ---")

    # 1. Generate DSA private and public keys
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()

    # 2. Define the message to be signed
    message = b"This is a test message for the DSA signature scheme."
    print(f"Original Message: {message.decode()}")

    # 3. Sign the message with the private key
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )
    print(f"Generated DSA Signature (hex): {signature.hex()}")

    # 4. Verify the signature with the public key
    try:
        public_key.verify(signature, message, hashes.SHA256())
        print("DSA Signature Verification: SUCCESS! The signature is valid.")
    except InvalidSignature:
        print("DSA Signature Verification: FAILED! The signature is invalid.")
    except Exception as e:
        print(f"An error occurred during DSA verification: {e}")
    print("-" * 50)


def demonstrate_ed25519_signature():
    """
    Demonstrates the Ed25519 Signature scheme as a modern alternative to Schnorr.
    This uses the cryptography library and requires no extra installations.
    """
    print("\n--- Demonstrating Ed25519 Signature (Alternative to Schnorr) ---")

    # 1. Generate Ed25519 private and public keys
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 2. Define the message to be signed
    message = b"This is a test message for the Ed25519 signature scheme."
    print(f"Original Message: {message.decode()}")

    # 3. Sign the message with the private key
    signature = private_key.sign(message)
    print(f"Generated Ed25519 Signature (hex): {signature.hex()}")

    # 4. Verify the signature with the public key
    try:
        public_key.verify(signature, message)
        print("Ed25519 Signature Verification: SUCCESS! The signature is valid.")
    except InvalidSignature:
        print("Ed25519 Signature Verification: FAILED! The signature is invalid.")
    except Exception as e:
        print(f"An error occurred during Ed25519 verification: {e}")
    print("-" * 50)


if __name__ == "__main__":
    demonstrate_dsa_signature()
    demonstrate_ed25519_signature()