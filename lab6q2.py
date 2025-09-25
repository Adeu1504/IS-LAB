# Try using the Diffie-Hellman asymmetric encryption standard and verify the above
# steps.

# File: lab_diffie_hellman.py
# This script demonstrates Diffie-Hellman Key Exchange.
# You will need the cryptography library:
# pip install cryptography

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh


def demonstrate_diffie_hellman():
    """
    Demonstrates the Diffie-Hellman key exchange protocol between two parties.
    """
    print("--- Demonstrating Diffie-Hellman Key Exchange ---")

    # 1. Agree on public parameters (prime p and generator g)
    # In a real application, these would be pre-agreed upon.
    # The cryptography library can generate them for us.
    print("[SYSTEM] Generating common public parameters (p and g)...")
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # --- ALICE'S SIDE ---
    print("\n--- Alice's Side ---")
    # 2. Alice generates her own private key
    alice_private_key = parameters.generate_private_key()
    print("Alice has generated her private key.")

    # 3. Alice computes her public key to send to Bob
    alice_public_key = alice_private_key.public_key()
    print("Alice computes her public key to be shared.")

    # --- BOB'S SIDE ---
    print("\n--- Bob's Side ---")
    # 2. Bob generates his own private key
    bob_private_key = parameters.generate_private_key()
    print("Bob has generated his private key.")

    # 3. Bob computes his public key to send to Alice
    bob_public_key = bob_private_key.public_key()
    print("Bob computes his public key to be shared.")

    # --- KEY EXCHANGE ---
    print("\n--- Secure Exchange Simulation ---")
    print("Alice sends her public key to Bob.")
    print("Bob sends his public key to Alice.")

    # 5. Alice computes the shared secret
    # She uses her private key and Bob's public key
    alice_shared_key = alice_private_key.exchange(bob_public_key)
    print("\nAlice has computed the shared secret.")

    # 5. Bob computes the shared secret
    # He uses his private key and Alice's public key
    bob_shared_key = bob_private_key.exchange(alice_public_key)
    print("Bob has computed the shared secret.")

    # --- VERIFICATION ---
    print("\n--- Verification of Shared Secret ---")
    print(f"Alice's computed key (hex): {alice_shared_key.hex()}")
    print(f"Bob's computed key (hex):   {bob_shared_key.hex()}")

    if alice_shared_key == bob_shared_key:
        print("\nSUCCESS: Both Alice and Bob have computed the exact same secret key.")
        print("This key can now be used for symmetric encryption (e.g., with AES).")
    else:
        print("\nFAILURE: The keys do not match. The exchange failed.")

    # In a real system, you would derive a fixed-size key from this shared secret
    # using a Key Derivation Function (KDF).
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(alice_shared_key)

    print(f"\nDerived 32-byte key for symmetric encryption (hex): {derived_key.hex()}")
    print("-" * 50)


if __name__ == "__main__":
    demonstrate_diffie_hellman()