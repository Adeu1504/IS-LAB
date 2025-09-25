# As part of a project to enhance the security of communication in a peer-to-peer file
# sharing system, you are tasked with implementing a secure key exchange
# mechanism using the Diffie-Hellman algorithm. Each peer must establish a shared
# secret key with another peer over an insecure channel. Implement the Diffie-
# Hellman key exchange protocol, enabling peers to generate their public and private
# keys and securely compute the shared secret key. Measure the time taken for key
# generation and key exchange processes.

import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --- Core Functions ---

def generate_dh_keys(parameters):
    """
    Generates a private and public key pair using shared DH parameters.

    Args:
        parameters: A DH parameters object from the cryptography library.

    Returns:
        tuple: (private_key_object, public_key_object)
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def compute_dh_shared_secret(own_private_key, other_peer_public_key):
    """
    Computes the shared secret using one's own private key and the
    other peer's public key.

    Args:
        own_private_key: Your own DH private key object.
        other_peer_public_key: The other peer's public key object.

    Returns:
        bytes: The computed shared secret.
    """
    shared_secret = own_private_key.exchange(other_peer_public_key)
    return shared_secret


# --- Main Simulation ---
if __name__ == "__main__":
    print("--- Diffie-Hellman Key Exchange Simulation (Functional Style) ---")

    # Step 1: Network-wide Parameter Generation
    # In a real P2P system, peers agree on a standard set of parameters.
    # This is a one-time setup.
    print("\n[SETUP] Generating shared DH parameters (p and g) for the network...")
    # Using 2048 bits for strong security.
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    print("Parameters generated successfully.")

    # Step 2: Alice generates her key pair
    print("\n[ALICE] Generating key pair...")
    start_time = time.perf_counter()
    alice_private_key, alice_public_key = generate_dh_keys(parameters)
    alice_key_gen_time = time.perf_counter() - start_time
    print("  - Alice's keys generated.")

    # Step 3: Bob generates his key pair
    print("\n[BOB] Generating key pair...")
    start_time = time.perf_counter()
    bob_private_key, bob_public_key = generate_dh_keys(parameters)
    bob_key_gen_time = time.perf_counter() - start_time
    print("  - Bob's keys generated.")

    # Step 4: Simulate the public key exchange over an insecure channel
    print("\n[EXCHANGE] Simulating the exchange of public keys...")
    print("  - Alice sends her public key to Bob.")
    print("  - Bob sends his public key to Alice.")

    # Step 5: Each peer computes the shared secret
    print("\n[SECRET COMPUTATION] Each peer computes the shared secret...")

    # Alice computes the secret using her private key and Bob's public key
    start_time = time.perf_counter()
    alice_shared_secret = compute_dh_shared_secret(alice_private_key, bob_public_key)
    alice_secret_comp_time = time.perf_counter() - start_time
    print("  - Alice has computed her version of the secret.")

    # Bob computes the secret using his private key and Alice's public key
    start_time = time.perf_counter()
    bob_shared_secret = compute_dh_shared_secret(bob_private_key, alice_public_key)
    bob_secret_comp_time = time.perf_counter() - start_time
    print("  - Bob has computed his version of the secret.")

    # Step 6: Verification
    print("\n[VERIFICATION] Verifying that the secrets match...")
    if alice_shared_secret == bob_shared_secret:
        print("  ✅ SUCCESS: The shared secrets match perfectly.")
        # print(f"Shared Secret (first 16 bytes): {alice_shared_secret[:16].hex()}...")
    else:
        print("  ❌ FAILURE: The shared secrets DO NOT match.")

    # Step 7: Performance Measurement Reporting
    print("\n--- PERFORMANCE METRICS ---")
    results = {
        "Alice": {
            "Key Generation Time (ms)": alice_key_gen_time * 1000,
            "Secret Computation Time (ms)": alice_secret_comp_time * 1000,
        },
        "Bob": {
            "Key Generation Time (ms)": bob_key_gen_time * 1000,
            "Secret Computation Time (ms)": bob_secret_comp_time * 1000,
        }
    }

    for peer, metrics in results.items():
        print(f"Peer: {peer}")
        for metric, value in metrics.items():
            print(f"  - {metric}: {value:.4f}")