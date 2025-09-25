# Given an ElGamal encryption scheme with a public key (p, g, h) and a private key
# x, encrypt the message "Confidential Data". Then decrypt the ciphertext to retrieve
# the original message.

import secrets
from cryptography.hazmat.primitives.asymmetric import dh


# --- ElGamal Core Functions (using library primitives) ---

def generate_keys(bits=2048):
    """
    Generates public and private keys for the ElGamal scheme using
    the cryptography library's DH primitives.

    Args:
        bits (int): The number of bits for the prime p (e.g., 2048).

    Returns:
        tuple: A tuple containing the public key (p, g, h) and the private key x.
    """
    # 1. Generate secure DH parameters (p and g)
    # The generator g=2 is a common choice.
    params = dh.generate_parameters(generator=2, key_size=bits)
    p = params.parameter_numbers().p
    g = params.parameter_numbers().g

    # 2. Generate the private key (x) and derive the public key (h)
    private_key_obj = params.generate_private_key()
    public_key_obj = private_key_obj.public_key()

    # 3. Extract the integer values for our use
    x = private_key_obj.private_numbers().x
    h = public_key_obj.public_numbers().y  # In DH terms, h is often called y

    public_key = (p, g, h)
    private_key = x

    return public_key, private_key


def encrypt(public_key, message):
    """
    Encrypts a message using the ElGamal public key.

    Args:
        public_key (tuple): The public key (p, g, h).
        message (str): The message to encrypt.

    Returns:
        list: A list of ciphertext pairs (c1, c2) for each character.
    """
    p, g, h = public_key

    # Convert string message to a list of integers (UTF-8 byte values)
    # This is more robust than assuming ASCII.
    m_bytes = message.encode('utf-8')

    ciphertext = []
    for m_byte in m_bytes:
        if m_byte >= p:
            # This is highly unlikely with large primes but good practice to check
            raise ValueError("Message byte value exceeds prime p. This should not happen.")

        # Choose a cryptographically secure random ephemeral key y for each byte
        # secrets.randbelow is preferred over random.randint for crypto
        y = secrets.randbelow(p - 2) + 1  # y must be in [1, p-2]

        c1 = pow(g, y, p)
        c2 = (m_byte * pow(h, y, p)) % p
        ciphertext.append((c1, c2))

    return ciphertext


def decrypt(private_key, public_key, ciphertext):
    """
    Decrypts a ciphertext using the ElGamal private key.

    Args:
        private_key (int): The private key x.
        public_key (tuple): The public key (p, g, h), needed for p.
        ciphertext (list): The list of ciphertext pairs (c1, c2).

    Returns:
        str: The decrypted message.
    """
    p, _, _ = public_key  # We only need p from the public key tuple
    x = private_key

    decrypted_bytes = []
    for c1, c2 in ciphertext:
        # Calculate shared secret s
        s = pow(c1, x, p)
        # Calculate modular inverse using Python's built-in pow(s, -1, p)
        s_inv = pow(s, -1, p)

        # Recover the message byte
        m_byte = (c2 * s_inv) % p
        decrypted_bytes.append(m_byte)

    return bytes(decrypted_bytes).decode('utf-8')


# --- Main Demonstration ---
if __name__ == "__main__":
    print("--- ElGamal Encryption using the 'cryptography' library for key generation ---")

    # 1. Generate keys for the receiver (Alice)
    # Using 2048 bits for strong security, as recommended by standards.
    print("\nStep 1: Generating 2048-bit public and private keys (this may take a moment)...")
    public_key, private_key = generate_keys(bits=2048)
    p_demo, g_demo, h_demo = public_key

    # Print truncated keys for readability
    print("  - Keys generated successfully.")
    print(f"  - Prime (p): {str(p_demo)[:50]}...")
    print(f"  - Generator (g): {g_demo}")
    print(f"  - Public Key (h): {str(h_demo)[:50]}...")
    print(f"  - Private Key (x): {str(private_key)[:50]}...")

    # 2. The message to be sent by the sender (Bob)
    original_message = "Confidential Data"
    print(f"\nStep 2: Original message to encrypt: '{original_message}'")

    # 3. Bob encrypts the message using Alice's public key
    print("\nStep 3: Encrypting the message...")
    ciphertext = encrypt(public_key, original_message)
    print("  - Encryption complete.")
    print(f"  - Ciphertext (first pair): {ciphertext[0]}")
    print(f"  - Total pairs generated: {len(ciphertext)}")

    # 4. Alice decrypts the ciphertext using her private key
    print("\nStep 4: Decrypting the message...")
    decrypted_message = decrypt(private_key, public_key, ciphertext)
    print("  - Decryption complete.")

    # 5. Verification
    print("\n--- Verification ---")
    print(f"Original message:   '{original_message}'")
    print(f"Decrypted message:  '{decrypted_message}'")

    assert original_message == decrypted_message
    print("\nSuccess! The original message was recovered correctly.")