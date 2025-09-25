# Encrypt the message "Top Secret Data" using AES-192 with the key
# "FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the
# encryption process (key expansion, initial round, main rounds, final round).

# aes_crypto.py

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# The AES block size is always 16 bytes (128 bits)
AES_BLOCK_SIZE = 16


def encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Encrypts a string using AES-CBC with a given key.

    Args:
        plaintext: The string data to encrypt.
        key: The encryption key (must be 16, 24, or 32 bytes for AES-128,
             AES-192, or AES-256).

    Returns:
        The initialization vector (IV) concatenated with the ciphertext, as bytes.
    """
    # First, validate the key size
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid key size. Key must be 16, 24, or 32 bytes long.")

    # Convert the plaintext string to bytes using UTF-8 encoding
    plaintext_bytes = plaintext.encode('utf-8')

    # Generate a random, non-secret Initialization Vector (IV)
    iv = get_random_bytes(AES_BLOCK_SIZE)

    # Create an AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the plaintext to be a multiple of the block size and then encrypt it
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES_BLOCK_SIZE))

    # Return the IV and ciphertext together. The IV is needed for decryption.
    return iv + ciphertext


def decrypt(iv_and_ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts an AES-CBC encrypted bytestring.

    Args:
        iv_and_ciphertext: The bytestring containing the IV and ciphertext.
        key: The decryption key (must be the same one used for encryption).

    Returns:
        The original decrypted string.
    """
    # Also validate the key size during decryption
    if len(key) not in [16, 24, 32]:
        raise ValueError("Invalid key size. Key must be 16, 24, or 32 bytes long.")

    # Split the IV and the ciphertext
    iv = iv_and_ciphertext[:AES_BLOCK_SIZE]
    ciphertext = iv_and_ciphertext[AES_BLOCK_SIZE:]

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext and then unpad it to get the original bytes
    decrypted_padded_bytes = cipher.decrypt(ciphertext)
    decrypted_bytes = unpad(decrypted_padded_bytes, AES_BLOCK_SIZE)

    # Decode the bytes back to a string and return it
    return decrypted_bytes.decode('utf-8')


# This block demonstrates how to use the functions
if __name__ == '__main__':
    # 🔐 --- Example Usage --- 🔐

    # 1. Define your message and a secret key.
    # The key MUST be 16, 24, or 32 bytes long.
    # NEVER hardcode keys in a real application! Load them from a secure
    # location like an environment variable or a secret manager.

    # Let's create a 24-byte (192-bit) key from a password using a hash function.
    # This is a good practice to ensure the key is the correct length.
    password = "MySuperSecurePassword!123"
    # Use SHA-256 and truncate its output to 24 bytes for an AES-192 key
    key_192 = hashlib.sha256(password.encode()).digest()[:24]

    original_message = "Top Secret Data"

    print(f"Original Message: '{original_message}'")
    print(f"Key (192-bit hex): {key_192.hex()}")
    print("-" * 30)

    # 2. Encrypt the message
    try:
        encrypted_data = encrypt(original_message, key_192)
        print(f"Encrypted (IV+Ciphertext) hex: {encrypted_data.hex()}")

        # 3. Decrypt the message
        decrypted_message = decrypt(encrypted_data, key_192)
        print(f"Decrypted Message: '{decrypted_message}'")
        print("-" * 30)

        # 4. Verification
        assert original_message == decrypted_message
        print("✅ Success: The original and decrypted messages match!")

    except ValueError as e:
        print(f"Error: {e}")