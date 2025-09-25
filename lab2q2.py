# Encrypt the message "Sensitive Information" using AES-128 with the following
# key: "0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to
# verify the original message.

# Import necessary modules from the pycryptodome library
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_aes(message: str, key: str) -> bytes:
    """
    Encrypts a message using AES-128 in ECB mode.

    Args:
        message (str): The plaintext message to encrypt.
        key (str): The 16-byte (128-bit) key.

    Returns:
        bytes: The encrypted ciphertext.
    """
    # Convert the key and message to bytes, which is required for cryptographic operations
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')

    # Create a new AES cipher object. We use ECB mode for this example.
    # AES.MODE_ECB is the simplest mode but not recommended for general use.
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # AES works on fixed-size blocks (16 bytes). We pad the message so its
    # length is a multiple of the block size.
    padded_message = pad(message_bytes, AES.block_size)

    # Encrypt the padded message
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def decrypt_aes(ciphertext: bytes, key: str) -> str:
    """
    Decrypts a ciphertext using AES-128 in ECB mode.

    Args:
        ciphertext (bytes): The encrypted data.
        key (str): The 16-byte (128-bit) key used for encryption.

    Returns:
        str: The original decrypted message.
    """
    # Convert the key to bytes
    key_bytes = key.encode('utf-8')

    # Create a new AES cipher object with the same key and mode
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # Decrypt the ciphertext
    decrypted_padded_message = cipher.decrypt(ciphertext)

    # Unpad the decrypted message to remove the padding and get the original plaintext
    original_message_bytes = unpad(decrypted_padded_message, AES.block_size)

    # Decode the bytes back to a string and return it
    return original_message_bytes.decode('utf-8')

# --- Main execution block to demonstrate the functions ---
if __name__ == "__main__":
    # Note: AES-128 requires a 16-byte (128-bit) key.
    # The provided key "0123456789ABCDEF0123456789ABCDEF" is 32 bytes long.
    # Therefore, we will use the first 16 bytes: "0123456789ABCDEF".
    key = "0123456789ABCDEF"
    message = "Sensitive Information"

    print(f"Original Message: '{message}'")
    print(f"Key (16-byte for AES-128): '{key}'\n")

    # 1. Encrypt the message
    encrypted_message = encrypt_aes(message, key)

    # For display purposes, we encode the raw ciphertext bytes into Base64,
    # which is a common way to represent binary data as text.
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
    print(f"Encrypted (Ciphertext) in Base64: {encrypted_message_b64}\n")

    # 2. Decrypt the ciphertext
    decrypted_message = decrypt_aes(encrypted_message, key)
    print(f"Decrypted (Plaintext): '{decrypted_message}'\n")

    # 3. Verify the result
    print("--- Verification ---")
    if message == decrypted_message:
        print("✅ Success: The decrypted message matches the original message.")
    else:
        print("❌ Failure: The decrypted message does not match the original.")