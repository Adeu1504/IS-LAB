# Encrypt the message "Classified Text" using Triple DES with the key
# "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF". Then
# decrypt the ciphertext to verify the original message.

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

def encrypt_3des(plaintext_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Encrypts a byte string using Triple DES (EDE, ECB mode).

    Args:
        plaintext_bytes: The data to encrypt, as a byte string.
        key_bytes: The encryption key, must be 16 or 24 bytes long.

    Returns:
        The encrypted data as a byte string (ciphertext).
    """
    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    padded_plaintext = pad(plaintext_bytes, DES3.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_3des(ciphertext_bytes: bytes, key_bytes: bytes) -> bytes:
    """
    Decrypts a Triple DES ciphertext (EDE, ECB mode).

    Args:
        ciphertext_bytes: The data to decrypt, as a byte string.
        key_bytes: The encryption key, must be 16 or 24 bytes long.

    Returns:
        The original decrypted data as a byte string.
    """
    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(ciphertext_bytes)
    original_plaintext = unpad(decrypted_padded_text, DES3.block_size)
    return original_plaintext

# --- Main execution block to demonstrate the functions ---
if __name__ == "__main__":
    # 1. Define a VALID Key and Plaintext
    # This key is 24 bytes (48 hex chars) and its three 8-byte parts are unique.
    key_hex = "1122334455667788AABBCCDDEEFF00118877665544332211"
    key = bytes.fromhex(key_hex)

    # The message to be encrypted
    plaintext_str = "Classified Text"
    plaintext = plaintext_str.encode('utf-8')

    print(f"Original Message: {plaintext_str}")
    print(f"Key (Hex): {key_hex}")
    print("-" * 30)

    # 2. Encrypt the message
    print("Encrypting...")
    ciphertext = encrypt_3des(plaintext, key)
    print(f"Ciphertext (Hex): {binascii.hexlify(ciphertext).decode()}")
    print("-" * 30)

    # 3. Decrypt the message
    print("Decrypting...")
    decrypted_text = decrypt_3des(ciphertext, key)
    print(f"Decrypted Message: {decrypted_text.decode('utf-8')}")
    print("-" * 30)

    # 4. Verify the result
    if plaintext == decrypted_text:
        print("Verification successful: The decrypted message matches the original.")
    else:
        print("Verification failed: The messages do not match.")