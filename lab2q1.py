# Encrypt the message "Confidential Data" using DES with the following key:
# "A1B2C3D4". Then decrypt the ciphertext to verify the original message

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt_des(key, plaintext):
    """
    Encrypts plaintext using DES in ECB mode with padding.

    Args:
        key (bytes): The 8-byte encryption key.
        plaintext (bytes): The data to encrypt.

    Returns:
        bytes: The encrypted ciphertext.
    """
    # Create a new DES cipher object
    cipher = DES.new(key, DES.MODE_ECB)

    # Pad the plaintext and encrypt it
    padded_text = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_text)

    return ciphertext


def decrypt_des(key, ciphertext):
    """
    Decrypts ciphertext using DES in ECB mode with unpadding.

    Args:
        key (bytes): The 8-byte decryption key.
        ciphertext (bytes): The data to decrypt.

    Returns:
        bytes: The original plaintext.
    """
    # Create a new DES cipher object
    decipher = DES.new(key, DES.MODE_ECB)

    # Decrypt the data and unpad it
    decrypted_padded_text = decipher.decrypt(ciphertext)
    original_text = unpad(decrypted_padded_text, DES.block_size)

    return original_text


# --- Main Program Execution ---
if __name__ == "__main__":
    # Define your key and plaintext
    my_key = b'A1B2C3D4'
    my_plaintext = b'This is a secret message.'

    print(f"Original Message: {my_plaintext.decode()}")
    print("-" * 25)

    # 1. Encrypt the message using our function
    encrypted_data = encrypt_des(my_key, my_plaintext)
    print(f"Encrypted (Hex): {encrypted_data.hex()}")

    # 2. Decrypt the message using our function
    decrypted_data = decrypt_des(my_key, encrypted_data)
    print(f"Decrypted Message: {decrypted_data.decode()}")
    print("-" * 25)

    # 3. Verify the result
    if my_plaintext == decrypted_data:
        print("✅ Success! The decrypted message matches the original.")
    else:
        print("❌ Failure! The messages do not match.")