# 2. Encrypt the message "the house is being sold tonight" using each of the following
# ciphers. Ignore the space between words. Decrypt the message to get the original
# plaintext:
# a) Vigenere cipher with key: "dollars"
# b) Autokey cipher with key = 7

import re


# --- Vigenere Cipher Functions ---

def generate_vigenere_key(plaintext, key):
    """Generates a Vigenere key stream by repeating the key."""
    key = list(key)
    if len(plaintext) == len(key):
        return key
    else:
        # Repeat the key characters to match the length of the plaintext
        return [key[i % len(key)] for i in range(len(plaintext))]


def vigenere_encrypt(plaintext, key):
    """Encrypts text using the Vigenere cipher."""
    key_stream = generate_vigenere_key(plaintext, key)
    ciphertext = ""
    for i in range(len(plaintext)):
        p_char_val = ord(plaintext[i]) - ord('a')
        k_char_val = ord(key_stream[i]) - ord('a')
        c_char_val = (p_char_val + k_char_val) % 26
        ciphertext += chr(c_char_val + ord('a'))
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    """Decrypts text from a Vigenere cipher."""
    key_stream = generate_vigenere_key(ciphertext, key)
    decrypted_text = ""
    for i in range(len(ciphertext)):
        c_char_val = ord(ciphertext[i]) - ord('a')
        k_char_val = ord(key_stream[i]) - ord('a')
        p_char_val = (c_char_val - k_char_val + 26) % 26
        decrypted_text += chr(p_char_val + ord('a'))
    return decrypted_text


# --- Autokey Cipher Functions ---

def autokey_encrypt(plaintext, key):
    """Encrypts text using the Autokey cipher."""
    ciphertext = ""
    # Encrypt the first character using the initial key
    p1_val = ord(plaintext[0]) - ord('a')
    c1_val = (p1_val + key) % 26
    ciphertext += chr(c1_val + ord('a'))

    # Encrypt the rest of the message using the plaintext as the key
    for i in range(1, len(plaintext)):
        p_char_val = ord(plaintext[i]) - ord('a')
        k_char_val = ord(plaintext[i - 1]) - ord('a')  # Key is the previous plaintext char
        c_char_val = (p_char_val + k_char_val) % 26
        ciphertext += chr(c_char_val + ord('a'))
    return ciphertext


def autokey_decrypt(ciphertext, key):
    """Decrypts text from an Autokey cipher."""
    decrypted_text = ""
    # Decrypt the first character using the initial key
    c1_val = ord(ciphertext[0]) - ord('a')
    p1_val = (c1_val - key + 26) % 26
    decrypted_text += chr(p1_val + ord('a'))

    # Decrypt the rest of the message using the *decrypted* plaintext as the key
    for i in range(1, len(ciphertext)):
        c_char_val = ord(ciphertext[i]) - ord('a')
        # Key is the previously decrypted character
        k_char_val = ord(decrypted_text[i - 1]) - ord('a')
        p_char_val = (c_char_val - k_char_val + 26) % 26
        decrypted_text += chr(p_char_val + ord('a'))
    return decrypted_text


# --- Main Execution ---

if __name__ == "__main__":
    # Original message
    message = "the house is being sold tonight"

    # Pre-process the message: remove spaces and convert to lowercase
    plaintext = re.sub(r'[^a-z]', '', message.lower())

    print(f"Original Message: '{message}'")
    print(f"Processed Plaintext: '{plaintext}'")
    print("-" * 40)

    # a) Vigenere Cipher
    vigenere_key = "dollars"
    print("a) Vigenere Cipher")
    print(f"   Key: '{vigenere_key}'")

    # Encrypt
    vigenere_ciphertext = vigenere_encrypt(plaintext, vigenere_key)
    print(f"   Ciphertext: {vigenere_ciphertext}")

    # Decrypt
    vigenere_decrypted = vigenere_decrypt(vigenere_ciphertext, vigenere_key)
    print(f"   Decrypted:  {vigenere_decrypted}")
    print("-" * 40)

    # b) Autokey Cipher
    autokey_key = 7
    print("b) Autokey Cipher")
    print(f"   Key: {autokey_key}")

    # Encrypt
    autokey_ciphertext = autokey_encrypt(plaintext, autokey_key)
    print(f"   Ciphertext: {autokey_ciphertext}")

    # Decrypt
    autokey_decrypted = autokey_decrypt(autokey_ciphertext, autokey_key)
    print(f"   Decrypted:  {autokey_decrypted}")
    print("-" * 40)