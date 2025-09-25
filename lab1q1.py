# 1. Encrypt the message "I am learning information security" using each of the following
# ciphers. Ignore the space between words. Decrypt the message to get the original
# plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)

import math


def prepare_plaintext(text):
    """Removes spaces and converts to lowercase."""
    return "".join(filter(str.isalpha, text)).lower()


def additive_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using the additive cipher.
    mode can be 'encrypt' or 'decrypt'.
    """
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            p = ord(char) - ord('a')
            if mode == 'encrypt':
                c = (p + key) % 26
            elif mode == 'decrypt':
                c = (p - key + 26) % 26  # Add 26 to handle negative results
            else:
                return "Invalid mode"
            result += chr(c + ord('a'))
        else:
            result += char
    return result


def mod_inverse(a, m):
    """
    Finds the modular multiplicative inverse of a under modulo m.
    Returns -1 if the inverse does not exist.
    """
    if math.gcd(a, m) != 1:
        return -1  # Inverse does not exist
    # Using Python 3.8+'s built-in modular inverse function
    # For older versions, an Extended Euclidean Algorithm implementation would be needed.
    return pow(a, -1, m)


def multiplicative_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using the multiplicative cipher.
    mode can be 'encrypt' or 'decrypt'.
    """
    inverse_key = mod_inverse(key, 26)
    if inverse_key == -1:
        return f"Error: Key {key} is not coprime with 26. Inverse cannot be found."

    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            p = ord(char) - ord('a')
            if mode == 'encrypt':
                c = (p * key) % 26
            elif mode == 'decrypt':
                c = (p * inverse_key) % 26
            else:
                return "Invalid mode"
            result += chr(c + ord('a'))
        else:
            result += char
    return result


def affine_cipher(text, key_pair, mode='encrypt'):
    """
    Encrypts or decrypts text using the affine cipher.
    key_pair is a tuple (a, b) where a is multiplicative, b is additive.
    mode can be 'encrypt' or 'decrypt'.
    """
    a, b = key_pair
    inverse_a = mod_inverse(a, 26)
    if inverse_a == -1:
        return f"Error: Key 'a'={a} is not coprime with 26. Inverse cannot be found."

    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            p = ord(char) - ord('a')
            if mode == 'encrypt':
                c = (a * p + b) % 26
            elif mode == 'decrypt':
                c = (inverse_a * (p - b + 26)) % 26  # Add 26 to handle negative results
            else:
                return "Invalid mode"
            result += chr(c + ord('a'))
        else:
            result += char
    return result


if __name__ == '__main__':
    original_message = "I am learning information security"
    plaintext = prepare_plaintext(original_message)

    print(f"Original Message: '{original_message}'")
    print(f"Prepared Plaintext: '{plaintext}'")
    print("-" * 40)

    # 1. Additive Cipher
    add_key = 20
    print(f"a) Additive Cipher (key = {add_key})")
    encrypted_add = additive_cipher(plaintext, add_key, 'encrypt')
    print(f"   Encrypted: {encrypted_add}")
    decrypted_add = additive_cipher(encrypted_add, add_key, 'decrypt')
    print(f"   Decrypted: {decrypted_add}\n")

    # 2. Multiplicative Cipher
    mul_key = 15
    print(f"b) Multiplicative Cipher (key = {mul_key})")
    encrypted_mul = multiplicative_cipher(plaintext, mul_key, 'encrypt')
    print(f"   Encrypted: {encrypted_mul}")
    decrypted_mul = multiplicative_cipher(encrypted_mul, mul_key, 'decrypt')
    print(f"   Decrypted: {decrypted_mul}\n")

    # 3. Affine Cipher
    aff_key = (15, 20)
    print(f"c) Affine Cipher (key = {aff_key})")
    encrypted_aff = affine_cipher(plaintext, aff_key, 'encrypt')
    print(f"   Encrypted: {encrypted_aff}")
    decrypted_aff = affine_cipher(encrypted_aff, aff_key, 'decrypt')
    print(f"   Decrypted: {decrypted_aff}\n")