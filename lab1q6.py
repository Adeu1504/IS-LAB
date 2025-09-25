# 6. Use a brute-force attack to decipher the following message. Assume that you know it is
# an affine cipher and that the plaintext "ab" is enciphered to "GL":
# XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS

import math


def mod_inverse(a, m):
    """
    Calculates the modular multiplicative inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    """
    # This is a brute-force way to find the inverse, suitable for small m like 26.
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def find_affine_key_brute_force(known_plaintext, known_ciphertext):
    """
    Finds the affine cipher key (a, b) by brute-forcing all possibilities
    and checking against a known plaintext-ciphertext pair.
    """
    # The value 'a' must be coprime with 26.
    possible_a = [a for a in range(26) if math.gcd(a, 26) == 1]

    # Convert known text to numerical values (a=0, b=1, ...)
    p0 = ord(known_plaintext[0].lower()) - ord('a')
    p1 = ord(known_plaintext[1].lower()) - ord('a')
    c0 = ord(known_ciphertext[0].upper()) - ord('A')
    c1 = ord(known_ciphertext[1].upper()) - ord('A')

    # Iterate through all possible keys (a, b)
    for a in possible_a:
        for b in range(26):
            # Check if this key encrypts the known plaintext to the known ciphertext
            if (a * p0 + b) % 26 == c0 and (a * p1 + b) % 26 == c1:
                return (a, b)  # Key found
    return None  # Key not found


def decrypt_affine(ciphertext, key):
    """
    Decrypts a message using an affine cipher key (a, b).
    """
    a, b = key
    a_inv = mod_inverse(a, 26)

    if a_inv is None:
        return "Error: Key 'a' has no modular inverse. Cannot decrypt."

    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            y = ord(char) - ord('A')
            # Decryption formula: x = a_inv * (y - b) mod 26
            # We add 26 to (y - b) to ensure the result is positive
            x = (a_inv * (y - b + 26)) % 26
            plaintext += chr(x + ord('A'))
        else:
            plaintext += char  # Keep non-alphabetic characters unchanged
    return plaintext


# --- Main execution ---
if __name__ == "__main__":
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    known_plaintext = "ab"
    known_ciphertext = "GL"

    print(f"Ciphertext: {ciphertext}")
    print(f"Known mapping: plaintext '{known_plaintext}' -> ciphertext '{known_ciphertext}'")
    print("\nStarting brute-force attack to find the key...")

    # Find the key using the known plaintext attack
    key = find_affine_key_brute_force(known_plaintext, known_ciphertext)

    if key:
        a, b = key
        print(f"Success! Found key (a, b) = ({a}, {b})")

        # Decrypt the full message with the found key
        decrypted_message = decrypt_affine(ciphertext, key)

        print("\n--- Decryption Result ---")
        print(f"Decrypted Message: {decrypted_message}")
    else:
        print("Failed to find a valid key with the given information.")