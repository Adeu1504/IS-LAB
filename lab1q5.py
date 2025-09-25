# 5. John is reading a mystery book involving cryptography. In one part of the book, the
# author gives a ciphertext "CIW" and two paragraphs later the author tells the reader that
# this is a shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet
# in a cave with "XVIEWYWI" engraved on it. John immediately found the actual meaning
# of the ciphertext. Identify the type of attack and plaintext.

def find_shift_key(plaintext_sample, ciphertext_sample):
    """
    Determines the shift key for a Caesar cipher using a known plaintext-ciphertext pair.

    Args:
        plaintext_sample (str): A sample of the original text.
        ciphertext_sample (str): The corresponding encrypted text.

    Returns:
        int: The calculated shift key (0-25).
    """
    # Use the first character of the samples to find the key
    # Convert to uppercase to ensure consistency
    p_char = plaintext_sample[0].upper()
    c_char = ciphertext_sample[0].upper()

    # Calculate the numerical position (0-25) for each character
    p_val = ord(p_char) - ord('A')
    c_val = ord(c_char) - ord('A')

    # The key is the difference, handled with modulo for wrap-around
    key = (c_val - p_val) % 26
    return key


def decrypt_shift_cipher(ciphertext, key):
    """
    Decrypts a message encrypted with a Caesar (shift) cipher.

    Args:
        ciphertext (str): The message to be decrypted.
        key (int): The shift key used for encryption.

    Returns:
        str: The decrypted plaintext message.
    """
    decrypted_message = ""
    for char in ciphertext.upper():
        if 'A' <= char <= 'Z':
            # Get the numerical value of the character
            char_val = ord(char) - ord('A')

            # Apply the reverse shift to decrypt
            decrypted_val = (char_val - key) % 26

            # Convert the numerical value back to a character
            decrypted_char = chr(decrypted_val + ord('A'))
            decrypted_message += decrypted_char
        else:
            # If the character is not a letter, keep it as is
            decrypted_message += char

    return decrypted_message


# --- Main Program ---

# 1. Known information from the book
known_plaintext = "yes"
known_ciphertext = "CIW"
target_ciphertext = "XVIEWYWI"

print("--- Step 1: Analyze the Known Information (Known-Plaintext Attack) ---")

# Find the key using the known plaintext/ciphertext pair
shift_key = find_shift_key(known_plaintext, known_ciphertext)
print(f"Plaintext sample: '{known_plaintext}'")
print(f"Ciphertext sample: '{known_ciphertext}'")
print(f"Discovered Shift Key: {shift_key}")
print("\nThis method of using a known plaintext/ciphertext pair to find the key is a 'Known-Plaintext Attack'.")

print("\n--- Step 2: Decrypt the New Ciphertext ---")

# Decrypt the new message using the discovered key
final_plaintext = decrypt_shift_cipher(target_ciphertext, shift_key)
print(f"Ciphertext to decrypt: '{target_ciphertext}'")
print(f"Using key = {shift_key}")
print(f"Decrypted Plaintext: {final_plaintext}")