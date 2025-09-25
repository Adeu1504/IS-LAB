# . Use the Playfair cipher to encipher the message "The key is hidden under the door pad".
# The secret key can be made by filling the first and part of the second row with the word
# "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.

import textwrap


def create_key_matrix(key):
    """Creates a 5x5 Playfair key matrix."""
    # Convert key to uppercase and handle 'J' -> 'I'
    key = key.upper().replace('J', 'I')

    # Build the initial part of the matrix with unique key characters
    matrix_chars = []
    for char in key:
        if char not in matrix_chars and char.isalpha():
            matrix_chars.append(char)

    # Add the rest of the alphabet
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in matrix_chars:
            matrix_chars.append(char)

    # Reshape the list into a 5x5 matrix
    matrix = [matrix_chars[i:i + 5] for i in range(0, 25, 5)]
    return matrix


def prepare_plaintext(plaintext):
    """Prepares the plaintext for Playfair encryption."""
    # Convert to uppercase, remove non-alphabetic chars, and replace 'J' with 'I'
    plaintext = ''.join(filter(str.isalpha, plaintext.upper().replace('J', 'I')))

    # Insert 'X' between identical consecutive letters
    i = 0
    prepared_text = ""
    while i < len(plaintext):
        char1 = plaintext[i]
        prepared_text += char1
        if i + 1 < len(plaintext):
            char2 = plaintext[i + 1]
            if char1 == char2:
                prepared_text += 'X'
            else:
                prepared_text += char2
                i += 1
        i += 1

    # If the length is odd, append 'X' at the end
    if len(prepared_text) % 2 != 0:
        prepared_text += 'X'

    return prepared_text


def find_position(matrix, char):
    """Finds the row and column of a character in the matrix."""
    for r, row in enumerate(matrix):
        for c, value in enumerate(row):
            if value == char:
                return r, c
    return -1, -1  # Should not happen with prepared text


def playfair_encrypt(plaintext, key):
    """Encrypts a message using the Playfair cipher."""
    matrix = create_key_matrix(key)
    prepared_text = prepare_plaintext(plaintext)
    ciphertext = ""

    # Process the text in pairs (digraphs)
    for i in range(0, len(prepared_text), 2):
        char1 = prepared_text[i]
        char2 = prepared_text[i + 1]

        r1, c1 = find_position(matrix, char1)
        r2, c2 = find_position(matrix, char2)

        # Apply Playfair rules
        if r1 == r2:  # Same row
            ciphertext += matrix[r1][(c1 + 1) % 5]
            ciphertext += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:  # Same column
            ciphertext += matrix[(r1 + 1) % 5][c1]
            ciphertext += matrix[(r2 + 1) % 5][c2]
        else:  # Rectangle
            ciphertext += matrix[r1][c2]
            ciphertext += matrix[r2][c1]

    return matrix, prepared_text, ciphertext


# --- Main execution ---
if __name__ == "__main__":
    message = "The key is hidden under the door pad"
    secret_key = "GUIDANCE"

    key_matrix, processed_message, encrypted_message = playfair_encrypt(message, secret_key)

    print("--- Playfair Cipher Encryption ---")
    print(f"Original Message : {message}")
    print(f"Secret Key       : {secret_key}\n")

    print("Step 1: Generated Key Matrix")
    for row in key_matrix:
        print(" ".join(row))
    print("\n")

    print("Step 2: Prepared Plaintext (Digraphs)")
    # textwrap helps print the digraphs with spaces for readability
    print(" ".join(textwrap.wrap(processed_message, 2)))
    print("\n")

    print("Step 3: Encrypted Ciphertext")
    print(encrypted_message)