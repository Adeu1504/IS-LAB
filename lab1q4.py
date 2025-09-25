# 4. Use a Hill cipher to encipher the message "We live in an insecure world". Use the
# following key:
# =𝐾 [03 03
# 02 07]

import numpy as np


def hill_cipher_encrypt(plaintext, key_matrix):
    """
    Encrypts a message using the Hill cipher.

    Args:
        plaintext (str): The message to encrypt.
        key_matrix (np.ndarray): The encryption key as a NumPy array.

    Returns:
        str: The encrypted ciphertext.
    """
    # 1. Prepare the plaintext
    # Remove non-alphabetic characters and convert to uppercase
    plaintext = ''.join(filter(str.isalpha, plaintext)).upper()

    # Pad the plaintext if its length is not a multiple of the key matrix size
    n = key_matrix.shape[0]
    if len(plaintext) % n != 0:
        padding_needed = n - (len(plaintext) % n)
        plaintext += 'X' * padding_needed

    # 2. Convert plaintext to numeric vectors
    plain_numbers = [ord(char) - ord('A') for char in plaintext]

    # 3. Encrypt using matrix multiplication
    cipher_numbers = []
    for i in range(0, len(plain_numbers), n):
        # Create a plaintext vector for the current block
        p_vector = np.array(plain_numbers[i:i + n]).reshape(n, 1)

        # C = (K * P) mod 26
        c_vector = np.dot(key_matrix, p_vector) % 26

        # Append the resulting numbers to the list
        cipher_numbers.extend(c_vector.flatten().tolist())

    # 4. Convert numbers back to ciphertext
    ciphertext = ''.join([chr(num + ord('A')) for num in cipher_numbers])

    return ciphertext


# --- Main execution ---
if __name__ == "__main__":
    # Given plaintext and key
    plaintext_message = "We live in an insecure world"
    key = [[3, 3],
           [2, 7]]

    # Convert the key list to a NumPy array
    key_matrix = np.array(key)

    # Check if the key is valid (invertible modulo 26)
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = -1
    for i in range(26):
        if (det * i) % 26 == 1:
            det_inv = i
            break

    if det_inv == -1:
        print("Error: The key matrix is not invertible modulo 26 and cannot be used for decryption.")
    else:
        # Encrypt the message
        encrypted_message = hill_cipher_encrypt(plaintext_message, key_matrix)

        print("--- Hill Cipher Encryption ---")
        print(f"Original Message: '{plaintext_message}'")
        print(f"Key Matrix:\n{key_matrix}")

        # Show pre-processed plaintext for clarity
        processed_plain = ''.join(filter(str.isalpha, plaintext_message)).upper()
        if len(processed_plain) % 2 != 0:
            processed_plain += 'X'

        print(f"Processed Plaintext: {processed_plain}")
        print("-" * 30)
        print(f"Encrypted Message: {encrypted_message}")

# import numpy as np
#
#
# def hill_cipher_encrypt(plaintext, key_matrix):
#     """
#     Encrypts a message using the Hill cipher.
#     (This function is identical to the previous answer and works for any n x n key)
#     """
#     # 1. Prepare the plaintext
#     plaintext = ''.join(filter(str.isalpha, plaintext)).upper()
#
#     # 2. Get the block size and pad if necessary
#     n = key_matrix.shape[0]
#     if len(plaintext) % n != 0:
#         padding_needed = n - (len(plaintext) % n)
#         plaintext += 'X' * padding_needed
#
#     # 3. Convert to numbers
#     plain_numbers = [ord(char) - ord('A') for char in plaintext]
#
#     # 4. Encrypt using matrix multiplication in blocks of size n
#     cipher_numbers = []
#     for i in range(0, len(plain_numbers), n):
#         p_vector = np.array(plain_numbers[i:i + n]).reshape(n, 1)
#         c_vector = np.dot(key_matrix, p_vector) % 26
#         cipher_numbers.extend(c_vector.flatten().tolist())
#
#     # 5. Convert back to ciphertext
#     ciphertext = ''.join([chr(num + ord('A')) for num in cipher_numbers])
#
#     return ciphertext
#
#
# # --- Main execution with a 3x3 key ---
# if __name__ == "__main__":
#     # Define a new plaintext and a 3x3 key
#     plaintext_3x3 = "Pay more money"
#     key_3x3_list = [[6, 24, 1],
#                     [13, 16, 10],
#                     [20, 17, 15]]
#
#     key_matrix_3x3 = np.array(key_3x3_list)
#
#     # Check if the key is valid (invertible modulo 26)
#     det = int(np.round(np.linalg.det(key_matrix_3x3))) % 26
#     det_inv = -1
#     for i in range(26):
#         if (det * i) % 26 == 1:
#             det_inv = i
#             break
#
#     if det_inv == -1:
#         print("Error: The 3x3 key matrix is not invertible modulo 26.")
#     else:
#         # The SAME function is called, just with different inputs
#         encrypted_message_3x3 = hill_cipher_encrypt(plaintext_3x3, key_matrix_3x3)
#
#         print("--- Hill Cipher Encryption (3x3 Example) ---")
#         print(f"Original Message: '{plaintext_3x3}'")
#         print(f"Key Matrix:\n{key_matrix_3x3}")
#
#         # Show pre-processed plaintext
#         processed_plain = ''.join(filter(str.isalpha, plaintext_3x3)).upper()
#         if len(processed_plain) % 3 != 0:
#             padding_needed = 3 - (len(processed_plain) % 3)
#             processed_plain += 'X' * padding_needed
#
#         print(f"Processed Plaintext: {processed_plain}")
#         print("-" * 30)
#         print(f"Encrypted Message: {encrypted_message_3x3}")