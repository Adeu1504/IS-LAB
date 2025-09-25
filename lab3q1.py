# Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n,
# e). Then decrypt the ciphertext with the private key (n, d) to verify the original
# message.



from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_keys():
    """
    Generates a new RSA private and public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_message(public_key, message):
    """
    Encrypts a message using the provided public key.

    Args:
        public_key: The public key object.
        message (str): The string message to encrypt.

    Returns:
        bytes: The encrypted ciphertext.
    """
    # Convert the string message to bytes for encryption
    message_bytes = message.encode('utf-8')

    ciphertext = public_key.encrypt(
        message_bytes,
        # OAEP is the standard, secure padding scheme for RSA
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_message(private_key, ciphertext):
    """
    Decrypts ciphertext using the provided private key.

    Args:
        private_key: The private key object.
        ciphertext (bytes): The encrypted data.

    Returns:
        str: The original plaintext message.
    """
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Convert the decrypted bytes back to a string
    return plaintext_bytes.decode('utf-8')


# --- Main script execution ---

# 1. Generate the RSA key pair
print("1. Generating RSA private and public keys...")
private_key, public_key = generate_keys()
print("   Keys generated successfully.")

# 2. Define the message to be sent
original_message = "Asymmetric Encryption is powerful and simple with libraries."
print(f"\n2. Original Message: '{original_message}'")

# 3. Encrypt the message with the PUBLIC key
print("\n3. Encrypting the message with the public key...")
ciphertext = encrypt_message(public_key, original_message)
print(f"   Ciphertext (as bytes): {ciphertext}")

# 4. Decrypt the message with the PRIVATE key
print("\n4. Decrypting the ciphertext with the private key...")
decrypted_message = decrypt_message(private_key, ciphertext)
print(f"   Decrypted Message: '{decrypted_message}'")

# 5. Verify the result
print("\n5. Verifying the result...")
if original_message == decrypted_message:
    print("✅ Success! The decrypted message matches the original.")
else:
    print("❌ Error! The messages do not match.")