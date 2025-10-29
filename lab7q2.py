import math


def rsa_key_gen():
    """
    Generates a simple, non-secure RSA key pair for demonstration.
    """
    # 1. Choose two simple prime numbers
    # (In a real system, these would be very large and randomly generated)
    p = 61
    q = 53

    # 2. Calculate n (modulus)
    n = p * q  # 3233

    # 3. Calculate Euler's totient, phi(n)
    phi_n = (p - 1) * (q - 1)  # (60 * 52) = 3120

    # 4. Choose public exponent e
    # e must be 1 < e < phi_n and coprime to phi_n
    e = 17  # A common choice

    # 5. Calculate private exponent d
    # d is the modular multiplicative inverse of e mod phi_n
    # (d * e) % phi_n = 1
    d = pow(e, -1, phi_n)  # pow(17, -1, 3120) = 2753

    # Public key: (e, n), Private key: (d, n)
    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def encrypt(message, public_key):
    """
    Encrypts a message using the public key (m^e mod n).
    """
    e, n = public_key
    ciphertext = pow(message, e, n)
    return ciphertext


def decrypt(ciphertext, private_key):
    """
    Decrypts a ciphertext using the private key (c^d mod n).
    """
    d, n = private_key
    message = pow(ciphertext, d, n)
    return message


# --- Main Demonstration ---

print("### RSA Multiplicative Homomorphic Property Demo ###\n")

# 1. Generate keys
public_key, private_key = rsa_key_gen()
print(f"Public Key (e, n): {public_key}")
print(f"Private Key (d, n): ({private_key[0]}, {private_key[1]})\n")

# 2. Define original messages (integers)
m1 = 7
m2 = 3
print(f"Original message 1 (m1): {m1}")
print(f"Original message 2 (m2): {m2}\n")

# 3. Encrypt the integers
c1 = encrypt(m1, public_key)
c2 = encrypt(m2, public_key)
print(f"Encrypted m1 (c1): {c1}")
print(f"Encrypted m2 (c2): {c2}\n")

# 4. Perform multiplication on the encrypted integers
# We must perform the multiplication modulo n
n = public_key[1]
c_product = (c1 * c2) % n
print(f"Multiplied ciphertext (c_product = (c1 * c2) % n): {c_product}\n")

# 5. Decrypt the result of the multiplication
decrypted_product = decrypt(c_product, private_key)
print(f"Decrypted product (Dec(c_product)): {decrypted_product}\n")

# 6. Verify the result
original_product = m1 * m2
print(f"Original product (m1 * m2): {original_product}")

if decrypted_product == original_product:
    print("✅ Verification SUCCESS: Dec(c1 * c2) == m1 * m2")
else:
    print("❌ Verification FAILED")