import phe.paillier as paillier

# 1. Key Generation
print("Generating keypair...")
public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)

# 2. Integers to be encrypted
m1 = 15
m2 = 25
print(f"Original integers: {m1}, {m2}")

# 3. Encrypt the integers
print("\nEncrypting integers...")
c1 = public_key.encrypt(m1)
c2 = public_key.encrypt(m2)

print(f"Ciphertext 1: {c1.ciphertext(be_secure=False)}")
print(f"Ciphertext 2: {c2.ciphertext(be_secure=False)}")

# 4. Perform homomorphic addition
# This is the magic! We just add the encrypted objects.
print("\nPerforming homomorphic addition...")
c_sum = c1 + c2

print(f"Encrypted Sum: {c_sum.ciphertext(be_secure=False)}")

# 5. Decrypt the result
print("\nDecrypting sum...")
m_sum = private_key.decrypt(c_sum)

# 6. Verify the result
print(f"Decrypted Sum: {m_sum}")
print(f"Original Sum (15 + 25): {m1 + m2}")
print(f"Verification successful: {m_sum == m1 + m2}")