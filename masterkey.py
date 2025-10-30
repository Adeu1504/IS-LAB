"""
Complete Modular Python file for ICT 3141 Information Security Lab (Version 3)
Implements all feasible schemes from the lab manual in easy-to-use functions.

Required libraries:
pip install pycryptodome
pip install phe
pip install numpy
"""

import hashlib
import json
import numpy as np  # For Hill Cipher
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util import number
from phe import paillier  # For Partial Homomorphic Encryption

# --- Helper Functions ---

def mod_inverse(a, m):
    """Finds the modular multiplicative inverse of a under modulo m using Extended Euclidean Algorithm."""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None  # Inverse doesn't exist
    else:
        return x % m

def extended_gcd(a, b):
    """Extended Euclidean Algorithm: returns (gcd, x, y) where a*x + b*y = gcd."""
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (gcd, x, y)

# --- LAB 1: Basic Symmetric Key Ciphers ---

def caesar_cipher(text, key, mode='encrypt'):
    """Caesar (additive) cipher."""
    result = ""
    if mode == 'decrypt':
        key = -key

    for char in text.upper():
        if 'A' <= char <= 'Z':
            new_ord = (ord(char) - ord('A') + key) % 26 + ord('A')
            result += chr(new_ord)
        else:
            result += char
    return result

def multiplicative_cipher(text, key, mode='encrypt'):
    """Multiplicative cipher."""
    result = ""
    if mode == 'decrypt':
        key = mod_inverse(key, 26)
        if key is None:
            raise ValueError("Invalid key for multiplicative cipher decryption. No modular inverse.")

    for char in text.upper():
        if 'A' <= char <= 'Z':
            new_ord = ((ord(char) - ord('A')) * key) % 26 + ord('A')
            result += chr(new_ord)
        else:
            result += char
    return result

def affine_cipher(text, key, mode='encrypt'):
    """Affine cipher."""
    a, b = key
    result = ""

    if mode == 'decrypt':
        a_inv = mod_inverse(a, 26)
        if a_inv is None:
            raise ValueError("Invalid multiplicative key 'a' for affine cipher. No modular inverse.")
        for char in text.upper():
            if 'A' <= char <= 'Z':
                new_ord = (a_inv * (ord(char) - ord('A') - b)) % 26 + ord('A')
                result += chr(new_ord)
            else:
                result += char
    else: # encrypt
        for char in text.upper():
            if 'A' <= char <= 'Z':
                new_ord = (a * (ord(char) - ord('A')) + b) % 26 + ord('A')
                result += chr(new_ord)
            else:
                result += char
    return result

def vigenere_cipher(text, key, mode='encrypt'):
    """Vigenere cipher."""
    result = ""
    key_index = 0
    key = key.upper()

    for char in text.upper():
        if 'A' <= char <= 'Z':
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            if mode == 'decrypt':
                key_shift = -key_shift

            new_ord = (ord(char) - ord('A') + key_shift) % 26 + ord('A')
            result += chr(new_ord)
            key_index += 1
        else:
            result += char
    return result

def autokey_cipher(text, key, mode='encrypt'):
    """Autokey cipher."""
    result = ""
    text = text.upper()
    key = key.upper()

    if mode == 'encrypt':
        keystr = (key + text)
        for i, char in enumerate(text):
            if 'A' <= char <= 'Z':
                key_shift = ord(keystr[i]) - ord('A')
                new_ord = (ord(char) - ord('A') + key_shift) % 26 + ord('A')
                result += chr(new_ord)
            else:
                result += char
    else: # decrypt
        keystr = key
        for i, char in enumerate(text):
            if 'A' <= char <= 'Z':
                key_shift = ord(keystr[i]) - ord('A')
                new_ord = (ord(char) - ord('A') - key_shift) % 26 + ord('A')
                decrypted_char = chr(new_ord)
                result += decrypted_char
                keystr += decrypted_char # Append decrypted char to key
            else:
                result += char
    return result

def _playfair_generate_matrix(key):
    """Helper for Playfair: Generates 5x5 key matrix."""
    key = key.upper().replace(' ', '').replace('J', 'I')
    matrix = []
    seen = set()

    for char in key:
        if char not in seen:
            matrix.append(char)
            seen.add(char)

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in seen:
            matrix.append(char)
            seen.add(char)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def _playfair_find_coords(matrix, char):
    """Helper for Playfair: Finds (row, col) of a char."""
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None, None

def playfair_cipher(text, key, mode='encrypt'):
    """Playfair cipher."""
    matrix = _playfair_generate_matrix(key)
    text = text.upper().replace(' ', '').replace('J', 'I')
    result = ""

    # Prepare digraphs
    if mode == 'encrypt':
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                text = text + 'X'
            elif text[i] == text[i+1]:
                text = text[:i+1] + 'X' + text[i+1:]
            i += 2

    # Process digraphs
    for i in range(0, len(text), 2):
        c1 = text[i]
        c2 = text[i+1]
        r1, c1_idx = _playfair_find_coords(matrix, c1)
        r2, c2_idx = _playfair_find_coords(matrix, c2)

        shift = 1 if mode == 'encrypt' else -1

        if r1 == r2: # Same row
            result += matrix[r1][(c1_idx + shift) % 5]
            result += matrix[r2][(c2_idx + shift) % 5]
        elif c1_idx == c2_idx: # Same column
            result += matrix[(r1 + shift) % 5][c1_idx]
            result += matrix[(r2 + shift) % 5][c2_idx]
        else: # Rectangle
            result += matrix[r1][c2_idx]
            result += matrix[r2][c1_idx]

    return result

def hill_cipher(text, key_matrix, mode='encrypt'):
    """
    Hill cipher.
    :param text: Plaintext.
    :param key_matrix: A 2x2 NumPy array, e.g., np.array([[3, 3], [2, 7]]).
    :param mode: 'encrypt' or 'decrypt'.
    """
    text = text.upper().replace(' ', '')
    if len(text) % 2 != 0:
        text += 'X' # Padding

    result = ""

    if mode == 'decrypt':
        # Find matrix inverse mod 26
        det = int(np.round(np.linalg.det(key_matrix))) % 26
        det_inv = mod_inverse(det, 26)
        if det_inv is None:
            raise ValueError("Key matrix is not invertible mod 26.")
        inv_matrix = np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)
        inv_matrix = (inv_matrix * det_inv) % 26
        inv_matrix = np.round(inv_matrix).astype(int)
        key_matrix = inv_matrix

    for i in range(0, len(text), 2):
        digraph = np.array([
            [ord(text[i]) - ord('A')],
            [ord(text[i+1]) - ord('A')]
        ])

        encrypted_digraph = (key_matrix @ digraph) % 26

        result += chr(encrypted_digraph[0][0] + ord('A'))
        result += chr(encrypted_digraph[1][0] + ord('A'))

    return result

def transposition_cipher(text, key, mode='encrypt'):
    """
    Keyed transposition cipher.
    :param text: Plaintext.
    :param key: Keyword, e.g., "HEALTH".
    """
    key = key.upper()

    if mode == 'encrypt':
        # Create permutation order
        sorted_key = sorted([(char, i) for i, char in enumerate(key)])
        col_order = [i for char, i in sorted_key]

        # Create grid
        num_cols = len(key)
        num_rows = int(np.ceil(len(text) / num_cols))
        grid = [[' ' for _ in range(num_cols)] for _ in range(num_rows)]

        k = 0
        for r in range(num_rows):
            for c in range(num_cols):
                if k < len(text):
                    grid[r][c] = text[k]
                    k += 1

        # Read by columns
        ciphertext = ""
        for c in col_order:
            for r in range(num_rows):
                ciphertext += grid[r][c]
        return ciphertext

    else: # decrypt
        # Create inverse permutation
        sorted_key = sorted([(char, i) for i, char in enumerate(key)])
        inv_col_order = [0] * len(key)
        for i, (char, orig_idx) in enumerate(sorted_key):
            inv_col_order[orig_idx] = i

        num_cols = len(key)
        num_rows = int(np.ceil(len(text) / num_cols))
        num_full_cols = len(text) % num_cols

        # Create grid to fill
        grid = [[' ' for _ in range(num_cols)] for _ in range(num_rows)]

        # Calculate column lengths
        col_lengths = [num_rows] * num_cols
        if num_full_cols > 0:
            for c in range(num_cols):
                if c >= num_full_cols:
                     col_lengths[c] = num_rows - 1

        # Re-order column lengths based on key
        true_col_lengths = [0] * num_cols
        for i, (char, orig_idx) in enumerate(sorted_key):
             true_col_lengths[i] = col_lengths[orig_idx]

        # Fill grid by columns
        k = 0
        for c in range(num_cols):
            for r in range(true_col_lengths[c]):
                grid[r][c] = text[k]
                k += 1

        # Read by rows
        plaintext = ""
        temp_grid = [[' ' for _ in range(num_cols)] for _ in range(num_rows)]
        for c in range(num_cols):
            read_col_idx = inv_col_order[c]
            for r in range(num_rows):
                 temp_grid[r][c] = grid[r][read_col_idx]

        for r in range(num_rows):
            for c in range(num_cols):
                plaintext += temp_grid[r][c]
        return plaintext.strip()


# --- LAB 2: Advanced Symmetric Key Ciphers ---

def des_cbc_encrypt(key, plaintext_bytes):
    """DES in CBC mode."""
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(plaintext_bytes, DES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return {'iv': iv.hex(), 'ciphertext': ciphertext.hex()}

def des_cbc_decrypt(key, iv_hex, ciphertext_hex):
    """DES in CBC mode."""
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, DES.block_size)

def des3_cbc_encrypt(key, plaintext_bytes):
    """Triple DES in CBC mode."""
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(plaintext_bytes, DES3.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return {'iv': iv.hex(), 'ciphertext': ciphertext.hex()}

def des3_cbc_decrypt(key, iv_hex, ciphertext_hex):
    """Triple DES in CBC mode."""
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, DES3.block_size)

def aes_cbc_encrypt(key, plaintext_bytes):
    """AES (128, 192, 256) in CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return {'iv': iv.hex(), 'ciphertext': ciphertext.hex()}

def aes_cbc_decrypt(key, iv_hex, ciphertext_hex):
    """AES in CBC mode."""
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, AES.block_size)


# --- LAB 3 & 4: Asymmetric Key Ciphers ---

def rsa_generate_keys(bits=2048):
    """Generates RSA key pair."""
    key = RSA.generate(bits)
    return key, key.publickey()

def rsa_encrypt(public_key, data_bytes):
    """Encrypts data using RSA public key."""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data_bytes)

def rsa_decrypt(private_key, ciphertext_bytes):
    """Decrypts data using RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext_bytes)

def elgamal_generate_keys(bits=512):
    """Generates ElGamal key pair."""
    p = number.getStrongPrime(bits)
    g = 2
    x = number.getRandomRange(2, p - 1) # private key
    y = pow(g, x, p) # public key
    public_key = (p, g, y)
    private_key = (p, x)
    return private_key, public_key

def elgamal_encrypt(public_key, message_int):
    """Encrypts a single integer using ElGamal."""
    p, g, y = public_key
    k = number.getRandomRange(2, p - 1)
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (message_int * s) % p
    return (c1, c2)

def elgamal_decrypt(private_key, ciphertext):
    """Decrypts an ElGamal ciphertext."""
    p, x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    if s_inv is None:
        raise ValueError("Decryption failed. Could not find modular inverse.")
    m = (c2 * s_inv) % p
    return m

def rabin_generate_keys(bits=512):
    """
    Generates Rabin key pair.
    p and q must be 3 (mod 4).
    """
    while True:
        p = number.getPrime(bits)
        if p % 4 == 3:
            break
    while True:
        q = number.getPrime(bits)
        if q % 4 == 3 and p != q:
            break
    n = p * q
    return (p, q), n # private key, public key

def rabin_encrypt(public_key_n, message_int):
    """Encrypts an integer using Rabin."""
    return pow(message_int, 2, public_key_n)

def rabin_decrypt(private_key, ciphertext):
    """
    Decrypts a Rabin ciphertext.
    Returns 4 possible plaintexts.
    """
    p, q = private_key
    n = p * q

    # 1. Compute square roots mod p and q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    # 2. Use Extended Euclidean Algorithm to find yp, yq
    # such that yp*p + yq*q = 1
    gcd, yp, yq = extended_gcd(p, q)

    # 3. Use Chinese Remainder Theorem for 4 roots
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    return [r1, r2, r3, r4]

# --- LAB 5: Hashing ---

def get_hash(data_bytes, algorithm='sha256'):
    """Generates a hash (MD5, SHA-1, SHA-256)."""
    if algorithm == 'sha256':
        h = hashlib.sha256()
    elif algorithm == 'sha1':
        h = hashlib.sha1()
    elif algorithm == 'md5':
        h = hashlib.md5()
    else:
        raise ValueError("Unsupported hash algorithm")
    h.update(data_bytes)
    return h.hexdigest()

# --- LAB 6: Digital Signature ---

def rsa_sign(private_key, data_bytes):
    """Creates an RSA digital signature."""
    h = SHA256.new(data_bytes)
    return pkcs1_15.new(private_key).sign(h)

def rsa_verify(public_key, data_bytes, signature_bytes):
    """Verifies an RSA digital signature."""
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False

# NOTE: Schnorr and ElGamal signatures
# are omitted for brevity.

# --- LAB 7: Partial Homomorphic Encryption ---

def paillier_generate_keys(key_length=1024):
    """Generates Paillier key pair (additive)."""
    return paillier.generate_paillier_keypair(n_length=key_length)

def paillier_encrypt(public_key, number):
    """Encrypts with Paillier."""
    return public_key.encrypt(number)

def paillier_decrypt(private_key, encrypted_number):
    """Decrypts with Paillier."""
    return private_key.decrypt(encrypted_number)

# Note: RSA and ElGamal support *multiplicative* homomorphism.
# See usage example.

# --- LAB 8: Searchable Encryption (SSE) ---

def sse_generate_key(key_length=32):
    """Generates a secret key for SSE."""
    return get_random_bytes(key_length)

def sse_create_index(key, documents):
    """
    Creates a simple encrypted index for SSE.
    'documents' is a dict like {"doc1": "text", "doc2": "more text"}.
    (Functional implementation of the lab manual's conceptual code)
    """
    index = {}
    encrypted_index = {}

    for doc_id, doc_text in documents.items():
        for word in set(doc_text.lower().split()):
            if word not in index:
                index[word] = []
            index[word].append(doc_id)

    for word, doc_ids in index.items():
        trapdoor_hash = hashlib.sha256(key + word.encode()).digest()
        doc_ids_json = json.dumps(doc_ids).encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_value = cipher.encrypt(pad(doc_ids_json, AES.block_size))

        encrypted_index[trapdoor_hash.hex()] = {
            'iv': iv.hex(),
            'data': encrypted_value.hex()
        }
    return encrypted_index

def sse_search(key, encrypted_index, query):
    """Searches the encrypted index for a query word."""
    query = query.lower()
    trapdoor_hash = hashlib.sha256(key + query.encode()).digest()
    result = encrypted_index.get(trapdoor_hash.hex())

    if result:
        try:
            iv = bytes.fromhex(result['iv'])
            encrypted_data = bytes.fromhex(result['data'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded_json = cipher.decrypt(encrypted_data)
            decrypted_json = unpad(decrypted_padded_json, AES.block_size)
            doc_ids = json.loads(decrypted_json.decode('utf-8'))
            return doc_ids
        except (ValueError, KeyError):
            return []
    else:
        return []

# NOTE: PKSE is also mentioned,
# but the sample code is non-functional and the
# exercise description is highly advanced.

# --- Main Usage Example ---
if __name__ == "__main__":

    print("--- LAB 1: Basic Symmetric Key Ciphers ---")
    plain1 = "IAMLEARNINGINFORMATIONSECURITY"
    key_add = 20
    enc1 = caesar_cipher(plain1, key_add, 'encrypt')
    print(f"Caesar Encrypt: {enc1}")
    print(f"Caesar Decrypt: {caesar_cipher(enc1, key_add, 'decrypt')}")

    key_aff = (15, 20)
    enc3 = affine_cipher(plain1, key_aff, 'encrypt')
    print(f"Affine Encrypt: {enc3}")
    print(f"Affine Decrypt: {affine_cipher(enc3, key_aff, 'decrypt')}")

    plain_playfair = "THEKEYISHIDDENUNDERTHEDOORPAD"
    key_playfair = "GUIDANCE"
    enc_playfair = playfair_cipher(plain_playfair, key_playfair, 'encrypt')
    print(f"Playfair Encrypt ('{key_playfair}'): {enc_playfair}")
    print(f"Playfair Decrypt: {playfair_cipher(enc_playfair, key_playfair, 'decrypt')}")

    plain_hill = "WELIVEINANINSECUREWORLD"
    key_hill = np.array([[3, 3], [2, 7]])
    enc_hill = hill_cipher(plain_hill, key_hill, 'encrypt')
    print(f"Hill Encrypt: {enc_hill}")
    print(f"Hill Decrypt: {hill_cipher(enc_hill, key_hill, 'decrypt')}")

    plain_trans = "Lifeisfullofsurprises"
    key_trans = "HEALTH"
    enc_trans = transposition_cipher(plain_trans, key_trans, 'encrypt')
    print(f"Transposition Encrypt ('{key_trans}'): {enc_trans}")
    print(f"Transposition Decrypt: {transposition_cipher(enc_trans, key_trans, 'decrypt')}")

    print("\n--- LAB 2: Advanced Symmetric Key Ciphers ---")
    key_des = b'A1B2C3D4'
    plain_des = b"Confidential Data"
    des_enc = des_cbc_encrypt(key_des, plain_des)
    des_dec = des_cbc_decrypt(key_des, des_enc['iv'], des_enc['ciphertext'])
    print(f"DES Decrypted: {des_dec.decode()}")

    key_aes = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    plain_aes = b"Sensitive Information"
    aes_enc = aes_cbc_encrypt(key_aes, plain_aes)
    aes_dec = aes_cbc_decrypt(key_aes, aes_enc['iv'], aes_enc['ciphertext'])
    print(f"AES-128 Decrypted: {aes_dec.decode()}")

    print("\n--- LAB 3 & 4: Asymmetric Key Ciphers ---")
    # RSA
    rsa_priv, rsa_pub = rsa_generate_keys(2048)
    plain_rsa = b"Asymmetric Encryption"
    rsa_enc = rsa_encrypt(rsa_pub, plain_rsa)
    rsa_dec = rsa_decrypt(rsa_priv, rsa_enc)
    print(f"RSA Decrypted: {rsa_dec.decode()}")

    # ElGamal
    el_priv, el_pub = elgamal_generate_keys(512)
    plain_el = 12345
    el_enc = elgamal_encrypt(el_pub, plain_el)
    el_dec = elgamal_decrypt(el_priv, el_enc)
    print(f"ElGamal Decrypted: {el_dec}")

    # Rabin
    rabin_priv, rabin_pub = rabin_generate_keys(512)
    plain_rabin = 123456789
    rabin_enc = rabin_encrypt(rabin_pub, plain_rabin)
    print(f"Rabin Encrypted: {rabin_enc}")
    rabin_decs = rabin_decrypt(rabin_priv, rabin_enc)
    print(f"Rabin Decrypted (4 roots): {rabin_decs}")
    print(f"Original in roots? {plain_rabin in rabin_decs}")


    print("\n--- LAB 5: Hashing ---")
    data_hash = b"Test data for hashing"
    print(f"SHA-256: {get_hash(data_hash, 'sha256')}")

    print("\n--- LAB 6: Digital Signature (RSA) ---")
    msg_to_sign = b"This document is authentic"
    signature = rsa_sign(rsa_priv, msg_to_sign)
    is_valid = rsa_verify(rsa_pub, msg_to_sign, signature)
    print(f"RSA Signature valid: {is_valid}")

    print("\n--- LAB 7: Partial Homomorphic Encryption ---")
    # Paillier (Additive)
    phe_pub, phe_priv = paillier_generate_keys(1024)
    num1 = 15
    num2 = 25
    enc_num1 = paillier_encrypt(phe_pub, num1)
    enc_num2 = paillier_encrypt(phe_pub, num2)
    enc_sum = enc_num1 + enc_num2
    decrypted_sum = paillier_decrypt(phe_priv, enc_sum)
    print(f"Paillier (Additive): {num1} + {num2} = {decrypted_sum}")

    # RSA (Multiplicative)
    rsa_priv_hom, rsa_pub_hom = rsa_generate_keys(1024)
    m1 = 7
    m2 = 3
    # Note: Using "textbook" RSA (no padding) for homomorphism
    c1 = pow(m1, rsa_pub_hom.e, rsa_pub_hom.n)
    c2 = pow(m2, rsa_pub_hom.e, rsa_pub_hom.n)
    c_prod = (c1 * c2) % rsa_pub_hom.n
    m_prod = pow(c_prod, rsa_priv_hom.d, rsa_priv_hom.n)
    print(f"RSA (Multiplicative): {m1} * {m2} = {m_prod}")

    # ElGamal (Multiplicative)
    el_priv_hom, el_pub_hom = elgamal_generate_keys(512)
    m3 = 5
    m4 = 6
    c_m3 = elgamal_encrypt(el_pub_hom, m3)
    c_m4 = elgamal_encrypt(el_pub_hom, m4)
    # C = (c1a*c1b, c2a*c2b)
    c_prod_el = ( (c_m3[0] * c_m4[0]) % el_pub_hom[0], (c_m3[1] * c_m4[1]) % el_pub_hom[0] )
    m_prod_el = elgamal_decrypt(el_priv_hom, c_prod_el)
    print(f"ElGamal (Multiplicative): {m3} * {m4} = {m_prod_el}")

    print("\n--- LAB 8: Searchable Encryption (SSE) ---")
    sse_key = sse_generate_key()
    docs = {
        "doc1": "this is a document with some words",
        "doc2": "another document with different words",
        "doc3": "yet another document with some common words"
    }
    encrypted_index = sse_create_index(sse_key, docs)
    query1 = "document"
    results1 = sse_search(sse_key, encrypted_index, query1)
    print(f"Search results for '{query1}': {results1}")