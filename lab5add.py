# is_lab_toolkit.py
# A comprehensive toolkit for ICT3141 Information Security Lab Exercises (Lab 1-6)
# Author: Gemini
# Date: 25-Sep-2025

# -----------------------------------------------------------------------------
# SECTION 0: IMPORTS
# -----------------------------------------------------------------------------
import string
import math
import time
import os
import hashlib
import socket
import threading
import numpy as np
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number


# -----------------------------------------------------------------------------
# SECTION 1: LAB 1 - Basic Symmetric Key Ciphers
# -----------------------------------------------------------------------------

# --- Helper for classical ciphers ---
def _prepare_text(text):
    """Removes spaces and converts to uppercase."""
    return "".join(filter(str.isalpha, text)).upper()


# --- Question 1: Additive, Multiplicative, Affine Ciphers ---
def additive_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using an Additive (Caesar/Shift) Cipher.
    Args:
        text (str): The input text.
        key (int): The shift value.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text.
    """
    text = _prepare_text(text)
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            offset = ord('A')
            if mode == 'encrypt':
                result += chr((ord(char) - offset + key) % 26 + offset)
            else:  # decrypt
                result += chr((ord(char) - offset - key + 26) % 26 + offset)
        else:
            result += char
    return result


def multiplicative_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using a Multiplicative Cipher.
    Args:
        text (str): The input text.
        key (int): The multiplicative key (must be coprime with 26).
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text or an error message.
    """
    if math.gcd(key, 26) != 1:
        return "Error: Key must be coprime with 26."

    text = _prepare_text(text)
    result = ""
    mod_inverse = pow(key, -1, 26)

    for char in text:
        offset = ord('A')
        if mode == 'encrypt':
            result += chr(((ord(char) - offset) * key) % 26 + offset)
        else:  # decrypt
            result += chr(((ord(char) - offset) * mod_inverse) % 26 + offset)
    return result


def affine_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using an Affine Cipher.
    Args:
        text (str): The input text.
        key (tuple): A tuple (a, b) where 'a' is the multiplicative key
                     and 'b' is the additive key.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text or an error message.
    """
    a, b = key
    if math.gcd(a, 26) != 1:
        return "Error: Multiplicative key 'a' must be coprime with 26."

    text = _prepare_text(text)
    result = ""
    mod_inverse_a = pow(a, -1, 26)
    offset = ord('A')

    for char in text:
        if mode == 'encrypt':
            y = (a * (ord(char) - offset) + b) % 26
            result += chr(y + offset)
        else:  # decrypt
            x = (mod_inverse_a * ((ord(char) - offset) - b + 26)) % 26
            result += chr(x + offset)
    return result


# --- Question 2: Vigenere and Autokey Ciphers ---
def vigenere_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using the Vigenere Cipher.
    Args:
        text (str): The input text.
        key (str): The keyword.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text.
    """
    text = _prepare_text(text)
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        offset = ord('A')
        key_char = key[key_index % len(key)]
        key_shift = ord(key_char) - offset

        if mode == 'encrypt':
            encrypted_char_code = (ord(char) - offset + key_shift) % 26
        else:  # decrypt
            encrypted_char_code = (ord(char) - offset - key_shift + 26) % 26

        result += chr(encrypted_char_code + offset)
        key_index += 1
    return result


def autokey_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using the Autokey Cipher.
    Args:
        text (str): The input text.
        key (int or str): An initial integer key or a keyword string.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text.
    """
    text = _prepare_text(text)
    result = []
    offset = ord('A')

    if isinstance(key, int):  # For key = 7
        keystream = [key] + [ord(c) - offset for c in text]
    else:  # For a string key
        keystream = [ord(k) - offset for k in key.upper()] + [ord(c) - offset for c in text]

    for i, char in enumerate(text):
        p_val = ord(char) - offset
        k_val = keystream[i]
        if mode == 'encrypt':
            c_val = (p_val + k_val) % 26
            result.append(chr(c_val + offset))
        else:  # decrypt
            p_val_decrypted = (p_val - k_val + 26) % 26
            result.append(chr(p_val_decrypted + offset))
            # Update keystream for next decryption step
            keystream[i + 1] = p_val_decrypted

    return "".join(result)


# --- Question 3: Playfair Cipher ---
def playfair_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using the Playfair Cipher.
    Args:
        text (str): The input text.
        key (str): The keyword for the matrix.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text.
    """

    def create_matrix(key):
        key = key.upper().replace("J", "I")
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        matrix = []
        # Add unique key characters
        for char in key:
            if char not in matrix:
                matrix.append(char)
        # Add remaining alphabet characters
        for char in alphabet:
            if char not in matrix:
                matrix.append(char)
        return [matrix[i:i + 5] for i in range(0, 25, 5)]

    def find_pos(matrix, char):
        for r, row in enumerate(matrix):
            for c, col_char in enumerate(row):
                if col_char == char:
                    return r, c
        return -1, -1

    def prepare_plaintext(text):
        text = _prepare_text(text).replace("J", "I")
        prepared = ""
        i = 0
        while i < len(text):
            a = text[i]
            if i + 1 == len(text):
                b = 'X'  # Use X for padding, Z is also common
                prepared += a + b
                break
            b = text[i + 1]
            if a == b:
                prepared += a + 'X'
                i += 1
            else:
                prepared += a + b
                i += 2
        return prepared

    matrix = create_matrix(key)
    plaintext = prepare_plaintext(text)
    ciphertext = ""
    shift = 1 if mode == 'encrypt' else -1

    for i in range(0, len(plaintext), 2):
        char1, char2 = plaintext[i], plaintext[i + 1]
        r1, c1 = find_pos(matrix, char1)
        r2, c2 = find_pos(matrix, char2)

        if r1 == r2:  # Same row
            ciphertext += matrix[r1][(c1 + shift) % 5]
            ciphertext += matrix[r2][(c2 + shift) % 5]
        elif c1 == c2:  # Same column
            ciphertext += matrix[(r1 + shift) % 5][c1]
            ciphertext += matrix[(r2 + shift) % 5][c2]
        else:  # Rectangle
            ciphertext += matrix[r1][c2]
            ciphertext += matrix[r2][c1]

    return ciphertext


# --- Question 4: Hill Cipher ---
def hill_cipher(text, key_matrix, mode='encrypt'):
    """
    Encrypts or decrypts text using the Hill Cipher.
    Args:
        text (str): The input text.
        key_matrix (np.array): A NumPy array representing the key.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        str: The processed text or an error message.
    """
    text = _prepare_text(text)
    n = key_matrix.shape[0]

    # Check for valid key
    det = int(np.round(np.linalg.det(key_matrix))) % 26
    if math.gcd(det, 26) != 1:
        return "Error: Key matrix is not invertible. Cannot decrypt."

    # Pad text if necessary
    if len(text) % n != 0:
        padding_needed = n - (len(text) % n)
        text += 'X' * padding_needed

    result = ""
    matrix_to_use = key_matrix
    if mode == 'decrypt':
        det_inv = pow(det, -1, 26)
        adj_matrix = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
        inv_matrix = (det_inv * adj_matrix) % 26
        matrix_to_use = inv_matrix

    for i in range(0, len(text), n):
        block = text[i:i + n]
        block_vec = np.array([ord(c) - ord('A') for c in block])
        result_vec = np.dot(block_vec, matrix_to_use) % 26
        result += "".join([chr(int(x) + ord('A')) for x in result_vec])

    return result


# --- Question 5: Known-Plaintext Attack on Shift Cipher ---
def known_plaintext_attack_shift(known_ct, known_pt, new_ct):
    """
    Finds the key of a shift cipher from a known pair and decrypts new ciphertext.
    Args:
        known_ct (str): Known ciphertext.
        known_pt (str): Known plaintext.
        new_ct (str): New ciphertext to decrypt.
    Returns:
        dict: A dictionary containing the attack type, key, and decrypted plaintext.
    """
    known_ct = _prepare_text(known_ct)
    known_pt = _prepare_text(known_pt)
    new_ct = _prepare_text(new_ct)

    # Assuming the first character reveals the key
    key = (ord(known_ct[0]) - ord(known_pt[0])) % 26
    decrypted_text = additive_cipher(new_ct, key, 'decrypt')

    return {
        "attack_type": "Known-Plaintext Attack",
        "found_key": key,
        "decrypted_plaintext": decrypted_text
    }


# --- Question 6: Brute-Force Attack on Affine Cipher ---
def brute_force_affine(ciphertext, known_pt_fragment, known_ct_fragment):
    """
    Brute-forces an Affine cipher using a known plaintext/ciphertext fragment.
    Args:
        ciphertext (str): The full ciphertext to crack.
        known_pt_fragment (str): A small piece of known plaintext (e.g., "ab").
        known_ct_fragment (str): The corresponding ciphertext (e.g., "GL").
    Returns:
        dict: A dictionary with the found key and decrypted plaintext, or a failure message.
    """
    ciphertext = _prepare_text(ciphertext)
    known_pt = _prepare_text(known_pt_fragment)
    known_ct = _prepare_text(known_ct_fragment)

    possible_a = [a for a in range(26) if math.gcd(a, 26) == 1]
    possible_b = range(26)

    p1, p2 = ord(known_pt[0]) - ord('A'), ord(known_pt[1]) - ord('A')
    c1, c2 = ord(known_ct[0]) - ord('A'), ord(known_ct[1]) - ord('A')

    for a in possible_a:
        for b in possible_b:
            if (a * p1 + b) % 26 == c1 and (a * p2 + b) % 26 == c2:
                # Found the key
                key = (a, b)
                plaintext = affine_cipher(ciphertext, key, 'decrypt')
                return {"found_key": key, "decrypted_plaintext": plaintext}

    return {"error": "Could not find the key with the given fragments."}


# -----------------------------------------------------------------------------
# SECTION 2: LAB 2 - Advanced Symmetric Key Ciphers
# -----------------------------------------------------------------------------

def des_cipher(message, key_hex, mode='encrypt'):
    """
    Encrypts or decrypts a message using DES in ECB mode.
    Args:
        message (str): The message to process.
        key_hex (str): An 8-byte (16 hex chars) key.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        bytes: The processed data (ciphertext or plaintext).
    """
    key = bytes.fromhex(key_hex)
    cipher = DES.new(key, DES.MODE_ECB)

    if mode == 'encrypt':
        plaintext = message.encode()
        padded_text = pad(plaintext, DES.block_size)
        return cipher.encrypt(padded_text)
    else:  # decrypt
        decrypted_padded = cipher.decrypt(message)
        return unpad(decrypted_padded, DES.block_size)


def triple_des_cipher(message, key_hex, mode='encrypt'):
    """
    Encrypts or decrypts a message using Triple DES in ECB mode.
    Args:
        message (str or bytes): The message to process.
        key_hex (str): A 24-byte (48 hex chars) key.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        bytes: The processed data (ciphertext or plaintext).
    """
    key = DES3.adjust_key_parity(bytes.fromhex(key_hex))
    cipher = DES3.new(key, DES3.MODE_ECB)

    if mode == 'encrypt':
        plaintext = message.encode()
        padded_text = pad(plaintext, DES3.block_size)
        return cipher.encrypt(padded_text)
    else:  # decrypt
        decrypted_padded = cipher.decrypt(message)
        return unpad(decrypted_padded, DES3.block_size)


def aes_cipher(message, key_hex, mode='encrypt'):
    """
    Encrypts or decrypts a message using AES in ECB mode.
    The key length determines the AES variant (128, 192, or 256 bits).
    Args:
        message (str or bytes): The message to process.
        key_hex (str): A 16, 24, or 32-byte key in hex.
        mode (str): 'encrypt' or 'decrypt'.
    Returns:
        bytes: The processed data (ciphertext or plaintext).
    """
    key = bytes.fromhex(key_hex)
    cipher = AES.new(key, AES.MODE_ECB)

    if mode == 'encrypt':
        plaintext = message.encode()
        padded_text = pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_text)
    else:  # decrypt
        decrypted_padded = cipher.decrypt(message)
        return unpad(decrypted_padded, AES.block_size)


def compare_cipher_performance(message, iterations=100):
    """
    Compares the encryption/decryption times for DES and AES-256.
    Args:
        message (str): The message to use for testing.
        iterations (int): Number of times to run the test for an average.
    Returns:
        dict: A dictionary containing the performance results.
    """
    # Generate random keys
    des_key = get_random_bytes(8).hex()
    aes256_key = get_random_bytes(32).hex()

    results = {}

    # --- DES Performance ---
    start = time.time()
    for _ in range(iterations):
        ct = des_cipher(message, des_key, 'encrypt')
    results['des_encryption_time'] = (time.time() - start) / iterations

    start = time.time()
    for _ in range(iterations):
        des_cipher(ct, des_key, 'decrypt')
    results['des_decryption_time'] = (time.time() - start) / iterations

    # --- AES-256 Performance ---
    start = time.time()
    for _ in range(iterations):
        ct = aes_cipher(message, aes256_key, 'encrypt')
    results['aes256_encryption_time'] = (time.time() - start) / iterations

    start = time.time()
    for _ in range(iterations):
        aes_cipher(ct, aes256_key, 'decrypt')
    results['aes256_decryption_time'] = (time.time() - start) / iterations

    return results


# -----------------------------------------------------------------------------
# SECTION 3 & 4: LAB 3/4 - Asymmetric Key Ciphers
# -----------------------------------------------------------------------------

# --- RSA ---
def generate_rsa_keys(bits=2048):
    """Generates an RSA public/private key pair."""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def rsa_encrypt(message, public_key_pem):
    """Encrypts a message using an RSA public key."""
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(message.encode())


def rsa_decrypt(ciphertext, private_key_pem):
    """Decrypts a message using an RSA private key."""
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext).decode()


# --- ElGamal (Manual Implementation) ---
def generate_elgamal_keys(bits=512):
    """Generates ElGamal keys (p, g, y) and private key x."""
    p = number.getPrime(bits)
    g = 2  # A common generator
    x = number.getRandomRange(2, p - 1)
    y = pow(g, x, p)
    public_key = (p, g, y)
    private_key = x
    return public_key, private_key


def elgamal_encrypt(message, public_key):
    """Encrypts a message using ElGamal."""
    p, g, y = public_key
    m_int = int.from_bytes(message.encode(), 'big')
    k = number.getRandomRange(2, p - 1)
    c1 = pow(g, k, p)
    c2 = (m_int * pow(y, k, p)) % p
    return (c1, c2)


def elgamal_decrypt(ciphertext, public_key, private_key):
    """Decrypts an ElGamal ciphertext."""
    p, _, _ = public_key
    x = private_key
    c1, c2 = ciphertext
    s_inv = pow(c1, -x, p)
    m_int = (c2 * s_inv) % p
    return m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big').decode()


# --- Rabin (Manual Implementation for Lab 4) ---
def generate_rabin_keys(bits=512):
    """Generates Rabin keys (n) and private keys (p, q)."""
    p = number.getPrime(bits // 2)
    while p % 4 != 3: p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    while q % 4 != 3 or p == q: q = number.getPrime(bits // 2)
    n = p * q
    return n, (p, q)


def rabin_encrypt(message, n):
    """Encrypts a message using Rabin."""
    m_int = int.from_bytes(message.encode(), 'big')
    # Simple padding to distinguish the correct root
    m_padded = (m_int << 8) | m_int % 256
    if m_padded >= n:
        raise ValueError("Message too large for key size")
    return pow(m_padded, 2, n)


def rabin_decrypt(ciphertext, private_key):
    """Decrypts a Rabin ciphertext and finds the correct root."""
    p, q = private_key
    n = p * q

    # Find square roots modulo p and q
    m_p = pow(ciphertext, (p + 1) // 4, p)
    m_q = pow(ciphertext, (q + 1) // 4, q)

    # Use Chinese Remainder Theorem to find four roots
    _, yp, yq = number.GCD(p, q)
    r1 = (yp * p * m_q + yq * q * m_p) % n
    r2 = n - r1
    r3 = (yp * p * m_q - yq * q * m_p) % n
    r4 = n - r3

    # Check padding to find the original message
    for r in [r1, r2, r3, r4]:
        if (r & 0xFF) == ((r >> 8) & 0xFF):
            m_int = r >> 8
            return m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big').decode()
    return "Decryption failed: could not find correct root."


# --- Diffie-Hellman Key Exchange ---
def diffie_hellman_exchange(bits=512):
    """Simulates a Diffie-Hellman key exchange."""
    # Publicly agreed parameters
    p = number.getPrime(bits)
    g = 2

    # Alice's side
    a_private = number.getRandomRange(2, p - 1)
    a_public = pow(g, a_private, p)

    # Bob's side
    b_private = number.getRandomRange(2, p - 1)
    b_public = pow(g, b_private, p)

    # Shared secret calculation
    alice_shared_secret = pow(b_public, a_private, p)
    bob_shared_secret = pow(a_public, b_private, p)

    return {
        "p": p, "g": g,
        "alice_public": a_public, "bob_public": b_public,
        "alice_shared_secret": alice_shared_secret,
        "bob_shared_secret": bob_shared_secret,
        "success": alice_shared_secret == bob_shared_secret
    }


# -----------------------------------------------------------------------------
# SECTION 5: LAB 5 - Hashing
# -----------------------------------------------------------------------------

def custom_hash_function(input_string):
    """
    Implements the custom hash function from Lab 5, Q1.
    hash = (hash * 33 + ord(char)) & 0xFFFFFFFF
    """
    hash_val = 5381
    for char in input_string:
        hash_val = (hash_val * 33 + ord(char)) & 0xFFFFFFFF
    return hash_val


def analyze_hashing_performance(num_strings=100, string_length=50):
    """
    Analyzes computation time and detects collisions for MD5, SHA-1, SHA-256.
    """
    dataset = [os.urandom(string_length).hex() for _ in range(num_strings)]
    results = {}

    for algo_name in ['md5', 'sha1', 'sha256']:
        algo = getattr(hashlib, algo_name)
        hashes = set()
        collisions = 0

        start_time = time.time()
        for s in dataset:
            h = algo(s.encode()).hexdigest()
            if h in hashes:
                collisions += 1
            hashes.add(h)
        end_time = time.time()

        results[algo_name] = {
            "computation_time": end_time - start_time,
            "collisions_found": collisions
        }
    return results


# --- Socket Programming for Data Integrity ---
# Note: These must be run in separate terminals.
def integrity_server(host='127.0.0.1', port=65432):
    print(f"Starting integrity server on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            print(f"Received data: {data.decode()}")
            # Compute hash and send it back
            computed_hash = hashlib.sha256(data).hexdigest()
            conn.sendall(computed_hash.encode())
            print(f"Sent hash: {computed_hash}")


def integrity_client(data_to_send, tamper=False, host='127.0.0.1', port=65432):
    original_data = data_to_send.encode()
    data_to_transmit = original_data

    if tamper:
        data_to_transmit += b'tampered'
        print("--- Data has been tampered with before sending! ---")

    client_hash = hashlib.sha256(original_data).hexdigest()
    print(f"Client-side original data hash: {client_hash}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(data_to_transmit)
        server_hash = s.recv(1024).decode()
        print(f"Received hash from server: {server_hash}")

    if client_hash == server_hash:
        print("✅ Data integrity verified: Hashes match.")
    else:
        print("❌ Data integrity check failed: Hashes do not match.")


# -----------------------------------------------------------------------------
# SECTION 6: LAB 6 - Digital Signatures
# -----------------------------------------------------------------------------

def rsa_sign(message, private_key_pem):
    """Signs a message using an RSA private key."""
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature


def rsa_verify(message, signature, public_key_pem):
    """Verifies a signature using an RSA public key."""
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def elgamal_sign(message, public_key, private_key):
    """Signs a message using ElGamal."""
    p, g, _ = public_key
    x = private_key
    m_hash = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')

    k = number.getRandomRange(2, p - 2)
    while math.gcd(k, p - 1) != 1:
        k = number.getRandomRange(2, p - 2)

    r = pow(g, k, p)
    s = ((m_hash - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)


def elgamal_verify(message, signature, public_key):
    """Verifies an ElGamal signature."""
    p, g, y = public_key
    r, s = signature
    m_hash = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')

    if not (0 < r < p and 0 < s < p - 1):
        return False

    v1 = pow(g, m_hash, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


# -----------------------------------------------------------------------------
# MAIN EXECUTION BLOCK
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("--- Information Security Lab Toolkit ---")
    print("Uncomment the code block for the question you want to run.\n")

    # === LAB 1 EXAMPLES ===
    # --- Q1: Additive, Multiplicative, Affine ---
    # msg1 = "I am learning information security"
    # print(f"Original: {msg1}")
    # # a) Additive cipher with key = 20
    # ct_add = additive_cipher(msg1, 20, 'encrypt')
    # print(f"Additive Encrypted (k=20): {ct_add}")
    # print(f"Additive Decrypted (k=20): {additive_cipher(ct_add, 20, 'decrypt')}")
    # # b) Multiplicative cipher with key = 15
    # ct_mul = multiplicative_cipher(msg1, 15, 'encrypt')
    # print(f"Multiplicative Encrypted (k=15): {ct_mul}")
    # print(f"Multiplicative Decrypted (k=15): {multiplicative_cipher(ct_mul, 15, 'decrypt')}")
    # # c) Affine cipher with key = (15, 20)
    # ct_aff = affine_cipher(msg1, (15, 20), 'encrypt')
    # print(f"Affine Encrypted (k=(15,20)): {ct_aff}")
    # print(f"Affine Decrypted (k=(15,20)): {affine_cipher(ct_aff, (15, 20), 'decrypt')}")

    # --- Q2: Vigenere, Autokey ---
    # msg2 = "the house is being sold tonight"
    # print(f"\nOriginal: {msg2}")
    # # a) Vigenere cipher with key: "dollars"
    # ct_vig = vigenere_cipher(msg2, "dollars", 'encrypt')
    # print(f"Vigenere Encrypted (key=dollars): {ct_vig}")
    # print(f"Vigenere Decrypted (key=dollars): {vigenere_cipher(ct_vig, 'dollars', 'decrypt')}")
    # # b) Autokey cipher with key = 7
    # ct_auto = autokey_cipher(msg2, 7, 'encrypt')
    # print(f"Autokey Encrypted (key=7): {ct_auto}")
    # print(f"Autokey Decrypted (key=7): {autokey_cipher(ct_auto, 7, 'decrypt')}")

    # --- Q3: Playfair Cipher ---
    # msg3 = "The key is hidden under the door pad"
    # key3 = "GUIDANCE"
    # print(f"\nOriginal: {msg3}")
    # ct_play = playfair_cipher(msg3, key3, 'encrypt')
    # print(f"Playfair Encrypted (key={key3}): {ct_play}")

    # --- Q4: Hill Cipher ---
    # msg4 = "We live in an insecure world"
    # key4 = np.array([[3, 3], [2, 7]])
    # print(f"\nOriginal: {msg4}")
    # ct_hill = hill_cipher(msg4, key4, 'encrypt')
    # print(f"Hill Encrypted (key=[[3,3],[2,7]]): {ct_hill}")
    # print(f"Hill Decrypted (key=[[3,3],[2,7]]): {hill_cipher(ct_hill, key4, 'decrypt')}")

    # --- Q5: Known-Plaintext Attack ---
    # print("\n--- Q5: Known-Plaintext Attack ---")
    # attack_result = known_plaintext_attack_shift("CIW", "yes", "XVIEWYWI")
    # print(attack_result)

    # --- Q6: Brute-Force Affine Cipher ---
    # print("\n--- Q6: Brute-Force Affine ---")
    # ct6 = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    # result6 = brute_force_affine(ct6, "ab", "GL")
    # print(result6)

    # === LAB 2 EXAMPLES ===
    # print("\n--- LAB 2 ---")
    # # Q1: DES
    # msg_des = "Confidential Data"
    # key_des = "A1B2C3D4A1B2C3D4" # 8 bytes hex
    # ct_des = des_cipher(msg_des, key_des, 'encrypt')
    # print(f"DES Encrypted: {ct_des.hex()}")
    # pt_des = des_cipher(ct_des, key_des, 'decrypt')
    # print(f"DES Decrypted: {pt_des.decode()}")

    # # Q2: AES-128
    # msg_aes128 = "Sensitive Information"
    # key_aes128 = "0123456789ABCDEF0123456789ABCDEF" # 16 bytes hex
    # ct_aes128 = aes_cipher(msg_aes128, key_aes128, 'encrypt')
    # print(f"AES-128 Encrypted: {ct_aes128.hex()}")
    # pt_aes128 = aes_cipher(ct_aes128, key_aes128, 'decrypt')
    # print(f"AES-128 Decrypted: {pt_aes128.decode()}")

    # # Q3: Performance Comparison
    # msg_perf = "Performance Testing of Encryption Algorithms"
    # print(f"\nRunning performance comparison for: '{msg_perf}'...")
    # perf_results = compare_cipher_performance(msg_perf)
    # for key, value in perf_results.items():
    #     print(f"{key}: {value:.8f} seconds per operation")

    # # Q4: Triple DES
    # msg_3des = "Classified Text"
    # key_3des = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" # 24 bytes hex
    # ct_3des = triple_des_cipher(msg_3des, key_3des, 'encrypt')
    # print(f"\n3DES Encrypted: {ct_3des.hex()}")
    # pt_3des = triple_des_cipher(ct_3des, key_3des, 'decrypt')
    # print(f"3DES Decrypted: {pt_3des.decode()}")

    # # Q5: AES-192
    # # Note: Showing intermediate steps requires a from-scratch implementation.
    # # This function just performs the encryption/decryption.
    # msg_aes192 = "Top Secret Data"
    # key_aes192 = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210" # 24 bytes hex
    # ct_aes192 = aes_cipher(msg_aes192, key_aes192, 'encrypt')
    # print(f"AES-192 Encrypted: {ct_aes192.hex()}")
    # pt_aes192 = aes_cipher(ct_aes192, key_aes192, 'decrypt')
    # print(f"AES-192 Decrypted: {pt_aes192.decode()}")

    # === LAB 3 & 4 EXAMPLES ===
    # print("\n--- LAB 3 & 4 ---")
    # # Q1 (Lab 3): RSA
    # print("\n--- RSA Example ---")
    # rsa_pub, rsa_priv = generate_rsa_keys()
    # msg_rsa = "Asymmetric Encryption"
    # ct_rsa = rsa_encrypt(msg_rsa, rsa_pub)
    # print(f"RSA Encrypted: {ct_rsa.hex()}")
    # pt_rsa = rsa_decrypt(ct_rsa, rsa_priv)
    # print(f"RSA Decrypted: {pt_rsa}")

    # # Q3 (Lab 3): ElGamal
    # print("\n--- ElGamal Example ---")
    # elg_pub, elg_priv = generate_elgamal_keys()
    # msg_elg = "Confidential Data"
    # ct_elg = elgamal_encrypt(msg_elg, elg_pub)
    # print(f"ElGamal Encrypted (c1, c2): {ct_elg}")
    # pt_elg = elgamal_decrypt(ct_elg, elg_pub, elg_priv)
    # print(f"ElGamal Decrypted: {pt_elg}")

    # # Q5 (Lab 3): Diffie-Hellman
    # print("\n--- Diffie-Hellman Exchange ---")
    # dh_results = diffie_hellman_exchange()
    # print(f"Success: {dh_results['success']}")
    # print(f"Alice's secret: {dh_results['alice_shared_secret']}")
    # print(f"Bob's secret:   {dh_results['bob_shared_secret']}")

    # # Q2 (Lab 4): Rabin
    # print("\n--- Rabin Example ---")
    # rabin_pub, rabin_priv = generate_rabin_keys()
    # msg_rabin = "Secure patient data management"
    # ct_rabin = rabin_encrypt(msg_rabin, rabin_pub)
    # print(f"Rabin Encrypted: {ct_rabin}")
    # pt_rabin = rabin_decrypt(ct_rabin, rabin_priv)
    # print(f"Rabin Decrypted: {pt_rabin}")

    # === LAB 5 EXAMPLES ===
    # print("\n--- LAB 5 ---")
    # # Q1: Custom Hash Function
    # test_string = "Hello World"
    # print(f"\nCustom hash for '{test_string}': {custom_hash_function(test_string)}")

    # # Q3: Hashing Performance
    # print("\nAnalyzing hashing performance...")
    # hash_perf = analyze_hashing_performance()
    # for algo, data in hash_perf.items():
    #     print(f"Algorithm: {algo.upper()}")
    #     print(f"  Time for 100 strings: {data['computation_time']:.6f}s")
    #     print(f"  Collisions found: {data['collisions_found']}")

    # # Q2: Data Integrity with Sockets
    # # To run this, open two terminals.
    # # In terminal 1, run: python your_script_name.py server
    # # In terminal 2, run: python your_script_name.py client
    # import sys
    # if len(sys.argv) > 1:
    #     if sys.argv[1] == 'server':
    #         integrity_server()
    #     elif sys.argv[1] == 'client':
    #         print("\n--- Running Integrity Client (No Tampering) ---")
    #         integrity_client("This is a test message for integrity.")
    #         print("\n--- Running Integrity Client (With Tampering) ---")
    #         integrity_client("This is a test message for integrity.", tamper=True)
    # else:
    #     print("\nTo run Lab 5 Q2, use command line arguments:")
    #     print("  'python is_lab_toolkit.py server' to start the server.")
    #     print("  'python is_lab_toolkit.py client' to run the client.")

    # === LAB 6 EXAMPLES ===
    # print("\n--- LAB 6 ---")
    # # RSA Digital Signature
    # print("\n--- RSA Signature ---")
    # rsa_pub_sign, rsa_priv_sign = generate_rsa_keys()
    # msg_to_sign = "This message needs a signature."
    # signature = rsa_sign(msg_to_sign, rsa_priv_sign)
    # print(f"Signature created: {signature.hex()}")
    # is_valid = rsa_verify(msg_to_sign, signature, rsa_pub_sign)
    # print(f"Is signature valid? {is_valid}")
    # # Test with wrong message
    # is_valid_tampered = rsa_verify("This is a different message.", signature, rsa_pub_sign)
    # print(f"Is tampered signature valid? {is_valid_tampered}")

    # # ElGamal Digital Signature
    # print("\n--- ElGamal Signature ---")
    # elg_pub_sign, elg_priv_sign = generate_elgamal_keys()
    # signature_elg = elgamal_sign(msg_to_sign, elg_pub_sign, elg_priv_sign)
    # print(f"ElGamal signature (r,s): {signature_elg}")
    # is_valid_elg = elgamal_verify(msg_to_sign, signature_elg, elg_pub_sign)
    # print(f"Is ElGamal signature valid? {is_valid_elg}")