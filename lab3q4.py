# Design and implement a secure file transfer system using RSA (2048-bit) and ECC
# (secp256r1 curve) public key algorithms. Generate and exchange keys, then
# encrypt and decrypt files of varying sizes (e.g., 1 MB, 10 MB) using both
# algorithms. Measure and compare the performance in terms of key generation
# time, encryption/decryption speed, and computational overhead. Evaluate the
# security and efficiency of each algorithm in the context of file transfer, considering
# 19
# factors such as key size, storage requirements, and resistance to known attacks.
# Document your findings, including performance metrics and a summary of the
# strengths and weaknesses of RSA and ECC for secure file transfer.

import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# --- Helper Functions ---
def generate_dummy_file(filename, size_mb):
    """Creates a file of a specific size in MB with random data."""
    print(f"Creating a dummy file: {filename} ({size_mb} MB)...")
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_mb * 1024 * 1024))
    print("File created.")


def get_file_size(filename):
    """Returns file size in a human-readable format."""
    size_bytes = os.path.getsize(filename)
    if size_bytes > 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / 1024:.2f} KB"


# --- RSA Implementation ---
def rsa_generate_keys():
    """Generates 2048-bit RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_file(public_key, file_path, out_file_path):
    """Encrypts a file using a hybrid RSA-AES scheme."""
    # 1. Generate a one-time AES-256 key
    aes_key = os.urandom(32)  # 256 bits
    iv = os.urandom(16)  # 96 bits is common for GCM, but 128 is also fine

    # 2. Encrypt the file with AES-GCM
    with open(file_path, 'rb') as f:
        file_data = f.read()

    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_aes.encryptor()
    encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    # 3. Encrypt the AES key with RSA-OAEP
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Write to an output file
    with open(out_file_path, 'wb') as f:
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(tag)
        f.write(encrypted_file_data)


def rsa_decrypt_file(private_key, encrypted_file_path, out_file_path):
    """Decrypts a file using a hybrid RSA-AES scheme."""
    with open(encrypted_file_path, 'rb') as f:
        encrypted_aes_key = f.read(256)  # 2048 bits / 8 = 256 bytes
        iv = f.read(16)
        tag = f.read(16)
        encrypted_file_data = f.read()

    # 1. Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Decrypt the file with AES-GCM
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher_aes.decryptor()
    decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

    with open(out_file_path, 'wb') as f:
        f.write(decrypted_file_data)


# --- ECC (ECIES) Implementation ---
def ecc_generate_keys():
    """Generates secp256r1 ECC private and public keys."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def ecc_encrypt_file(public_key, file_path, out_file_path):
    """Encrypts a file using a hybrid ECC-AES scheme (ECIES)."""
    # 1. Generate an ephemeral ECC key pair for ECDH
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # 2. Perform ECDH to get a shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # 3. Derive a symmetric key from the shared secret using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key
        salt=None,
        info=b'ecies-encryption',
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_secret)

    # 4. Encrypt the file with AES-GCM
    iv = os.urandom(16)
    with open(file_path, 'rb') as f:
        file_data = f.read()

    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_aes.encryptor()
    encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    # 5. Serialize the ephemeral public key to send it
    ephemeral_public_key_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 6. Write to an output file
    with open(out_file_path, 'wb') as f:
        f.write(len(ephemeral_public_key_bytes).to_bytes(2, 'big'))  # 2 bytes for key length
        f.write(ephemeral_public_key_bytes)
        f.write(iv)
        f.write(tag)
        f.write(encrypted_file_data)


def ecc_decrypt_file(private_key, encrypted_file_path, out_file_path):
    """Decrypts a file using a hybrid ECC-AES scheme (ECIES)."""
    with open(encrypted_file_path, 'rb') as f:
        ephemeral_public_key_len = int.from_bytes(f.read(2), 'big')
        ephemeral_public_key_bytes = f.read(ephemeral_public_key_len)
        iv = f.read(16)
        tag = f.read(16)
        encrypted_file_data = f.read()

    # 1. Load the ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_bytes, backend=default_backend())

    # 2. Recreate the same shared secret with ECDH
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # 3. Derive the same symmetric key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-encryption',
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_secret)

    # 4. Decrypt the file with AES-GCM
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher_aes.decryptor()
    decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

    with open(out_file_path, 'wb') as f:
        f.write(decrypted_file_data)


# --- Main Benchmark Execution ---
if __name__ == "__main__":
    file_sizes_mb = [1, 10]
    dummy_files = [f"dummy_{size}mb.bin" for size in file_sizes_mb]

    for i, size in enumerate(file_sizes_mb):
        generate_dummy_file(dummy_files[i], size)

    results = []

    # --- RSA Benchmark ---
    print("\n--- Benchmarking RSA-2048 ---")
    start_time = time.perf_counter()
    rsa_priv, rsa_pub = rsa_generate_keys()
    rsa_key_gen_time = time.perf_counter() - start_time

    for file in dummy_files:
        enc_file = "rsa_encrypted.bin"
        dec_file = "rsa_decrypted.bin"

        start_time = time.perf_counter()
        rsa_encrypt_file(rsa_pub, file, enc_file)
        rsa_enc_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        rsa_decrypt_file(rsa_priv, enc_file, dec_file)
        rsa_dec_time = time.perf_counter() - start_time

        results.append({
            "Algorithm": "RSA-2048",
            "File Size": get_file_size(file),
            "Key Gen Time (s)": f"{rsa_key_gen_time:.6f}",
            "Encryption Time (s)": f"{rsa_enc_time:.6f}",
            "Decryption Time (s)": f"{rsa_dec_time:.6f}"
        })
        os.remove(enc_file)
        os.remove(dec_file)

    # --- ECC Benchmark ---
    print("\n--- Benchmarking ECC (secp256r1) ---")
    start_time = time.perf_counter()
    ecc_priv, ecc_pub = ecc_generate_keys()
    ecc_key_gen_time = time.perf_counter() - start_time

    for file in dummy_files:
        enc_file = "ecc_encrypted.bin"
        dec_file = "ecc_decrypted.bin"

        start_time = time.perf_counter()
        ecc_encrypt_file(ecc_pub, file, enc_file)
        ecc_enc_time = time.perf_counter() - start_time

        start_time = time.perf_counter()
        ecc_decrypt_file(ecc_priv, enc_file, dec_file)
        ecc_dec_time = time.perf_counter() - start_time

        results.append({
            "Algorithm": "ECC (secp256r1)",
            "File Size": get_file_size(file),
            "Key Gen Time (s)": f"{ecc_key_gen_time:.6f}",
            "Encryption Time (s)": f"{ecc_enc_time:.6f}",
            "Decryption Time (s)": f"{ecc_dec_time:.6f}"
        })
        os.remove(enc_file)
        os.remove(dec_file)

    # --- Cleanup and Reporting ---
    for file in dummy_files:
        os.remove(file)

    print("\n--- BENCHMARK RESULTS ---")
    header = results[0].keys()
    rows = [list(r.values()) for r in results]
    col_widths = [max(len(str(x)) for x in col) for col in zip(*([header] + rows))]

    header_line = " | ".join(h.ljust(w) for h, w in zip(header, col_widths))
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        print(" | ".join(str(r).ljust(w) for r, w in zip(row, col_widths)))