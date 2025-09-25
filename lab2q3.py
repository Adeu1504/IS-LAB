# Compare the encryption and decryption times for DES and AES-256 for the
# message "Performance Testing of Encryption Algorithms". Use a standard
# implementation and report your findings.

import time
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.Util.Padding import pad


def benchmark_symmetric_algorithm(cipher_module, key_size_bytes, data, iterations):
    """
    Benchmarks symmetric block ciphers like AES and DES.
    This version is corrected to use separate cipher objects for decryption.
    """
    key = os.urandom(key_size_bytes)
    iv = os.urandom(cipher_module.block_size)
    padded_data = pad(data, cipher_module.block_size)

    # --- Encryption Test ---
    # Create a cipher object specifically for encryption
    encrypt_cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv=iv)

    start_encrypt = time.perf_counter_ns()
    for _ in range(iterations):
        encrypt_cipher.encrypt(padded_data)
    end_encrypt = time.perf_counter_ns()

    # --- Decryption Test ---
    # Get a single block of encrypted data to use for the test
    encrypted_data = encrypt_cipher.encrypt(padded_data)

    # FIX: Create a NEW, separate cipher object for decryption
    decrypt_cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv=iv)

    start_decrypt = time.perf_counter_ns()
    for _ in range(iterations):
        # Use the new decryption cipher
        decrypt_cipher.decrypt(encrypted_data)
    end_decrypt = time.perf_counter_ns()

    avg_encrypt_time = (end_encrypt - start_encrypt) / iterations / 1000
    avg_decrypt_time = (end_decrypt - start_decrypt) / iterations / 1000
    return avg_encrypt_time, avg_decrypt_time


def benchmark_asymmetric_algorithm(cipher_module, key_size_bits, data, iterations):
    """
    Benchmarks asymmetric ciphers like RSA.
    Note: RSA has a small message size limit.
    """
    # 1. Generate a public/private key pair
    private_key = cipher_module.generate(key_size_bits)
    public_key = private_key.publickey()

    # 2. Create encryptor and decryptor objects with the keys
    encryptor = PKCS1_OAEP.new(public_key)
    decryptor = PKCS1_OAEP.new(private_key)

    # Time encryption
    start_encrypt = time.perf_counter_ns()
    for _ in range(iterations):
        encryptor.encrypt(data)
    end_encrypt = time.perf_counter_ns()

    # Time decryption
    encrypted_data = encryptor.encrypt(data)
    start_decrypt = time.perf_counter_ns()
    for _ in range(iterations):
        decryptor.decrypt(encrypted_data)
    end_decrypt = time.perf_counter_ns()

    avg_encrypt_time = (end_encrypt - start_encrypt) / iterations / 1000
    avg_decrypt_time = (end_decrypt - start_decrypt) / iterations / 1000
    return avg_encrypt_time, avg_decrypt_time


def print_results(results):
    """Formats and prints the performance benchmark results."""
    print("\n--- Performance Results (Average per operation) ---")
    print("=" * 60)
    print(f"| {'Algorithm':<14} | {'Encryption Time (µs)':<22} | {'Decryption Time (µs)':<22} |")
    print("-" * 60)
    for name, times in results.items():
        encrypt_time, decrypt_time = times
        print(f"| {name:<14} | {encrypt_time:<22.4f} | {decrypt_time:<22.4f} |")
    print("=" * 60)
    print("\n* µs = microseconds (one millionth of a second)")


# --- Main Execution Block ---
if __name__ == "__main__":
    ITERATIONS_SYM = 10000  # More iterations for fast symmetric ciphers
    ITERATIONS_ASYM = 100  # Fewer iterations for slow asymmetric ciphers

    # Define messages for each cipher type
    SYM_MESSAGE = b"Performance Testing of Encryption Algorithms"
    ASYM_MESSAGE = b"This is a test."  # Must be small for RSA!

    # Structure: { 'Name': (Type, Module, KeySize) }
    algorithms_to_test = {
        'DES': ('symmetric', DES, 8),  # Key size in bytes
        'AES-256': ('symmetric', AES, 32),  # Key size in bytes
        'RSA-2048': ('asymmetric', RSA, 2048)  # Key size in bits
    }

    performance_results = {}
    print("Running benchmarks...")

    for name, (algo_type, module, key_size) in algorithms_to_test.items():
        print(f"Testing {name}...")
        if algo_type == 'symmetric':
            e_time, d_time = benchmark_symmetric_algorithm(module, key_size, SYM_MESSAGE, ITERATIONS_SYM)
        elif algo_type == 'asymmetric':
            e_time, d_time = benchmark_asymmetric_algorithm(module, key_size, ASYM_MESSAGE, ITERATIONS_ASYM)
        else:
            print(f"Skipping unknown algorithm type: {algo_type}")
            continue
        performance_results[name] = (e_time, d_time)

    print("\n... All tests complete.")
    print_results(performance_results)