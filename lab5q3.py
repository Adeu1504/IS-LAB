# Design a Python-based experiment to analyze the performance of MD5, SHA-1, and
# SHA-256 hashing techniques in terms of computation time and collision resistance.
# Generate a dataset of random strings ranging from 50 to 100 strings, compute the hash
# values using each hashing technique, and measure the time taken for hash computation.
# Implement collision detection algorithms to identify any collisions within the hashed dataset

import hashlib
import time
import random
import string


def generate_random_strings(num_strings, min_length=100, max_length=1000):
    """
    Generates a list of random strings.

    Args:
        num_strings (int): The number of strings to generate.
        min_length (int): The minimum length of each string.
        max_length (int): The maximum length of each string.

    Returns:
        list: A list of randomly generated strings.
    """
    strings = []
    characters = string.ascii_letters + string.digits + string.punctuation
    for _ in range(num_strings):
        length = random.randint(min_length, max_length)
        random_string = ''.join(random.choice(characters) for _ in range(length))
        strings.append(random_string)
    return strings


def measure_hashing_time(data, hash_algorithm):
    """
    Measures the time taken to hash a list of data using a specified algorithm.

    Args:
        data (list): A list of strings to hash.
        hash_algorithm (function): The hashing function from the hashlib module (e.g., hashlib.md5).

    Returns:
        tuple: A tuple containing the list of hash values and the time taken.
    """
    start_time = time.time()
    hash_values = [hash_algorithm(s.encode('utf-8')).hexdigest() for s in data]
    end_time = time.time()
    time_taken = end_time - start_time
    return hash_values, time_taken


def detect_collisions(hash_values):
    """
    Detects collisions in a list of hash values.

    Args:
        hash_values (list): A list of hash values.

    Returns:
        dict: A dictionary where keys are the hash values and values are lists of
              indices in the original dataset that produced that hash.
    """
    collisions = {}
    for i, hash_val in enumerate(hash_values):
        if hash_val in collisions:
            collisions[hash_val].append(i)
        else:
            collisions[hash_val] = [i]

    # Filter out hashes that didn't have collisions (i.e., list length is 1)
    return {k: v for k, v in collisions.items() if len(v) > 1}


def run_experiment(num_strings=1000):
    """
    Main function to run the hashing experiment.
    """
    print("--- Hashing Algorithm Performance Analysis ---")
    print(f"Generating a dataset of {num_strings} random strings...")
    data = generate_random_strings(num_strings)
    print("Dataset generation complete.\n")

    # --- MD5 Analysis ---
    print("--- Analyzing MD5 ---")
    md5_hashes, md5_time = measure_hashing_time(data, hashlib.md5)
    md5_collisions = detect_collisions(md5_hashes)
    print(f"Time taken to compute {num_strings} MD5 hashes: {md5_time:.6f} seconds")
    print(f"Number of MD5 collisions detected: {len(md5_collisions)}")
    if md5_collisions:
        print("MD5 Collisions found. Here are a few examples:")
        for k, v in list(md5_collisions.items())[:3]:
            print(f"  - Hash: {k}, Original indices: {v}")
    print("-" * 25 + "\n")

    # --- SHA-1 Analysis ---
    print("--- Analyzing SHA-1 ---")
    sha1_hashes, sha1_time = measure_hashing_time(data, hashlib.sha1)
    sha1_collisions = detect_collisions(sha1_hashes)
    print(f"Time taken to compute {num_strings} SHA-1 hashes: {sha1_time:.6f} seconds")
    print(f"Number of SHA-1 collisions detected: {len(sha1_collisions)}")
    if sha1_collisions:
        print("SHA-1 Collisions found. Here are a few examples:")
        for k, v in list(sha1_collisions.items())[:3]:
            print(f"  - Hash: {k}, Original indices: {v}")
    print("-" * 25 + "\n")

    # --- SHA-256 Analysis ---
    print("--- Analyzing SHA-256 ---")
    sha256_hashes, sha256_time = measure_hashing_time(data, hashlib.sha256)
    sha256_collisions = detect_collisions(sha256_hashes)
    print(f"Time taken to compute {num_strings} SHA-256 hashes: {sha256_time:.6f} seconds")
    print(f"Number of SHA-256 collisions detected: {len(sha256_collisions)}")
    if sha256_collisions:
        print("SHA-256 Collisions found. Here are a few examples:")
        for k, v in list(sha256_collisions.items())[:3]:
            print(f"  - Hash: {k}, Original indices: {v}")
    print("-" * 25 + "\n")

    # --- Summary ---
    print("--- Experiment Summary ---")
    print(f"| Algorithm | Computation Time (s) | Collisions Detected |")
    print(f"|-----------|----------------------|---------------------|")
    print(f"| MD5       | {md5_time:.6f}       | {len(md5_collisions):<19}|")
    print(f"| SHA-1     | {sha1_time:.6f}       | {len(sha1_collisions):<19}|")
    print(f"| SHA-256   | {sha256_time:.6f}       | {len(sha256_collisions):<19}|")
    print("\nNote: The number of collisions is expected to be 0 for these algorithms with a small dataset.")


if __name__ == "__main__":
    # You can change the number of strings to see how the performance scales.
    # A larger number of strings (e.g., 100000) will show a more pronounced time difference.
    # Note: For a dataset of 50-100 strings, collisions are extremely unlikely.
    # To demonstrate collisions, you would need to run a birthday attack-style experiment,
    # which is a different, more complex setup.
    run_experiment(num_strings=100)