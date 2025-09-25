# 1. Using DES and AES (128, 192, and 256 bits key).encrypt the five different messages
# using same key.
# a. Consider different modes of operation
# b. Plot the graph which shows execution time taken by each technique.
# c. Compare time taken by different modes of operation

import time
import os
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad
import matplotlib.pyplot as plt
import numpy as np


# --- 1. Core Logic Functions ---

def define_crypto_params():
    """
    Defines the cryptographic algorithms and modes to be tested.

    Returns:
        tuple: A tuple containing two dictionaries (algorithms, modes).
    """
    algorithms = {
        'DES': DES,
        'AES-128': AES,
        'AES-192': AES,
        'AES-256': AES
    }
    modes = {
        'ECB': AES.MODE_ECB,
        'CBC': AES.MODE_CBC,
        'CFB': AES.MODE_CFB,
        'OFB': AES.MODE_OFB,
        'CTR': AES.MODE_CTR
    }
    return algorithms, modes


def generate_keys(algorithms):
    """
    Generates and returns a dictionary of secure random keys for each algorithm.

    Args:
        algorithms (dict): A dictionary of algorithm names and their classes.

    Returns:
        dict: A dictionary of algorithm names and their corresponding keys.
    """
    keys = {
        'DES': os.urandom(8),
        'AES-128': os.urandom(16),
        'AES-192': os.urandom(24),
        'AES-256': os.urandom(32)
    }
    return keys


def run_benchmark(messages, algorithms, modes, keys):
    """
    Runs the encryption benchmark for the given parameters.

    Args:
        messages (list): A list of byte strings to encrypt.
        algorithms (dict): Dictionary of algorithms to test.
        modes (dict): Dictionary of modes to test.
        keys (dict): Dictionary of keys to use for encryption.

    Returns:
        dict: A nested dictionary with the timing results in milliseconds.
    """
    results = {}
    print("Starting encryption performance benchmark...")

    for algo_name, algo_class in algorithms.items():
        results[algo_name] = {}
        key = keys[algo_name]
        block_size = algo_class.block_size

        for mode_name, mode_val in modes.items():
            if algo_name == 'DES' and mode_name == 'CTR':
                continue  # Skip unsupported combination

            start_time = time.perf_counter()
            for message in messages:
                padded_message = pad(message, block_size)

                if mode_name == 'ECB':
                    cipher = algo_class.new(key, mode_val)
                elif mode_name == 'CTR':
                    nonce = os.urandom(block_size // 2)
                    cipher = algo_class.new(key, mode_val, nonce=nonce)
                else:
                    iv = os.urandom(block_size)
                    cipher = algo_class.new(key, mode_val, iv=iv)

                _ = cipher.encrypt(padded_message)

            end_time = time.perf_counter()
            total_time = (end_time - start_time) * 1000  # Convert to ms
            results[algo_name][mode_name] = total_time

    print("Benchmark completed.")
    return results


# --- 2. Reporting and Plotting Functions ---

def print_summary(results):
    """
    Prints a formatted summary of the benchmark results to the console.

    Args:
        results (dict): The results dictionary from run_benchmark.
    """
    if not results:
        print("No results to display.")
        return

    print("\n--- Benchmark Summary (Execution Time in ms) ---")
    for algo_name, timings in results.items():
        print(f"\nAlgorithm: {algo_name}")
        for mode_name, exec_time in timings.items():
            print(f"  - {mode_name:<5}: {exec_time:.4f} ms")
    print("--------------------------------------------------")


def plot_by_algorithm(results):
    """
    Plots a bar chart comparing the average performance of each algorithm.

    Args:
        results (dict): The results dictionary from run_benchmark.
    """
    avg_times = {
        algo: np.mean(list(timings.values())) for algo, timings in results.items()
    }
    algo_names = list(avg_times.keys())
    avg_values = list(avg_times.values())

    plt.figure(figsize=(10, 6))
    plt.bar(algo_names, avg_values, color=['skyblue', 'salmon', 'lightgreen', 'plum'])
    plt.xlabel("Encryption Technique")
    plt.ylabel("Average Execution Time (ms)")
    plt.title("Comparison of Encryption Technique Performance (Averaged Across Modes)")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()


def plot_by_mode(results, modes):
    """
    Plots a grouped bar chart comparing performance by mode of operation.

    Args:
        results (dict): The results dictionary from run_benchmark.
        modes (dict): The dictionary of modes used in the benchmark.
    """
    mode_names = list(modes.keys())
    x = np.arange(len(mode_names))
    width = 0.2

    fig, ax = plt.subplots(figsize=(14, 8))
    ax.bar(x - 1.5 * width, [results.get('DES', {}).get(m, 0) for m in mode_names], width, label='DES')
    ax.bar(x - 0.5 * width, [results.get('AES-128', {}).get(m, 0) for m in mode_names], width, label='AES-128')
    ax.bar(x + 0.5 * width, [results.get('AES-192', {}).get(m, 0) for m in mode_names], width, label='AES-192')
    ax.bar(x + 1.5 * width, [results.get('AES-256', {}).get(m, 0) for m in mode_names], width, label='AES-256')

    ax.set_ylabel('Total Execution Time (ms)')
    ax.set_title('Encryption Time by Mode of Operation and Algorithm')
    ax.set_xticks(x)
    ax.set_xticklabels(mode_names)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    fig.tight_layout()
    plt.show()


# --- 3. Main Execution Block ---

if __name__ == "__main__":
    # Define the data to be encrypted
    default_messages = [
        b"This is a short test message.",
        b"This is a slightly longer message to test encryption performance.",
        b"Cryptography is the practice and study of techniques for secure communication.",
        b"AES is a subset of the Rijndael block cipher developed by Vincent Rijmen and Joan Daemen.",
        b"This is the longest message, designed to provide a more substantial workload for the algorithms."
    ]

    # 1. Set up cryptographic parameters and keys
    algorithms_to_test, modes_to_test = define_crypto_params()
    encryption_keys = generate_keys(algorithms_to_test)

    # 2. Run the core benchmark function
    benchmark_results = run_benchmark(
        default_messages,
        algorithms_to_test,
        modes_to_test,
        encryption_keys
    )

    # 3. Report the results
    print_summary(benchmark_results)

    # 4. Plot the results
    print("\nGenerating plots...")
    if benchmark_results:
        plot_by_algorithm(benchmark_results)
        plot_by_mode(benchmark_results, modes_to_test)