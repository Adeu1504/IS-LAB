import client_toolkit_universal as remote_crypto
import numpy as np


def run_client_demo():
    try:
        print("--- DEMO: LAB 1 (HILL CIPHER) ---")
        plain_hill = "WELIVEINANINSECUREWORLD"
        key_hill = np.array([[3, 3], [2, 7]])

        print(f"Client: Asking server to encrypt '{plain_hill}'...")
        encrypted = remote_crypto.remote_hill_cipher(plain_hill, key_hill, 'encrypt')
        print(f"Server returned: {encrypted}")

        print(f"Client: Asking server to decrypt '{encrypted}'...")
        decrypted = remote_crypto.remote_hill_cipher(encrypted, key_hill, 'decrypt')
        print(f"Server returned: {decrypted}")
        print("-" * 20 + "\n")

        print("--- DEMO: LAB 3/4 (RSA SIGN/VERIFY) ---")
        print("Client: Asking server to generate RSA keys...")
        priv_key, pub_key = remote_crypto.remote_rsa_generate_keys(1024)
        print("Server returned keys successfully.")

        msg_to_sign = b"This is an authentic message."
        print(f"Client: Asking server to sign '{msg_to_sign.decode()}'...")

        # We send our private key (BAD security, but good for this lab)
        signature = remote_crypto.remote_rsa_sign(priv_key, msg_to_sign)
        print(f"Server returned signature: {signature.hex()[:20]}...")

        print("Client: Asking server to verify the signature...")
        # We send the public key, data, and signature
        is_valid = remote_crypto.remote_rsa_verify(pub_key, msg_to_sign, signature)
        print(f"Server confirmed signature is valid: {is_valid}")
        print("-" * 20 + "\n")

        print("--- DEMO: LAB 7 (PAILLIER) ---")
        print("Client: Asking server to generate Paillier keys...")
        # These are real, usable 'phe' objects!
        paillier_pub, paillier_priv = remote_crypto.remote_paillier_generate_keys(1024)
        print("Server returned Paillier keys successfully.")

        num1 = 15
        num2 = 25
        print(f"Client: Asking server to encrypt {num1}...")
        enc_num1 = remote_crypto.remote_paillier_encrypt(paillier_pub, num1)

        print(f"Client: Asking server to encrypt {num2}...")
        enc_num2 = remote_crypto.remote_paillier_encrypt(paillier_pub, num2)

        print("Client: Performing local homomorphic addition...")
        enc_sum = enc_num1 + enc_num2  # This is local

        print("Client: Asking server to decrypt the sum...")
        decrypted_sum = remote_crypto.remote_paillier_decrypt(paillier_priv, enc_sum)
        print(f"Server decrypted sum: {decrypted_sum}")
        print(f"Success: {decrypted_sum == num1 + num2}")
        print("-" * 20 + "\n")

        print("--- DEMO: LAB 8 (SSE) ---")
        docs = {
            "doc1": "this is a document with some words",
            "doc2": "another document with different words",
        }
        print("Client: Asking server to generate an SSE key...")
        sse_key = remote_crypto.remote_sse_generate_key()

        print("Client: Asking server to create an SSE index...")
        sse_index = remote_crypto.remote_sse_create_index(sse_key, docs)

        print("Client: Asking server to search for 'document'...")
        results = remote_crypto.remote_sse_search(sse_key, sse_index, "document")
        print(f"Server returned results: {results}")
        print("-" * 20 + "\n")

    except Exception as e:
        print(f"\n*** CLIENT-SIDE ERROR ***\n{e}")


if __name__ == "__main__":
    run_client_demo()