import time
from collections import defaultdict
from phe import paillier  # pip install python-phe


# --- Server-Side Simulation ---
# This function would "run on the server"
def search_encrypted_index(query, index):
    """
    Simulates the server searching the index.
    It only has access to the encrypted index.
    """
    print(f"\n... Server: Received search query '{query}'")
    # As discussed in the previous lab, the query must be plaintext
    # to find the key in the inverted index.
    if query in index:
        print("... Server: Found matching term. Returning encrypted document list.")
        # Returns the list of encrypted document IDs
        return index[query]
    else:
        print("... Server: Term not found.")
        return []


# --- Client-Side Simulation ---
# These functions would "run on the client"
def client_search_and_decrypt(query, encrypted_index, public_key, private_key):
    """
    Simulates the client initiating a search and decrypting the results.
    """
    print(f"\nClient: Initiating search for '{query}'...")

    # 1. Client sends the *plaintext* query to the server.
    #    The server searches and returns the encrypted results.
    encrypted_results = search_encrypted_index(query, encrypted_index)

    # 2. Client receives encrypted results and decrypts with private key.
    if not encrypted_results:
        print("Client: Received no results.")
        return []

    print(f"Client: Received {len(encrypted_results)} encrypted result(s). Decrypting...")

    start_time = time.time()
    try:
        # Decrypt each encrypted ID using the private key
        decrypted_doc_ids = [private_key.decrypt(enc_id) for enc_id in encrypted_results]
        end_time = time.time()
        print(f"Client: Decryption complete. Took {end_time - start_time:.4f} seconds.")
        return sorted(decrypted_doc_ids)
    except Exception as e:
        print(f"Client: An error occurred during decryption: {e}")
        return []


# --- Utility Functions ---
def view_documents(documents):
    """Displays the plaintext documents."""
    print("\n--- Plaintext Document Corpus ---")
    if not documents:
        print("No documents loaded.")
        return
    for i, doc in enumerate(documents):
        print(f"  Doc {i}: {doc}")
    print("---------------------------------")


def view_plaintext_index(plaintext_index):
    """Displays the plaintext inverted index for verification."""
    print("\n--- Plaintext Inverted Index (For Verification) ---")
    if not plaintext_index:
        print("Index not built.")
        return
    for word, doc_ids in sorted(plaintext_index.items()):
        print(f"  '{word}' -> {doc_ids}")
    print("---------------------------------------------------")


# --- Main Setup ---
def setup_environment():
    """
    Runs once to create dataset, keys, and encrypted index.
    """
    print("Setting up the PKSE environment. This may take a moment...")

    # 2a. Create dataset
    documents = [
        "The cloud is a network of servers",  # Doc 0
        "Cloud computing provides services over the internet",  # Doc 1
        "A server is a powerful computer",  # Doc 2
        "This lab is about public key searchable encryption",  # Doc 3
        "We use the Paillier cryptosystem",  # Doc 4
        "Paillier is an additively homomorphic cryptosystem",  # Doc 5
        "Homomorphic encryption allows computation on ciphertexts",  # Doc 6
        "Searchable encryption is a key feature",  # Doc 7
        "The private key decrypts the data",  # Doc 8
        "The public key encrypts the data"  # Doc 9
    ]

    # 2b. Generate Keys
    print("  Generating Paillier keypair (1024-bit)...")
    start_key = time.time()
    public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
    print(f"  Key generation complete. ({time.time() - start_key:.2f}s)")

    # 2c. Create index
    print("  Building plaintext inverted index...")
    plaintext_index = defaultdict(list)
    for doc_id, doc in enumerate(documents):
        words = set(doc.lower().split())
        for word in words:
            plaintext_index[word].append(doc_id)

    print("  Encrypting index values...")
    encrypted_index = defaultdict(list)
    start_encrypt = time.time()
    for word, doc_ids in plaintext_index.items():
        encrypted_ids = [public_key.encrypt(doc_id) for doc_id in doc_ids]
        encrypted_index[word] = encrypted_ids
    print(f"  Index encryption complete. ({time.time() - start_encrypt:.2f}s)")

    print("\nSetup complete. The server has the encrypted index and public key.")
    print("The client has the private key.")

    return documents, plaintext_index, encrypted_index, public_key, private_key


# --- Main Menu Loop ---
def main_menu():
    """
    Runs the main user-facing menu.
    """
    # Run the one-time setup
    (documents,
     plaintext_index,
     encrypted_index,
     public_key,
     private_key) = setup_environment()

    while True:
        print("\n" + "=" * 30)
        print("   Paillier PKSE Lab Menu")
        print("=" * 30)
        print("1. Search for a word")
        print("2. View all plaintext documents")
        print("3. View plaintext index (for verification)")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == '1':
            # 2d. Implement Search
            query = input("Enter a word to search for: ").strip().lower()
            if not query:
                print("Search term cannot be empty.")
                continue

            # This function simulates the client-server interaction
            results = client_search_and_decrypt(
                query,
                encrypted_index,
                public_key,
                private_key
            )

            if results:
                print(f"\n---> Final Result for '{query}': Documents {results}")
            else:
                print(f"\n---> Final Result for '{query}': No documents found.")

        elif choice == '2':
            view_documents(documents)

        elif choice == '3':
            view_plaintext_index(plaintext_index)

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter a number from 1 to 4.")


# Run the program
if __name__ == "__main__":
    main_menu()