import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import re


# -------------------------------------------------
# --- 1. The SimpleSSE Class (Core Logic) ---
# -------------------------------------------------

class SimpleSSE:
    """
    An easy-to-use class for the Symmetric Searchable Encryption lab.

    It handles key generation, index building, and searching internally.
    """

    def __init__(self):
        """Generates a secret key and initializes storage."""
        self.key = get_random_bytes(16)  # 128-bit key
        self.encrypted_index = {}
        self.documents = []

    # --- Internal (Private) Helper Methods ---

    def _tokenize(self, text):
        """Cleans and splits text into words."""
        text = text.lower()
        return re.findall(r'\b\w+\b', text)

    def _encrypt_word_deterministic(self, word):
        """Deterministically encrypts a word (for index keys)."""
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(word.encode('utf-8'), AES.block_size))

    def _encrypt_data_probabilistic(self, data):
        """Probabilistically encrypts data (for index values)."""
        # Convert list of IDs (e.g., [1, 5]) to a string ("1,5")
        data_str = ",".join(map(str, data))
        data_bytes = data_str.encode('utf-8')

        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Prepend IV to the ciphertext for decryption
        return iv + cipher.encrypt(pad(data_bytes, AES.block_size))

    def _decrypt_data_probabilistic(self, encrypted_data):
        """Decrypts the probabilistic data."""
        try:
            # Extract the IV (first 16 bytes)
            iv = encrypted_data[:AES.block_size]
            ciphertext = encrypted_data[AES.block_size:]

            cipher = AES.new(self.key, AES.MODE_CBC, iv)

            # Decrypt, unpad, and decode
            decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            decrypted_str = decrypted_bytes.decode('utf-8')

            # Convert the string (e.g., "1,5") back to a list of ints
            return [int(id_str) for id_str in decrypted_str.split(',')]
        except (ValueError, KeyError):
            print("Error: Decryption failed.")
            return []

    # --- Public (Easy-to-Use) Methods ---

    def build_index(self, documents):
        """
        Builds the encrypted index from a list of cleartext documents.
        (Corresponds to Lab Exercise 1c)
        """
        print("Building encrypted index...")
        self.documents = documents
        inverted_index = {}

        # 1. Create cleartext inverted index
        for doc_id, doc_text in enumerate(self.documents):
            for word in self._tokenize(doc_text):
                if word not in inverted_index:
                    inverted_index[word] = set()
                inverted_index[word].add(doc_id)

        # 2. Encrypt the inverted index
        self.encrypted_index = {}
        for word, doc_ids in inverted_index.items():
            # Encrypt the word (key)
            encrypted_word = self._encrypt_word_deterministic(word)
            # Encrypt the document list (value)
            encrypted_id_list = self._encrypt_data_probabilistic(list(doc_ids))

            self.encrypted_index[encrypted_word] = encrypted_id_list

        print(f"Index built successfully. {len(self.encrypted_index)} terms encrypted.")

    def search(self, query):
        """
        Searches the encrypted index for a query.
        Returns the matching cleartext documents.
        (Corresponds to Lab Exercise 1d)
        """
        print(f"\n--- Searching for: '{query}' ---")

        # 1. Encrypt the query (deterministically)
        encrypted_query = self._encrypt_word_deterministic(query.lower().strip())

        # 2. Search the encrypted index
        if encrypted_query in self.encrypted_index:
            print("... Found matching encrypted term.")

            # 3. Retrieve and decrypt the document IDs
            encrypted_ids = self.encrypted_index[encrypted_query]
            decrypted_doc_ids = self._decrypt_data_probabilistic(encrypted_ids)

            if not decrypted_doc_ids:
                return []

            print(f"... Decrypted document IDs: {decrypted_doc_ids}")

            # 4. Fetch and display the original documents
            results = []
            print("\n--- Matching Documents ---")
            for doc_id in decrypted_doc_ids:
                doc_text = self.documents[doc_id]
                print(f"Doc {doc_id}: {doc_text}")
                results.append(doc_text)
            return results

        else:
            print("... No matching encrypted term found.")
            print("\n--- No Results ---")
            return []


# -------------------------------------------------
# --- 2. Menu-Driven Application Logic ---
# -------------------------------------------------

def display_documents(docs):
    """Helper function to print all loaded documents."""
    print("\n--- All Current Documents ---")
    if not docs:
        print("No documents are loaded.")
        return

    for i, doc in enumerate(docs):
        print(f"Doc {i}: {doc}")


def main():
    """Runs the main menu-driven application."""

    # 1a. Your dataset
    documents = [
        "The quick brown fox jumps over the lazy dog",  # Doc 0
        "A quick brown dog jumps over a lazy cat",  # Doc 1
        "Never jump over the lazy dog quickly",  # Doc 2
        "A lazy cat and a lazy dog",  # Doc 3
        "The fox is quick and the dog is lazy",  # Doc 4
        "Cryptography is a key part of security",  # Doc 5
        "Searchable encryption is a cool topic",  # Doc 6
        "This lab demonstrates a basic SSE scheme",  # Doc 7
        "We use AES for this encryption scheme",  # Doc 8
        "A key is used for AES encryption"  # Doc 9
    ]

    # 1. Initialize the SSE system
    sse_system = SimpleSSE()

    # 2. Build the index immediately
    sse_system.build_index(documents)

    print("\nWelcome to the Simple SSE Lab Program!")

    # 3. Start the main menu loop
    while True:
        print("\n" + "=" * 30)
        print("          MAIN MENU          ")
        print("=" * 30)
        print("1. 🔍 Search for a word")
        print("2. 📄 View all documents")
        print("3. 🚪 Exit")
        print("=" * 30)

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            query = input("Enter word to search for: ")
            if query:
                sse_system.search(query)
            else:
                print("Search query cannot be empty.")

        elif choice == '2':
            display_documents(sse_system.documents)

        elif choice == '3':
            print("\nGoodbye!")
            break  # Exit the while loop

        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")


# -------------------------------------------------
# --- 3. Start the Program ---
# -------------------------------------------------

if __name__ == "__main__":
    main()