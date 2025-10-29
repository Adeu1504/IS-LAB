import socket
import pickle
import sys
from phe import paillier

# --- Configuration ---
HOST = 'localhost'
PORT = 9999


#
# This is the EXACT same function from seller.py
#
def run_seller(seller_name, transactions):
    """Main client function to connect, encrypt, and send data for ONE seller."""

    print(f"\n--- Processing for: {seller_name} ---")
    print(f"Transactions: {transactions}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # 1. Connect to the gateway
            client_socket.connect((HOST, PORT))
            print("Connected to Payment Gateway.")

            # 2. Receive the Paillier public key
            data = client_socket.recv(4096)
            paillier_pubkey = pickle.loads(data)
            print("Received Paillier public key.")

            # 3. Encrypt each transaction amount
            encrypted_txs = []
            for tx_amount in transactions:
                print(f"Encrypting transaction: {tx_amount}")
                encrypted_tx = paillier_pubkey.encrypt(tx_amount)
                encrypted_txs.append(encrypted_tx)

            # 4. Send the data packet (name, encrypted_txs)
            packet = (seller_name, encrypted_txs)
            client_socket.sendall(pickle.dumps(packet))

            print(f"✅ Successfully sent {len(transactions)} encrypted transactions.")
            print("Connection closed.")

    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to the Payment Gateway at {HOST}:{PORT}.")
        print("Please ensure 'payment_gateway.py' is running.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")


#
# This is the new menu-driven main function
#
if __name__ == "__main__":
    print("====================================")
    print("   Seller Transaction Simulator")
    print("====================================")

    # Must match the NUMBER_OF_SELLERS in your server script
    try:
        num_sellers = int(input("How many sellers to simulate? (e.g., 2): "))
    except ValueError:
        print("Invalid number. Exiting.")
        sys.exit(1)

    # Loop for each seller
    for i in range(num_sellers):
        print(f"\n--- CONFIGURING SELLER {i + 1}/{num_sellers} ---")

        seller_name = input(f"Enter name for Seller {i + 1}: ")
        if not seller_name:
            seller_name = f"Seller {i + 1}"

        transactions = []
        print("Enter transaction amounts. Type 'done' when finished.")

        # Inner loop for this seller's transactions
        while True:
            tx_str = input(f"Enter transaction amount {len(transactions) + 1} (or 'done'): ")

            if tx_str.lower() == 'done':
                if len(transactions) < 2:
                    print("Error: Each seller needs at least 2 transactions. Please add more.")
                    continue  # Stay in the loop
                else:
                    break  # Exit the transaction-entry loop

            try:
                tx_amount = int(tx_str)
                if tx_amount <= 0:
                    print("Please enter a positive amount.")
                    continue
                transactions.append(tx_amount)
            except ValueError:
                print("Invalid input. Please enter a number or 'done'.")

        # Now that we have this seller's data, run the client function
        run_seller(seller_name, transactions)

    print("\n====================================")
    print("All sellers have sent their data.")
    print("Check the server window for the final summary.")
    print("====================================")