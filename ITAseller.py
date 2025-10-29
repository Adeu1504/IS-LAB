import socket
import pickle
import sys
from phe import paillier

# --- Configuration ---
HOST = 'localhost'
PORT = 9999


def run_seller(seller_name, transactions):
    """Main client function."""

    print(f"--- Seller: {seller_name} ---")
    print(f"Preparing transactions: {transactions}")

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

            print(f"Successfully sent {len(transactions)} encrypted transactions to gateway.\n")

    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to the Payment Gateway at {HOST}:{PORT}.")
        print("Please ensure 'payment_gateway.py' is running.")
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")


if __name__ == "__main__":
    # Expects arguments: python seller.py <SellerName> <tx1> <tx2> ...
    if len(sys.argv) < 3:
        print("Usage: python seller.py <SellerName> <transaction1> <transaction2> ...")
        print("Example: python seller.py \"Seller A\" 150 200")
        sys.exit(1)

    seller_name = sys.argv[1]
    # Convert all other arguments to integers
    try:
        transactions = [int(tx) for tx in sys.argv[2:]]
    except ValueError:
        print("[ERROR] All transactions must be valid integers.")
        sys.exit(1)

    if len(transactions) < 2:
        print("[ERROR] Each seller must perform at least two transactions.")
        sys.exit(1)

    run_seller(seller_name, transactions)