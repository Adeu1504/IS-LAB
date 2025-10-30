import socket
import threading
import json
import numpy as np
from Crypto.PublicKey import RSA
from phe import paillier
# Import your ENTIRE toolkit as an API
import masterkey as crypto_api

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 65432


def handle_client(conn, addr):
    """
    This function is the "Universal Crypto Oracle."
    It parses a command and runs the corresponding function
    from the crypto_api (your toolkit).
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        # Use a loop to receive all data (requests might be large)
        data_buffer = b""
        while True:
            chunk = conn.recv(4096)
            data_buffer += chunk
            # Simple check: assume full JSON is received when chunk is < 4096
            # A more robust solution would use headers or delimiters
            if len(chunk) < 4096:
                break

        data = data_buffer.decode('utf-8')
        if not data:
            print(f"[{addr}] No data received. Closing.")
            return

        print(f"[{addr}] Received request.")
        request = json.loads(data)

        command = request.get('command')
        payload = request.get('payload', {})  # Default to empty dict
        response = {}

        # --- This is the "Universal" routing block ---
        try:
            # --- LAB 1 ---
            if command == 'CAESAR_CIPHER':
                result = crypto_api.caesar_cipher(
                    payload['text'], payload['key'], payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'MULTIPLICATIVE_CIPHER':
                result = crypto_api.multiplicative_cipher(
                    payload['text'], payload['key'], payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'AFFINE_CIPHER':
                result = crypto_api.affine_cipher(
                    payload['text'], tuple(payload['key']), payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'VIGENERE_CIPHER':
                result = crypto_api.vigenere_cipher(
                    payload['text'], payload['key'], payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'AUTOKEY_CIPHER':
                result = crypto_api.autokey_cipher(
                    payload['text'], payload['key'], payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'PLAYFAIR_CIPHER':
                result = crypto_api.playfair_cipher(
                    payload['text'], payload['key'], payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'HILL_CIPHER':
                key_matrix = np.array(payload['key_matrix'])
                result = crypto_api.hill_cipher(
                    payload['text'], key_matrix, payload['mode']
                )
                response = {"status": "ok", "result": result}

            elif command == 'TRANSPOSITION_CIPHER':
                result = crypto_api.transposition_cipher(
                    payload['text'], payload['key'], payload['mode']
                )
                response = {"status": "ok", "result": result}

            # --- LAB 2 ---
            elif command == 'DES_CIPHER':
                key_bytes = bytes.fromhex(payload['key_hex'])
                if payload['mode'] == 'encrypt':
                    data_bytes = payload['data'].encode('utf-8')
                    result = crypto_api.des_cbc_encrypt(key_bytes, data_bytes)
                else:
                    result = crypto_api.des_cbc_decrypt(
                        key_bytes, payload['iv_hex'], payload['ciphertext_hex']
                    )
                    result = result.decode('utf-8')  # Send back string
                response = {"status": "ok", "result": result}

            elif command == 'DES3_CIPHER':
                key_bytes = bytes.fromhex(payload['key_hex'])
                if payload['mode'] == 'encrypt':
                    data_bytes = payload['data'].encode('utf-8')
                    result = crypto_api.des3_cbc_encrypt(key_bytes, data_bytes)
                else:
                    result = crypto_api.des3_cbc_decrypt(
                        key_bytes, payload['iv_hex'], payload['ciphertext_hex']
                    )
                    result = result.decode('utf-8')
                response = {"status": "ok", "result": result}

            elif command == 'AES_CIPHER':
                key_bytes = bytes.fromhex(payload['key_hex'])
                if payload['mode'] == 'encrypt':
                    data_bytes = payload['data'].encode('utf-8')
                    result = crypto_api.aes_cbc_encrypt(key_bytes, data_bytes)
                else:
                    result = crypto_api.aes_cbc_decrypt(
                        key_bytes, payload['iv_hex'], payload['ciphertext_hex']
                    )
                    result = result.decode('utf-8')
                response = {"status": "ok", "result": result}

            # --- LAB 3 & 4 ---
            elif command == 'RSA_GENERATE_KEYS':
                priv, pub = crypto_api.rsa_generate_keys(payload['bits'])
                response = {
                    "status": "ok",
                    "result": {
                        "private_key": priv.export_key().decode('utf-8'),
                        "public_key": pub.export_key().decode('utf-8')
                    }
                }

            elif command == 'RSA_ENCRYPT':
                pub_key = RSA.import_key(payload['public_key'])
                data_bytes = payload['data'].encode('utf-8')
                result_bytes = crypto_api.rsa_encrypt(pub_key, data_bytes)
                response = {"status": "ok", "result": result_bytes.hex()}

            elif command == 'RSA_DECRYPT':
                priv_key = RSA.import_key(payload['private_key'])
                data_bytes = bytes.fromhex(payload['ciphertext_hex'])
                result_bytes = crypto_api.rsa_decrypt(priv_key, data_bytes)
                response = {"status": "ok", "result": result_bytes.decode('utf-8')}

            elif command == 'ELGAMAL_GENERATE_KEYS':
                priv, pub = crypto_api.elgamal_generate_keys(payload['bits'])
                response = {"status": "ok", "result": {"private_key": priv, "public_key": pub}}

            elif command == 'ELGAMAL_ENCRYPT':
                result = crypto_api.elgamal_encrypt(
                    tuple(payload['public_key']), payload['message_int']
                )
                response = {"status": "ok", "result": result}

            elif command == 'ELGAMAL_DECRYPT':
                result = crypto_api.elgamal_decrypt(
                    tuple(payload['private_key']), tuple(payload['ciphertext'])
                )
                response = {"status": "ok", "result": result}

            elif command == 'RABIN_GENERATE_KEYS':
                priv, pub = crypto_api.rabin_generate_keys(payload['bits'])
                response = {"status": "ok", "result": {"private_key": priv, "public_key": pub}}

            elif command == 'RABIN_ENCRYPT':
                result = crypto_api.rabin_encrypt(
                    payload['public_key'], payload['message_int']
                )
                response = {"status": "ok", "result": result}

            elif command == 'RABIN_DECRYPT':
                result = crypto_api.rabin_decrypt(
                    tuple(payload['private_key']), payload['ciphertext']
                )
                response = {"status": "ok", "result": result}

            # --- LAB 5 ---
            elif command == 'GET_HASH':
                data_bytes = payload['data'].encode('utf-8')
                algo = payload.get('algorithm', 'sha256')
                hash_hex = crypto_api.get_hash(data_bytes, algo)
                response = {"status": "ok", "result": hash_hex}

            # --- LAB 6 ---
            elif command == 'RSA_SIGN':
                priv_key = RSA.import_key(payload['private_key'])
                data_bytes = payload['data'].encode('utf-8')
                sig_bytes = crypto_api.rsa_sign(priv_key, data_bytes)
                response = {"status": "ok", "result": sig_bytes.hex()}

            elif command == 'RSA_VERIFY':
                pub_key = RSA.import_key(payload['public_key'])
                data_bytes = payload['data'].encode('utf-8')
                sig_bytes = bytes.fromhex(payload['signature_hex'])
                is_valid = crypto_api.rsa_verify(pub_key, data_bytes, sig_bytes)
                response = {"status": "ok", "result": is_valid}

            # --- LAB 7 ---
            elif command == 'PAILLIER_GENERATE_KEYS':
                pub, priv = crypto_api.paillier_generate_keys(payload['bits'])
                # Send back the raw numbers, not the objects
                response = {
                    "status": "ok",
                    "result": {
                        "public_key_n": pub.n,
                        "public_key_g": pub.g,
                        "private_key_p": priv.p,
                        "private_key_q": priv.q
                    }
                }

            elif command == 'PAILLIER_ENCRYPT':
                # Rebuild key from numbers
                pub_key = paillier.PaillierPublicKey(n=payload['public_key_n'])
                enc_obj = crypto_api.paillier_encrypt(pub_key, payload['number'])
                # Send back the two parts of the ciphertext
                response = {
                    "status": "ok",
                    "result": {
                        "ciphertext": enc_obj.ciphertext(be_secure=False),
                        "exponent": enc_obj.exponent
                    }
                }

            elif command == 'PAILLIER_DECRYPT':
                # Rebuild keys from numbers
                pub_key = paillier.PaillierPublicKey(n=payload['public_key_n'])
                priv_key = paillier.PaillierPrivateKey(
                    pub_key, payload['private_key_p'], payload['private_key_q']
                )
                # Rebuild ciphertext object
                enc_obj = paillier.EncryptedNumber(
                    pub_key, payload['ciphertext'], payload['exponent']
                )
                result = crypto_api.paillier_decrypt(priv_key, enc_obj)
                response = {"status": "ok", "result": result}

            # --- LAB 8 ---
            elif command == 'SSE_GENERATE_KEY':
                key_bytes = crypto_api.sse_generate_key()
                response = {"status": "ok", "result": key_bytes.hex()}

            elif command == 'SSE_CREATE_INDEX':
                key_bytes = bytes.fromhex(payload['key_hex'])
                documents = payload['documents']  # documents is a dict
                index = crypto_api.sse_create_index(key_bytes, documents)
                response = {"status": "ok", "result": index}

            elif command == 'SSE_SEARCH':
                key_bytes = bytes.fromhex(payload['key_hex'])
                index = payload['index']
                query = payload['query']
                results = crypto_api.sse_search(key_bytes, index, query)
                response = {"status": "ok", "result": results}

            else:
                response = {"status": "error", "message": "Unknown command"}

        except KeyError as e:
            response = {"status": "error", "message": f"Missing parameter: {e}"}
        except Exception as e:
            response = {"status": "error", "message": f"Crypto Error: {str(e)}"}

        # Send the JSON response back to the client
        conn.sendall(json.dumps(response).encode('utf-8'))

    except json.JSONDecodeError:
        print(f"[{addr}] Received invalid JSON.")
    except Exception as e:
        print(f"[{addr}] Error: {e}")
    finally:
        print(f"[{addr}] Connection closed.")
        conn.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow address reuse (e.g., after a crash)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[LISTENING] Universal Crypto Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    start_server()