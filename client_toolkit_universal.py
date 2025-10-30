import socket
import json
import numpy as np
from Crypto.PublicKey import RSA
from phe import paillier

# --- Client Configuration ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432


def _send_request(request_dict):
    """
    Private helper function to handle all networking.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps(request_dict).encode('utf-8'))

            response_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            response_json = json.loads(response_data.decode('utf-8'))

            if response_json['status'] == 'ok':
                return response_json['result']
            else:
                raise Exception(f"Server Error: {response_json['message']}")

    except ConnectionRefusedError:
        raise Exception("Connection refused. Is the server running?")
    except Exception as e:
        raise Exception(str(e))


# --- Public Toolkit Functions ---

# --- LAB 1 ---
def remote_caesar_cipher(text, key, mode='encrypt'):
    request = {
        "command": "CAESAR_CIPHER",
        "payload": {"text": text, "key": key, "mode": mode}
    }
    return _send_request(request)


def remote_multiplicative_cipher(text, key, mode='encrypt'):
    request = {
        "command": "MULTIPLICATIVE_CIPHER",
        "payload": {"text": text, "key": key, "mode": mode}
    }
    return _send_request(request)


def remote_affine_cipher(text, key_tuple, mode='encrypt'):
    request = {
        "command": "AFFINE_CIPHER",
        "payload": {"text": text, "key": list(key_tuple), "mode": mode}
    }
    return _send_request(request)


def remote_vigenere_cipher(text, key, mode='encrypt'):
    request = {
        "command": "VIGENERE_CIPHER",
        "payload": {"text": text, "key": key, "mode": mode}
    }
    return _send_request(request)


def remote_autokey_cipher(text, key, mode='encrypt'):
    request = {
        "command": "AUTOKEY_CIPHER",
        "payload": {"text": text, "key": key, "mode": mode}
    }
    return _send_request(request)


def remote_playfair_cipher(text, key, mode='encrypt'):
    request = {
        "command": "PLAYFAIR_CIPHER",
        "payload": {"text": text, "key": key, "mode": mode}
    }
    return _send_request(request)


def remote_hill_cipher(text, key_matrix, mode='encrypt'):
    request = {
        "command": "HILL_CIPHER",
        "payload": {
            "text": text,
            "key_matrix": key_matrix.tolist(),  # Convert numpy array
            "mode": mode
        }
    }
    return _send_request(request)


def remote_transposition_cipher(text, key, mode='encrypt'):
    request = {
        "command": "TRANSPOSITION_CIPHER",
        "payload": {"text": text, "key": key, "mode": mode}
    }
    return _send_request(request)


# --- LAB 2 ---
def remote_des_encrypt(key_bytes, data_bytes):
    request = {
        "command": "DES_CIPHER",
        "payload": {
            "mode": "encrypt",
            "key_hex": key_bytes.hex(),
            "data": data_bytes.decode('utf-8')
        }
    }
    return _send_request(request)


def remote_des_decrypt(key_bytes, iv_hex, ciphertext_hex):
    request = {
        "command": "DES_CIPHER",
        "payload": {
            "mode": "decrypt",
            "key_hex": key_bytes.hex(),
            "iv_hex": iv_hex,
            "ciphertext_hex": ciphertext_hex
        }
    }
    return _send_request(request)


def remote_des3_encrypt(key_bytes, data_bytes):
    request = {
        "command": "DES3_CIPHER",
        "payload": {
            "mode": "encrypt",
            "key_hex": key_bytes.hex(),
            "data": data_bytes.decode('utf-8')
        }
    }
    return _send_request(request)


def remote_des3_decrypt(key_bytes, iv_hex, ciphertext_hex):
    request = {
        "command": "DES3_CIPHER",
        "payload": {
            "mode": "decrypt",
            "key_hex": key_bytes.hex(),
            "iv_hex": iv_hex,
            "ciphertext_hex": ciphertext_hex
        }
    }
    return _send_request(request)


def remote_aes_encrypt(key_bytes, data_bytes):
    request = {
        "command": "AES_CIPHER",
        "payload": {
            "mode": "encrypt",
            "key_hex": key_bytes.hex(),
            "data": data_bytes.decode('utf-8')
        }
    }
    return _send_request(request)


def remote_aes_decrypt(key_bytes, iv_hex, ciphertext_hex):
    request = {
        "command": "AES_CIPHER",
        "payload": {
            "mode": "decrypt",
            "key_hex": key_bytes.hex(),
            "iv_hex": iv_hex,
            "ciphertext_hex": ciphertext_hex
        }
    }
    return _send_request(request)


# --- LAB 3 & 4 ---
def remote_rsa_generate_keys(bits=2048):
    request = {"command": "RSA_GENERATE_KEYS", "payload": {"bits": bits}}
    result = _send_request(request)
    private_key = RSA.import_key(result['private_key'])
    public_key = RSA.import_key(result['public_key'])
    return private_key, public_key


def remote_rsa_encrypt(public_key, data_bytes):
    request = {
        "command": "RSA_ENCRYPT",
        "payload": {
            "public_key": public_key.export_key().decode('utf-8'),
            "data": data_bytes.decode('utf-8')
        }
    }
    return bytes.fromhex(_send_request(request))  # Return bytes


def remote_rsa_decrypt(private_key, ciphertext_bytes):
    request = {
        "command": "RSA_DECRYPT",
        "payload": {
            "private_key": private_key.export_key().decode('utf-8'),
            "ciphertext_hex": ciphertext_bytes.hex()
        }
    }
    return _send_request(request).encode('utf-8')  # Return bytes


def remote_elgamal_generate_keys(bits=512):
    request = {"command": "ELGAMAL_GENERATE_KEYS", "payload": {"bits": bits}}
    result = _send_request(request)
    return tuple(result['private_key']), tuple(result['public_key'])


def remote_elgamal_encrypt(public_key_tuple, message_int):
    request = {
        "command": "ELGAMAL_ENCRYPT",
        "payload": {"public_key": public_key_tuple, "message_int": message_int}
    }
    return tuple(_send_request(request))


def remote_elgamal_decrypt(private_key_tuple, ciphertext_tuple):
    request = {
        "command": "ELGAMAL_DECRYPT",
        "payload": {"private_key": private_key_tuple, "ciphertext": ciphertext_tuple}
    }
    return _send_request(request)


def remote_rabin_generate_keys(bits=512):
    request = {"command": "RABIN_GENERATE_KEYS", "payload": {"bits": bits}}
    result = _send_request(request)
    return tuple(result['private_key']), result['public_key']


def remote_rabin_encrypt(public_key_n, message_int):
    request = {
        "command": "RABIN_ENCRYPT",
        "payload": {"public_key": public_key_n, "message_int": message_int}
    }
    return _send_request(request)


def remote_rabin_decrypt(private_key_tuple, ciphertext):
    request = {
        "command": "RABIN_DECRYPT",
        "payload": {"private_key": private_key_tuple, "ciphertext": ciphertext}
    }
    return _send_request(request)


# --- LAB 5 ---
def remote_get_hash(data_bytes, algorithm='sha256'):
    request = {
        "command": "GET_HASH",
        "payload": {
            "data": data_bytes.decode('utf-8'),
            "algorithm": algorithm
        }
    }
    return _send_request(request)


# --- LAB 6 ---
def remote_rsa_sign(private_key, data_bytes):
    request = {
        "command": "RSA_SIGN",
        "payload": {
            "private_key": private_key.export_key().decode('utf-8'),
            "data": data_bytes.decode('utf-8')
        }
    }
    return bytes.fromhex(_send_request(request))  # Return bytes


def remote_rsa_verify(public_key, data_bytes, signature_bytes):
    request = {
        "command": "RSA_VERIFY",
        "payload": {
            "public_key": public_key.export_key().decode('utf-8'),
            "data": data_bytes.decode('utf-8'),
            "signature_hex": signature_bytes.hex()
        }
    }
    return _send_request(request)  # Returns boolean


# --- LAB 7 ---
def remote_paillier_generate_keys(bits=1024):
    request = {"command": "PAILLIER_GENERATE_KEYS", "payload": {"bits": bits}}
    result = _send_request(request)
    # Rebuild key objects on the client side
    pub_key = paillier.PaillierPublicKey(n=result['public_key_n'])
    priv_key = paillier.PaillierPrivateKey(
        pub_key, result['private_key_p'], result['private_key_q']
    )
    return pub_key, priv_key


def remote_paillier_encrypt(public_key, number):
    # We only need 'n' from the public key to send
    request = {
        "command": "PAILLIER_ENCRYPT",
        "payload": {
            "public_key_n": public_key.n,
            "number": number
        }
    }
    result = _send_request(request)
    # Rebuild the EncryptedNumber object on the client side
    return paillier.EncryptedNumber(
        public_key, result['ciphertext'], result['exponent']
    )


def remote_paillier_decrypt(private_key, encrypted_number):
    request = {
        "command": "PAILLIER_DECRYPT",
        "payload": {
            "public_key_n": private_key.public_key.n,
            "private_key_p": private_key.p,
            "private_key_q": private_key.q,
            "ciphertext": encrypted_number.ciphertext(be_secure=False),
            "exponent": encrypted_number.exponent
        }
    }
    return _send_request(request)


# --- LAB 8 ---
def remote_sse_generate_key():
    request = {"command": "SSE_GENERATE_KEY"}
    return bytes.fromhex(_send_request(request))


def remote_sse_create_index(key_bytes, documents):
    request = {
        "command": "SSE_CREATE_INDEX",
        "payload": {
            "key_hex": key_bytes.hex(),
            "documents": documents
        }
    }
    return _send_request(request)


def remote_sse_search(key_bytes, index, query):
    request = {
        "command": "SSE_SEARCH",
        "payload": {
            "key_hex": key_bytes.hex(),
            "index": index,
            "query": query
        }
    }
    return _send_request(request)