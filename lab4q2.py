# HealthCare Inc., a leading healthcare provider, has implemented a secure patient data
# management system using the Rabin cryptosystem. The system allows authorized
# healthcare professionals to securely access and manage patient records across multiple
# hospitals and clinics within the organization. Implement a Python-based centralized key
# management service that can:
# • Key Generation: Generate public and private key pairs for each hospital and clinic
# using the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
# • Key Distribution: Provide a secure API for hospitals and clinics to request and receive
# their public and private key pairs.
# • Key Revocation: Implement a process to revoke and update the keys of a hospital or
# clinic when necessary (e.g., when a facility is closed or compromised).
# • Key Renewal: Automatically renew the keys of all hospitals and clinics at regular
# intervals (e.g., every 12 months) to maintain the security of the patient data management
# system.
# • Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring
# that they are not accessible to unauthorized parties.
# • Auditing and Logging: Maintain detailed logs of all key management operations, such
# as key generation, distribution, revocation, and renewal, to enable auditing and
# compliance reporting.
# • Regulatory Compliance: Ensure that the key management service and its operations are
# 28
# compliant with relevant data privacy regulations (e.g., HIPAA).
# • Perform a trade-off analysis to compare the workings of Rabin and RSA.

import os
import threading
import time
import datetime
import random
from sympy import isprime


# --- Section 1: Rabin Cryptosystem Helper Functions ---

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y


def mod_inverse(a, m):
    """Modular inverse of a modulo m."""
    d, x, y = extended_gcd(a, m)
    if d != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


def find_prime(bits):
    """Finds a prime p such that p ≡ 3 (mod 4)."""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if p % 4 == 3 and isprime(p):
            return p


def add_padding(message_bytes):
    """Adds redundancy padding to the message before encryption."""
    pad_length = 16
    padding = message_bytes[-pad_length:]
    return message_bytes + padding


def remove_padding(padded_bytes):
    """Checks and removes padding to verify the correct root."""
    pad_length = 16
    if len(padded_bytes) < pad_length:
        return None
    message = padded_bytes[:-pad_length]
    padding = padded_bytes[-pad_length:]
    if len(message) >= pad_length and message[-pad_length:] == padding:
        return message
    return None


def generate_rabin_keys(bits=1024):
    """Generates a Rabin key pair (n, (p, q))."""
    p = find_prime(bits // 2)
    q = find_prime(bits // 2)
    while p == q:
        q = find_prime(bits // 2)
    n = p * q
    return (n, (p, q))


def rabin_encrypt(message_bytes, public_key_n):
    """Encrypts a message using the Rabin public key."""
    padded_int = int.from_bytes(add_padding(message_bytes), 'big')
    if padded_int >= public_key_n:
        raise ValueError("Message is too large for the key size.")
    return pow(padded_int, 2, public_key_n)


def rabin_decrypt(ciphertext, private_key_p, private_key_q):
    """Decrypts a ciphertext, finding the 4 roots and checking padding."""
    n = private_key_p * private_key_q
    r1 = pow(ciphertext, (private_key_p + 1) // 4, private_key_p)
    r2 = pow(ciphertext, (private_key_q + 1) // 4, private_key_q)
    yp = mod_inverse(private_key_p, private_key_q)
    yq = mod_inverse(private_key_q, private_key_p)
    m1 = (r1 * yq * private_key_q + r2 * yp * private_key_p) % n
    m2 = n - m1
    m3 = (r1 * yq * private_key_q - r2 * yp * private_key_p) % n
    m4 = n - m3
    for root_int in [m1, m2, m3, m4]:
        padded_bytes = root_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        message = remove_padding(padded_bytes.lstrip(b'\x00'))
        if message:
            return message
    raise Exception("Decryption failed: could not find correct padded root.")


# --- Section 2: Key Management Service (KMS) Functions ---

def kms_init(renewal_interval_seconds=30):
    """Initializes the KMS state dictionary."""
    print("[KMS] Initializing HealthCare Inc. Key Management Service...")
    kms_state = {
        "secure_private_key_storage": {},
        "entity_registry": {},
        "audit_log_file": "kms_audit.log",
        "renewal_interval": renewal_interval_seconds,
        "renewal_thread": None,
        "shutdown_event": threading.Event()
    }
    kms_log_event(kms_state, "KMS_START", "Service initialized.")
    return kms_state


def kms_log_event(kms_state, event_type, details):
    """Logs an event to the audit file."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log_entry = f"{timestamp} | {event_type:20} | {details}\n"
    with open(kms_state["audit_log_file"], 'a') as f:
        f.write(log_entry)


def kms_generate_keys_for_entity(kms_state, entity_name, bits=1024):
    """Generates and securely stores keys for an entity."""
    public_key_n, private_key_pq = generate_rabin_keys(bits)
    kms_state["entity_registry"][entity_name] = {
        "public_key": public_key_n, "status": "active",
        "creation_date": datetime.datetime.now(datetime.timezone.utc)
    }
    kms_state["secure_private_key_storage"][entity_name] = private_key_pq
    kms_log_event(kms_state, "KEY_GENERATION", f"Generated {bits}-bit key for '{entity_name}'.")
    return public_key_n, private_key_pq


def kms_request_keys(kms_state, entity_name):
    """Simulates a secure API for an entity to get its keys."""
    if kms_state["entity_registry"].get(entity_name, {}).get("status") != "active":
        kms_log_event(kms_state, "KEY_DISTRIBUTION_FAIL", f"Denied request from inactive entity '{entity_name}'.")
        raise PermissionError("Entity is not active or does not exist.")
    public_key = kms_state["entity_registry"][entity_name]["public_key"]
    private_key = kms_state["secure_private_key_storage"][entity_name]
    kms_log_event(kms_state, "KEY_DISTRIBUTION", f"Securely distributed keys to '{entity_name}'.")
    return public_key, private_key


def kms_revoke_keys(kms_state, entity_name):
    """Revokes the keys for a given entity."""
    if entity_name in kms_state["entity_registry"]:
        kms_state["entity_registry"][entity_name]["status"] = "revoked"
        if entity_name in kms_state["secure_private_key_storage"]:
            del kms_state["secure_private_key_storage"][entity_name]
        kms_log_event(kms_state, "KEY_REVOCATION", f"Revoked keys for '{entity_name}'.")
        print(f"[KMS] 🚨 Revoked keys for {entity_name}.")
    else:
        kms_log_event(kms_state, "REVOCATION_FAIL", f"Attempted to revoke non-existent entity '{entity_name}'.")


def _kms_renewal_task(kms_state):
    """The background task that performs automatic key renewal."""
    while not kms_state["shutdown_event"].is_set():
        kms_state["shutdown_event"].wait(kms_state["renewal_interval"])
        if kms_state["shutdown_event"].is_set():
            break
        print("\n[KMS] ⏰ Starting scheduled key renewal process...")
        kms_log_event(kms_state, "RENEWAL_START", "Scheduled key renewal process initiated.")
        active_entities = [name for name, data in kms_state["entity_registry"].items() if data["status"] == "active"]
        for entity_name in active_entities:
            print(f"[KMS] Renewing keys for '{entity_name}'...")
            kms_generate_keys_for_entity(kms_state, entity_name)
        kms_log_event(kms_state, "RENEWAL_FINISH", f"Completed renewal for {len(active_entities)} entities.")
        print("[KMS] ✅ Key renewal process finished.")


def kms_start_renewal_scheduler(kms_state):
    """Starts the background thread for automatic key renewals."""
    thread = threading.Thread(target=_kms_renewal_task, args=(kms_state,))
    thread.daemon = True
    thread.start()
    kms_state["renewal_thread"] = thread
    print(f"[KMS] Automatic key renewal scheduler started (interval: {kms_state['renewal_interval']} seconds).")


def kms_stop_scheduler(kms_state):
    """Stops the background renewal thread."""
    kms_state["shutdown_event"].set()
    if kms_state["renewal_thread"]:
        kms_state["renewal_thread"].join()
    print("[KMS] Renewal scheduler stopped.")
    kms_log_event(kms_state, "KMS_STOP", "Service shut down.")


# --- Section 3: Main Simulation ---
if __name__ == "__main__":
    log_file = "kms_audit.log"
    if os.path.exists(log_file):
        os.remove(log_file)

    kms_state = kms_init(renewal_interval_seconds=15)

    # 1. Key Generation
    kms_generate_keys_for_entity(kms_state, "City General Hospital")
    kms_generate_keys_for_entity(kms_state, "Suburb Clinic")

    # 2. Key Distribution
    print("\n--- Simulating Secure Data Transfer ---")
    clinic_pub, clinic_priv = kms_request_keys(kms_state, "Suburb Clinic")
    hospital_pub = kms_state["entity_registry"]["City General Hospital"]["public_key"]

    # 3. Encrypt data
    patient_record = b"Patient: John Doe, DOB: 1985-04-12, Condition: Stable"
    print(f"Clinic is encrypting data for the hospital: '{patient_record.decode()}'")
    ciphertext = rabin_encrypt(patient_record, hospital_pub)
    print("Data encrypted successfully.")

    # 4. Decrypt data
    _, hospital_priv = kms_request_keys(kms_state, "City General Hospital")
    decrypted_record = rabin_decrypt(ciphertext, hospital_priv[0], hospital_priv[1])
    print(f"Hospital decrypted the data: '{decrypted_record.decode()}'")
    assert patient_record == decrypted_record
    print("✅ Verification successful.")

    # 5. Key Revocation
    print("\n--- Simulating Key Revocation ---")
    kms_revoke_keys(kms_state, "Suburb Clinic")
    try:
        kms_request_keys(kms_state, "Suburb Clinic")
    except PermissionError as e:
        print(f"✅ Successfully prevented key access for revoked clinic: {e}")

    # 6. Automatic Key Renewal
    print(f"\n--- Simulating Automatic Key Renewal (will run in {kms_state['renewal_interval']}s) ---")
    kms_start_renewal_scheduler(kms_state)
    time.sleep(16)
    kms_stop_scheduler(kms_state)

    # 7. Auditing and Logging
    print("\n--- Final Audit Log ---")
    with open(log_file, 'r') as f:
        print(f.read())
    os.remove(log_file)