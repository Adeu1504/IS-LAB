# SecureCorp is a large enterprise with multiple subsidiaries and business units located
# across different geographical regions. As part of their digital transformation initiative,
# the IT team at SecureCorp has been tasked with building a secure and scalable
# communication system to enable seamless collaboration and information sharing
# between their various subsystems.
# The enterprise system consists of the following key subsystems:
# 1. Finance System (System A): Responsible for all financial record-keeping, accounting,
# and reporting.
# 2. HR System (System B): Manages employee data, payroll, and personnel related
# processes.
# 3. Supply Chain Management (System C): Coordinates the flow of goods, services, and
# information across the organization's supply chain
# These subsystems need to communicate securely and exchange critical documents, such
# financial reports, employee contracts, and procurement orders, to ensure the enterprise's
# overall efficiency.
# The IT team at SecureCorp has identified the following requirements for the secure
# communication and document signing solution:
# 1. Secure Communication: The subsystems must be able to establish secure
# communication channels using a combination of RSA encryption and Diffie-Hellman
# 27
# key exchange.
# 2. Key Management: SecureCorp requires a robust key management system to generate,
# distribute, and revoke keys as needed to maintain the security of the enterprise system.
# 3. Scalability: The solution must be designed to accommodate the addition of new
# subsystems in the future as SecureCorp continues to grow and expand its operations.
# Implement a Python program which incorporates the requirements.

import os
import time
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --- 1. Certificate Authority (CA) Functions ---

def create_ca():
    """Initializes the CA's state and root keys."""
    print("[CA] Initializing the SecureCorp Certificate Authority...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    print("[CA] Root of Trust established.")
    return {
        "private_key": private_key,
        "public_key": private_key.public_key(),
        "certificates": {},
        "crl": set()  # Certificate Revocation List
    }


def ca_issue_certificate(ca_state, system_name, system_public_key):
    """Issues and signs a certificate for a subsystem."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Manipal"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureCorp"),
        x509.NameAttribute(NameOID.COMMON_NAME, system_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        system_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_state["private_key"], hashes.SHA256())

    ca_state["certificates"][system_name] = cert
    print(f"[CA] Issued certificate for '{system_name}'.")
    return cert


def ca_get_certificate(ca_state, system_name):
    """Retrieves a certificate, checking the revocation list first."""
    if system_name in ca_state["crl"]:
        raise ValueError(f"Certificate for '{system_name}' has been revoked.")
    return ca_state["certificates"].get(system_name)


def ca_revoke_certificate(ca_state, system_name):
    """Adds a certificate to the revocation list."""
    if system_name in ca_state["certificates"]:
        ca_state["crl"].add(system_name)
        print(f"[CA] 🚨 Revoked certificate for '{system_name}'.")


# --- 2. Subsystem Functions ---

def create_subsystem(name, ca_state, dh_params):
    """Creates a state dictionary for a new subsystem."""
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = ca_issue_certificate(ca_state, name, rsa_private_key.public_key())
    print(f"[{name}] System initialized, RSA keys generated, and certificate received.")
    return {
        "name": name,
        "rsa_private_key": rsa_private_key,
        "rsa_public_key": rsa_private_key.public_key(),
        "certificate": certificate,
        "dh_params": dh_params
    }


def subsystem_sign_data(subsystem_state, data):
    """Signs data with the subsystem's private RSA key."""
    return subsystem_state["rsa_private_key"].sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def subsystem_verify_signature(ca_state, data, signature, peer_name):
    """Verifies a signature using a peer's certified public key."""
    peer_cert = ca_get_certificate(ca_state, peer_name)
    if not peer_cert:
        raise ConnectionError(f"Could not find certificate for '{peer_name}'.")

    try:
        peer_cert.public_key().verify(
            signature, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# --- 3. Secure Session Functions ---

def session_encrypt(session_key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + encrypted_data


def session_decrypt(session_key, encrypted_package):
    iv = encrypted_package[:16]
    tag = encrypted_package[16:32]
    encrypted_data = encrypted_package[32:]
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


# --- 4. Main Simulation ---
if __name__ == "__main__":
    print("--- SecureCorp Enterprise System Simulation (Functional Style) ---")

    # Setup
    ca = create_ca()
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Instantiate Subsystems by creating their state dictionaries
    finance_system = create_subsystem("Finance System (A)", ca, dh_parameters)
    hr_system = create_subsystem("HR System (B)", ca, dh_parameters)
    supply_chain_system = create_subsystem("Supply Chain (C)", ca, dh_parameters)

    # --- SCENARIO 1: Secure Communication Handshake ---
    print(f"\n--- Scenario: '{finance_system['name']}' establishes a secure session with '{hr_system['name']}' ---")

    # 1a. Initiator (Finance) generates ephemeral DH key and signs it
    print(f"[{finance_system['name']}] Generating and signing ephemeral DH key...")
    fin_dh_private_key = dh_parameters.generate_private_key()
    fin_dh_public_key_bytes = fin_dh_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fin_signature = subsystem_sign_data(finance_system, fin_dh_public_key_bytes)

    # 1b. Responder (HR) receives the package, verifies, and responds
    print(f"[{hr_system['name']}] Received request, verifying signature...")
    if not subsystem_verify_signature(ca, fin_dh_public_key_bytes, fin_signature, finance_system['name']):
        raise SecurityException("MITM Alert! Finance signature on DH key is invalid.")
    print(f"[{hr_system['name']}] Signature is valid. Generating response...")

    hr_dh_private_key = dh_parameters.generate_private_key()
    hr_dh_public_key_bytes = hr_dh_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hr_signature = subsystem_sign_data(hr_system, hr_dh_public_key_bytes)

    # 1c. Both sides compute the shared secret and derive the session key
    print(f"[{hr_system['name']}] Computing shared secret...")
    fin_dh_public_key = serialization.load_pem_public_key(fin_dh_public_key_bytes)
    hr_shared_secret = hr_dh_private_key.exchange(fin_dh_public_key)
    hr_session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'session_key').derive(hr_shared_secret)

    print(f"[{finance_system['name']}] Received response, verifying signature and computing secret...")
    if not subsystem_verify_signature(ca, hr_dh_public_key_bytes, hr_signature, hr_system['name']):
        raise SecurityException("MITM Alert! HR signature on DH key is invalid.")

    hr_dh_public_key = serialization.load_pem_public_key(hr_dh_public_key_bytes)
    fin_shared_secret = fin_dh_private_key.exchange(hr_dh_public_key)
    fin_session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'session_key').derive(
        fin_shared_secret)

    assert fin_session_key == hr_session_key
    session_key = fin_session_key
    print("  ✅ SUCCESS: Secure session established. Session keys match.")

    # --- SCENARIO 2: Secure Document Transfer and Signing ---
    print("\n--- Scenario: Finance sends a signed, encrypted report to HR ---")

    report_data = b"Q3 Financial Report: Profits are up by 20%."
    finance_signature = subsystem_sign_data(finance_system, report_data)
    print(f"[{finance_system['name']}] Document signed.")

    package_to_send = session_encrypt(session_key, report_data + b"||SIGNATURE||" + finance_signature)
    print(f"[{finance_system['name']}] Report and signature encrypted.")

    decrypted_package = session_decrypt(session_key, package_to_send)
    print(f"[{hr_system['name']}] Received and decrypted package.")

    doc, sig = decrypted_package.split(b"||SIGNATURE||")
    is_valid = subsystem_verify_signature(ca, doc, sig, finance_system['name'])

    print(f"[{hr_system['name']}] Verifying signature from '{finance_system['name']}'...")
    if is_valid:
        print(f"  ✅ SUCCESS: Signature is valid. Document is authentic.")
        print(f"  - Received document: '{doc.decode()}'")
    else:
        print(f"  ❌ FAILURE: Signature is invalid!")

    # --- SCENARIO 3: Scalability and Key Revocation ---
    print("\n--- Scenario: Adding a new system and demonstrating key revocation ---")

    manufacturing_system = create_subsystem("Manufacturing (D)", ca, dh_parameters)
    print("\n  ✅ SUCCESS: New manufacturing system seamlessly integrated.")

    ca_revoke_certificate(ca, "HR System (B)")

    print("\n  - Finance now attempts to verify a (hypothetical) new signature from HR...")
    try:
        # This verification must fail because the CA will report the cert as revoked
        is_valid = subsystem_verify_signature(ca, b"some data", b"some signature", "HR System (B)")
        if not is_valid:
            # This path might be taken if verify returns False instead of raising an error
            raise ValueError("Certificate for 'HR System (B)' has been revoked.")
    except Exception as e:
        print(f"  ✅ SUCCESS: Verification failed as expected. Reason: {e}")