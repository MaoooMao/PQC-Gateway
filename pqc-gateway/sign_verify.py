#!/usr/bin/env python3
"""
PQC Sign and Verify Test Script
Tests Dilithium signature creation and verification
"""

import oqs
import hashlib
import time

ALGORITHM = "ML-DSA-65"

def load_keys():
    """Load keypair from files"""
    with open("keys/public.key", "rb") as f:
        public_key = f.read()
    with open("keys/private.key", "rb") as f:
        private_key = f.read()
    return public_key, private_key

def sign_message(message: bytes, private_key: bytes) -> bytes:
    """Sign a message using Dilithium"""
    signer = oqs.Signature(ALGORITHM, private_key)
    signature = signer.sign(message)
    return signature

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a signature using Dilithium"""
    verifier = oqs.Signature(ALGORITHM)
    return verifier.verify(message, signature, public_key)

def test_sign_verify():
    """Test signing and verification"""

    # Load keys
    print("Loading keys...")
    public_key, private_key = load_keys()

    # Test message (could be anything: message hash, API request, etc.)
    test_message = b"Hello, this is a test message for QKD system"

    # Hash the message (as in QGP protocol)
    message_hash = hashlib.sha256(test_message).digest()

    print(f"\nOriginal message: {test_message.decode()}")
    print(f"Message hash (SHA256): {message_hash.hex()[:32]}...")

    # Sign
    print("\n--- Signing ---")
    start = time.time()
    signature = sign_message(message_hash, private_key)
    sign_time = (time.time() - start) * 1000
    print(f"Signature size: {len(signature)} bytes")
    print(f"Signing time: {sign_time:.2f} ms")

    # Verify
    print("\n--- Verification ---")
    start = time.time()
    is_valid = verify_signature(message_hash, signature, public_key)
    verify_time = (time.time() - start) * 1000
    print(f"Signature valid: {is_valid}")
    print(f"Verification time: {verify_time:.2f} ms")

    # Test with tampered message
    print("\n--- Tamper Test ---")
    tampered_hash = hashlib.sha256(b"Tampered message").digest()
    is_valid_tampered = verify_signature(tampered_hash, signature, public_key)
    print(f"Tampered signature valid: {is_valid_tampered} (should be False)")

    return is_valid and not is_valid_tampered

if __name__ == "__main__":
    success = test_sign_verify()
    print(f"\n{'='*40}")
    print(f"Test result: {'PASSED' if success else 'FAILED'}")
