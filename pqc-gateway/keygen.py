#!/usr/bin/env python3
"""
PQC Key Generation Script
Generates ML-DSA (Dilithium) keypair for signing/verification
"""

import oqs
import os

# Use ML-DSA-65 (Dilithium3, NIST Level 3 security)
ALGORITHM = "ML-DSA-65"

def generate_keypair():
    """Generate and save Dilithium keypair"""

    # Create signer instance
    signer = oqs.Signature(ALGORITHM)

    # Generate keypair
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()

    # Create keys directory if not exists
    os.makedirs("keys", exist_ok=True)

    # Save keys to files
    with open("keys/public.key", "wb") as f:
        f.write(public_key)

    with open("keys/private.key", "wb") as f:
        f.write(private_key)

    print(f"Algorithm: {ALGORITHM}")
    print(f"Public key size: {len(public_key)} bytes")
    print(f"Private key size: {len(private_key)} bytes")
    print(f"Keys saved to keys/public.key and keys/private.key")

    return public_key, private_key

if __name__ == "__main__":
    generate_keypair()
