# PQC-Gateway
# PQC-Gateway

Post-Quantum Cryptography authentication layer for QKD ETSI 014 interface.

## Overview

This project adds Dilithium (ML-DSA-65) digital signatures to protect key delivery requests on IDQuantique Ceberis 3 QKD system.

## Architecture

```
┌──────────┐   Dilithium Signature   ┌─────────────┐   Original Request   ┌─────────────┐
│  Client  │ ──────────────────────> │ PQC Gateway │ ──────────────────> │ ETSI WebAPI │
│ (Sign)   │                         │  (Verify)   │                     │   (:443)    │
└──────────┘                         └─────────────┘                     └─────────────┘
```

## Environment

- **Platform:** IDQuantique Ceberis 3 QKD System
- **Server:** QMS (Ubuntu, 192.168.10.200)
- **Python:** 3.9 with virtual environment (`~/pqc-env`)
- **PQC Library:** liboqs v0.15.0 + liboqs-python v0.14.1

## Files

| File | Description |
|------|-------------|
| `keygen.py` | Generates ML-DSA-65 (Dilithium3) key pair |
| `sign_verify.py` | Tests signing and verification functions |
| `keys/` | Directory for key storage (not tracked in git) |

## Usage

```bash
# Activate virtual environment
source ~/pqc-env/bin/activate

# Generate key pair (run once)
python keygen.py

# Test signing and verification
python sign_verify.py
```

## Test Results

**Algorithm:** ML-DSA-65 (NIST Level 3 Security)

| Metric | Value |
|--------|-------|
| Public key size | 1952 bytes |
| Private key size | 4032 bytes |
| Signature size | 3309 bytes |
| Signing time | 0.29 ms |
| Verification time | 0.08 ms |

**Verification tests:**
-  Valid signature verification: PASSED
-  Tampered message detection: PASSED
