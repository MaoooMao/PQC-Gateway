#!/usr/bin/env python3
"""
Mock ETSI QKD 014 API Server

This script simulates an ETSI 014 compliant QKD key delivery API.
Used for testing the PQC Gateway without a real QKD system.

ETSI GS QKD 014 defines the REST API for QKD key delivery.
Reference: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/

Endpoints:
    GET  /api/v1/keys/{slave_SAE_ID}/status   - Get key status
    POST /api/v1/keys/{slave_SAE_ID}/enc_keys - Get encryption keys
    POST /api/v1/keys/{slave_SAE_ID}/dec_keys - Get decryption keys
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import uuid
from datetime import datetime

# Configuration
HOST = "127.0.0.1"
PORT = 8443  # Mock ETSI server port


class ETSIKeyStore:
    """
    Simulates QKD key storage.
    In real QKD system, keys come from quantum key distribution.
    Here we just generate random keys for testing.
    """

    def __init__(self):
        # Simulated key store: {key_id: key_bytes}
        self.keys = {}
        # Pre-generate some keys
        for _ in range(10):
            self._generate_key()

    def _generate_key(self, size=256):
        """Generate a random key (simulating QKD output)"""
        key_id = str(uuid.uuid4())
        key_bytes = os.urandom(size // 8)  # 256 bits = 32 bytes
        self.keys[key_id] = key_bytes
        return key_id, key_bytes

    def get_key_count(self):
        """Return number of available keys"""
        return len(self.keys)

    def get_keys(self, count=1, size=256):
        """
        Get keys from the store.
        Returns list of {key_ID, key} pairs.
        """
        result = []

        for _ in range(count):
            if not self.keys:
                # Generate new key if store is empty
                key_id, key_bytes = self._generate_key(size)
            else:
                # Pop a key from store
                key_id = next(iter(self.keys))
                key_bytes = self.keys.pop(key_id)

            result.append({
                "key_ID": key_id,
                "key": key_bytes.hex()  # Return as hex string
            })

        return result


# Global key store instance
key_store = ETSIKeyStore()


class ETSIRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for ETSI 014 API.
    """

    def _set_headers(self, status_code=200, content_type="application/json"):
        """Set response headers"""
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _send_json(self, data, status_code=200):
        """Send JSON response"""
        self._set_headers(status_code)
        response = json.dumps(data, indent=2)
        self.wfile.write(response.encode())

    def _send_error(self, status_code, message):
        """Send error response"""
        error_data = {
            "error": {
                "code": status_code,
                "message": message,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        self._send_json(error_data, status_code)

    def _parse_path(self):
        """
        Parse the request path.
        Expected format: /api/v1/keys/{slave_SAE_ID}/{action}
        Returns: (slave_SAE_ID, action) or (None, None) if invalid
        """
        parts = self.path.strip("/").split("/")
        # Expected: ['api', 'v1', 'keys', '{slave_SAE_ID}', '{action}']
        if len(parts) >= 5 and parts[0:3] == ["api", "v1", "keys"]:
            return parts[3], parts[4]
        elif len(parts) == 4 and parts[0:3] == ["api", "v1", "keys"]:
            return parts[3], None
        return None, None

    def do_GET(self):
        """
        Handle GET requests.

        GET /api/v1/keys/{slave_SAE_ID}/status
        Returns the status of available keys.
        """
        slave_sae_id, action = self._parse_path()

        if not slave_sae_id:
            self._send_error(400, "Invalid path")
            return

        if action == "status":
            # Return key status
            response = {
                "source_KME_ID": "QKD-Alice-001",
                "target_KME_ID": "QKD-Bob-001",
                "master_SAE_ID": "SAE-Master-001",
                "slave_SAE_ID": slave_sae_id,
                "key_size": 256,
                "stored_key_count": key_store.get_key_count(),
                "max_key_count": 100,
                "max_key_per_request": 10,
                "max_key_size": 1024,
                "min_key_size": 64,
                "max_SAE_ID_count": 0
            }
            self._send_json(response)
            print(f"[STATUS] slave_SAE_ID={slave_sae_id}, available_keys={key_store.get_key_count()}")
        else:
            self._send_error(404, f"Unknown action: {action}")

    def do_POST(self):
        """
        Handle POST requests.

        POST /api/v1/keys/{slave_SAE_ID}/enc_keys
        Request body: {"number": 1, "size": 256}
        Returns encryption keys.

        POST /api/v1/keys/{slave_SAE_ID}/dec_keys
        Request body: {"key_IDs": [{"key_ID": "..."}]}
        Returns decryption keys for given IDs.
        """
        slave_sae_id, action = self._parse_path()

        if not slave_sae_id:
            self._send_error(400, "Invalid path")
            return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            try:
                request_data = json.loads(body)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON")
                return
        else:
            request_data = {}

        if action == "enc_keys":
            # Get encryption keys
            number = request_data.get("number", 1)
            size = request_data.get("size", 256)

            # Validate parameters
            if number < 1 or number > 10:
                self._send_error(400, "number must be between 1 and 10")
                return
            if size not in [64, 128, 256, 512, 1024]:
                self._send_error(400, "Invalid key size")
                return

            # Get keys
            keys = key_store.get_keys(count=number, size=size)

            response = {
                "key_container": keys,
                "key_container_extension": None
            }
            self._send_json(response)
            print(f"[ENC_KEYS] slave_SAE_ID={slave_sae_id}, requested={number}, size={size}")
            for k in keys:
                print(f"  -> key_ID={k['key_ID'][:8]}..., key={k['key'][:16]}...")

        elif action == "dec_keys":
            # Get decryption keys by ID (in real system, retrieves matching keys)
            # For mock, we just generate new keys
            key_ids = request_data.get("key_IDs", [])

            keys = []
            for kid in key_ids:
                key_id = kid.get("key_ID", str(uuid.uuid4()))
                keys.append({
                    "key_ID": key_id,
                    "key": os.urandom(32).hex()
                })

            response = {
                "key_container": keys,
                "key_container_extension": None
            }
            self._send_json(response)
            print(f"[DEC_KEYS] slave_SAE_ID={slave_sae_id}, requested_ids={len(key_ids)}")

        else:
            self._send_error(404, f"Unknown action: {action}")

    def log_message(self, format, *args):
        """Custom log format"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


def main():
    """Start the mock ETSI server"""
    server = HTTPServer((HOST, PORT), ETSIRequestHandler)

    print("=" * 50)
    print("Mock ETSI QKD 014 API Server")
    print("=" * 50)
    print(f"Listening on http://{HOST}:{PORT}")
    print()
    print("Available endpoints:")
    print(f"  GET  http://{HOST}:{PORT}/api/v1/keys/{{SAE_ID}}/status")
    print(f"  POST http://{HOST}:{PORT}/api/v1/keys/{{SAE_ID}}/enc_keys")
    print(f"  POST http://{HOST}:{PORT}/api/v1/keys/{{SAE_ID}}/dec_keys")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 50)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
