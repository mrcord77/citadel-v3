#!/usr/bin/env python3
"""
Citadel Integration Example
============================

This script demonstrates how an application integrates with Citadel
for post-quantum encryption of sensitive data.

Scenario: A healthcare application encrypts patient records before
storing them in a database. Each record is encrypted with a
Citadel-managed DEK, with AAD binding to prevent record substitution.

Prerequisites:
    pip install requests

Usage:
    # Set your Citadel API key (encrypt scope required)
    export CITADEL_API_KEY="your-api-key-here"

    # Run the example
    python citadel_example.py
"""

import os
import sys
import json
import base64
import requests
from datetime import datetime


# ---------------------------------------------------------------------------
# Citadel client
# ---------------------------------------------------------------------------

class CitadelClient:
    """Minimal Citadel API client for application integration."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def health(self) -> dict:
        """Check API health."""
        r = self.session.get(f"{self.base_url}/health")
        r.raise_for_status()
        return r.json()

    def list_keys(self) -> list:
        """List all crypto keys."""
        r = self.session.get(f"{self.base_url}/api/keys")
        r.raise_for_status()
        return r.json()

    def get_active_dek(self) -> str | None:
        """Find an active DEK suitable for encryption."""
        keys = self.list_keys()
        for k in keys:
            state = k.get("state", "").lower()
            ktype = k.get("key_type", "").lower()
            if state == "active" and ktype == "dataencrypting":
                return k["id"]
        return None

    def encrypt(self, key_id: str, plaintext: str, aad: str, context: str) -> dict:
        """
        Encrypt data using a Citadel-managed key.

        Args:
            key_id:    UUID of the DEK to use
            plaintext: Data to encrypt (will be UTF-8 encoded)
            aad:       Additional authenticated data (bound to ciphertext,
                       must match on decryption)
            context:   Domain separation context (e.g., "patient-records")

        Returns:
            Encrypted blob (JSON dict) - store this in your database.
        """
        r = self.session.post(
            f"{self.base_url}/api/keys/{key_id}/encrypt",
            json={"plaintext": plaintext, "aad": aad, "context": context},
        )
        r.raise_for_status()
        return r.json()

    def decrypt(self, blob: dict, aad: str, context: str) -> str:
        """
        Decrypt a Citadel-encrypted blob.

        Args:
            blob:    The encrypted blob exactly as returned by encrypt()
            aad:     Must match the AAD used during encryption
            context: Must match the context used during encryption

        Returns:
            Decrypted plaintext string.
        """
        r = self.session.post(
            f"{self.base_url}/api/decrypt",
            json={"blob": blob, "aad": aad, "context": context},
        )
        r.raise_for_status()
        return r.json()["plaintext"]

    def rotate_key(self, key_id: str) -> str:
        """Rotate a key, returning the new key ID."""
        r = self.session.post(f"{self.base_url}/api/keys/{key_id}/rotate")
        r.raise_for_status()
        return r.json()["new_key_id"]

    def threat_status(self) -> dict:
        """Get current threat level."""
        r = self.session.get(f"{self.base_url}/api/status")
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Example: Healthcare record encryption
# ---------------------------------------------------------------------------

def demo_patient_record_encryption(client: CitadelClient):
    """
    Demonstrates encrypting patient records with AAD binding.

    AAD (Additional Authenticated Data) binds the ciphertext to a specific
    record ID. If someone swaps ciphertext between records, decryption
    fails -- preventing record substitution attacks.
    """
    print("\n--- Patient Record Encryption ---\n")

    # Find an active DEK
    dek_id = client.get_active_dek()
    if not dek_id:
        print("ERROR: No active DEK found. Create one first.")
        return
    print(f"Using DEK: {dek_id[:12]}...")

    # Simulate patient records
    patients = [
        {"record_id": "PAT-001", "name": "Jane Doe", "ssn": "123-45-6789",
         "diagnosis": "Type 2 Diabetes", "medications": ["Metformin 500mg"]},
        {"record_id": "PAT-002", "name": "John Smith", "ssn": "987-65-4321",
         "diagnosis": "Hypertension", "medications": ["Lisinopril 10mg"]},
    ]

    encrypted_records = []

    for patient in patients:
        record_id = patient["record_id"]
        sensitive_data = json.dumps({
            "ssn": patient["ssn"],
            "diagnosis": patient["diagnosis"],
            "medications": patient["medications"],
        })

        # AAD = record ID -- binds ciphertext to this specific record
        # Context = application domain -- separates from other use cases
        blob = client.encrypt(
            key_id=dek_id,
            plaintext=sensitive_data,
            aad=record_id,
            context="patient-records",
        )

        encrypted_records.append({
            "record_id": record_id,
            "name": patient["name"],  # Name stored in cleartext (searchable)
            "encrypted_data": blob,   # Everything else encrypted
        })
        print(f"  Encrypted {record_id}: {len(json.dumps(blob))} bytes")

    # Decrypt a record
    print("\n--- Decryption ---\n")

    rec = encrypted_records[0]
    plaintext = client.decrypt(
        blob=rec["encrypted_data"],
        aad=rec["record_id"],      # Must match what was used to encrypt
        context="patient-records",  # Must match
    )
    data = json.loads(plaintext)
    print(f"  Decrypted {rec['record_id']}:")
    print(f"    SSN: {data['ssn']}")
    print(f"    Diagnosis: {data['diagnosis']}")
    print(f"    Medications: {data['medications']}")

    # Demonstrate AAD binding -- wrong record ID fails
    print("\n--- AAD Binding Enforcement ---\n")

    try:
        client.decrypt(
            blob=encrypted_records[0]["encrypted_data"],
            aad="PAT-002",  # Wrong record ID!
            context="patient-records",
        )
        print("  ERROR: Should have failed!")
    except requests.HTTPError as e:
        print(f"  Correctly rejected: wrong AAD (record ID mismatch)")
        print(f"  This prevents swapping ciphertext between records.")

    return encrypted_records


def demo_key_rotation(client: CitadelClient, encrypted_records: list):
    """
    Demonstrates key rotation with backward-compatible decryption.

    After rotation, old ciphertext still decrypts (the old key version
    enters a grace period). New encryptions use the new key.
    """
    print("\n--- Key Rotation ---\n")

    dek_id = client.get_active_dek()
    print(f"  Current DEK: {dek_id[:12]}...")

    # Rotate the key
    new_dek_id = client.rotate_key(dek_id)
    print(f"  Rotated to:  {new_dek_id[:12]}...")

    # Old ciphertext still decrypts (grace period)
    rec = encrypted_records[0]
    plaintext = client.decrypt(
        blob=rec["encrypted_data"],
        aad=rec["record_id"],
        context="patient-records",
    )
    print(f"  Old ciphertext still decrypts: OK")

    # New encryptions use the new key
    new_blob = client.encrypt(
        key_id=new_dek_id,
        plaintext='{"test": "new encryption"}',
        aad="PAT-003",
        context="patient-records",
    )
    print(f"  New encryption with rotated key: OK")


def demo_threat_awareness(client: CitadelClient):
    """
    Shows how an application can check threat level and adapt behavior.

    At elevated threat levels, Citadel automatically tightens key rotation
    schedules and usage limits. Applications can also check the threat
    level and implement their own defensive measures.
    """
    print("\n--- Threat-Aware Application ---\n")

    status = client.threat_status()
    level = status["threat_level"]
    name = status["threat_name"]
    score = status["threat_score"]

    print(f"  Threat level: {name} ({level}/5)")
    print(f"  Threat score: {score:.1f}")

    # Application-level defensive measures based on threat level
    if level >= 4:
        print("  ACTION: Suspending bulk data exports")
        print("  ACTION: Requiring MFA for all operations")
        print("  ACTION: Alerting security team")
    elif level >= 3:
        print("  ACTION: Enabling enhanced audit logging")
        print("  ACTION: Reducing session timeouts")
    else:
        print("  STATUS: Normal operations")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    base_url = os.environ.get("CITADEL_URL", "http://localhost:8443")
    api_key = os.environ.get("CITADEL_API_KEY", "")

    if not api_key:
        print("Set CITADEL_API_KEY environment variable to your API key.")
        print("  The key needs 'read' and 'encrypt' scopes.")
        print()
        print("Example:")
        print("  export CITADEL_API_KEY='your-api-key-here'")
        print("  python citadel_example.py")
        sys.exit(1)

    client = CitadelClient(base_url, api_key)

    # Verify connection
    try:
        health = client.health()
        print(f"Connected to Citadel {health.get('version', '?')}")
    except Exception as e:
        print(f"Failed to connect to {base_url}: {e}")
        sys.exit(1)

    # Run demos
    encrypted = demo_patient_record_encryption(client)
    if encrypted:
        demo_key_rotation(client, encrypted)
    demo_threat_awareness(client)

    print("\n--- Done ---\n")
    print("This example demonstrated:")
    print("  1. Encrypting sensitive fields with AAD binding")
    print("  2. AAD enforcement preventing record substitution")
    print("  3. Key rotation with backward-compatible decryption")
    print("  4. Threat-aware application behavior")
    print()
    print("In production, the encrypted_data blob is what you store in")
    print("your database. The application never handles raw key material.")


if __name__ == "__main__":
    main()
