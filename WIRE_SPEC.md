# Citadel Envelope Wire Format — Formal Specification

**Version:** 1.0.0  
**Status:** SUPERSEDED — NON-NORMATIVE (see quarantine notice below)  
**Date:** 2026-01-28

---

> ## ⚠️ QUARANTINE NOTICE — DO NOT IMPLEMENT FROM THIS DOCUMENT
>
> This document describes a v1 key schedule that **was never shipped**. Its HKDF
> labels (`citadel-hybrid-v1`, `citadel-hybrid-env-v1|aes|`) and two-stage
> derivation **do not exist anywhere in the Citadel source** — a search of the
> codebase returns zero matches. Anyone implementing an interoperable encoder
> from the key schedule below will derive **different AES keys** and produce
> **ciphertexts that Citadel cannot decrypt**.
>
> **The normative v1 wire specification is [`SPEC.md`](SPEC.md).** It matches the
> shipped `citadel-envelope` crate: a single HKDF-SHA256 derivation with labels
> `citadel-env-v1` / `citadel-env-v1|aes|`. Implement from `SPEC.md`, not from
> this file.
>
> Everything below this notice is retained for historical reference only and
> carries no normative weight.

---

## 1. Notation

- `||` denotes concatenation
- `[N]` denotes a byte array of exactly N bytes
- `BE16(x)` denotes big-endian encoding of 16-bit integer x
- `MUST`, `MUST NOT`, `SHALL` per RFC 2119

---

## 2. Constants

```
VERSION             = 0x01
SUITE_KEM_HYBRID    = 0xA3      # X25519 + ML-KEM-768
SUITE_AEAD_GCM      = 0xB1      # AES-256-GCM

HEADER_BYTES        = 6
X25519_CT_BYTES     = 32
MLKEM768_CT_BYTES   = 1088
KEM_CT_BYTES        = 1120      # X25519_CT + MLKEM768_CT
NONCE_BYTES         = 12
TAG_BYTES           = 16
MIN_CIPHERTEXT      = 1154      # HEADER + KEM_CT + NONCE + TAG

X25519_PK_BYTES     = 32
X25519_SK_BYTES     = 32
MLKEM768_EK_BYTES   = 1184      # Encapsulation key
MLKEM768_DK_BYTES   = 2400      # Decapsulation key
HYBRID_PK_BYTES     = 1216      # X25519_PK + MLKEM768_EK
HYBRID_SK_BYTES     = 2432      # X25519_SK + MLKEM768_DK

SHARED_SECRET_BYTES = 32
AES_KEY_BYTES       = 32

MAX_AAD_BYTES       = 65536
MAX_CONTEXT_BYTES   = 256
MAX_PLAINTEXT_BYTES = 4294967295
```

---

## 3. Wire Format

### 3.1 Ciphertext Layout

```
Offset  Size   Field          Value/Description
------  ----   -----          -----------------
0       1      version        0x01 (fixed)
1       1      suite_kem      0xA3 (X25519+ML-KEM-768)
2       1      suite_aead     0xB1 (AES-256-GCM)
3       1      flags          0x00 (reserved, must be zero)
4       2      kem_ct_len     0x0460 (BE16(1120))
6       32     x25519_ct      X25519 ephemeral public key
38      1088   mlkem_ct       ML-KEM-768 ciphertext
1126    12     nonce          AES-GCM nonce
1138    N+16   aead_ct        AES-GCM(plaintext) || tag
```

Total length: `1154 + plaintext_len` bytes

### 3.2 Public Key Layout

```
Offset  Size   Field          Description
------  ----   -----          -----------
0       32     x25519_pk      X25519 public key
32      1184   mlkem_ek       ML-KEM-768 encapsulation key
```

Total: 1216 bytes

### 3.3 Secret Key Layout

```
Offset  Size   Field          Description
------  ----   -----          -----------
0       32     x25519_sk      X25519 secret scalar
32      2400   mlkem_dk       ML-KEM-768 decapsulation key
```

Total: 2432 bytes

---

## 4. Key Schedule

### 4.1 Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        ENCAPSULATION                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────────┐                               │
│  │ X25519   │───►│ x25519_ss    │──┐                            │
│  │ ECDH     │    │ (32 bytes)   │  │                            │
│  └──────────┘    └──────────────┘  │                            │
│                                    ▼                            │
│  ┌──────────┐    ┌──────────────┐  ┌──────────────────┐         │
│  │ ML-KEM   │───►│ mlkem_ss     │──┤ combined_ikm     │         │
│  │ Encap    │    │ (32 bytes)   │  │ (64 bytes)       │         │
│  └──────────┘    └──────────────┘  └────────┬─────────┘         │
│                                             │                   │
│                                             ▼                   │
│                               ┌─────────────────────────┐       │
│                               │ HKDF-SHA256             │       │
│                               │ info="citadel-hybrid-v1"│       │
│                               └────────────┬────────────┘       │
│                                            │                    │
│                                            ▼                    │
│                               ┌─────────────────────────┐       │
│                               │ shared_secret           │       │
│                               │ (32 bytes)              │       │
│                               └────────────┬────────────┘       │
└────────────────────────────────────────────┼────────────────────┘
                                             │
┌────────────────────────────────────────────┼────────────────────┐
│                     KEY DERIVATION         │                    │
├────────────────────────────────────────────┼────────────────────┤
│                                            ▼                    │
│  ┌──────────┐    ┌──────────────────────────────────────────┐   │
│  │ kem_ct   │───►│ SHA3-256(kem_ct) ──► ct_hash (32 bytes)  │   │
│  │(1120 B)  │    └──────────────────────────────────────────┘   │
│  └──────────┘                              │                    │
│                                            ▼                    │
│                               ┌─────────────────────────────┐   │
│                               │ info = "citadel-hybrid-env- │   │
│                               │         v1|aes|"            │   │
│                               │       || ct_hash            │   │
│                               │       || context            │   │
│                               └────────────┬────────────────┘   │
│                                            │                    │
│                                            ▼                    │
│                               ┌─────────────────────────┐       │
│                               │ HKDF-SHA256             │       │
│                               │ ikm = shared_secret     │       │
│                               │ salt = None             │       │
│                               │ len = 32                │       │
│                               └────────────┬────────────┘       │
│                                            │                    │
│                                            ▼                    │
│                               ┌─────────────────────────┐       │
│                               │ aes_key (32 bytes)      │       │
│                               └─────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Domain Separation Labels

| Stage | Label | Purpose |
|-------|-------|---------|
| Shared Secret | `"citadel-hybrid-v1"` | Combines X25519 + ML-KEM |
| AES Key | `"citadel-hybrid-env-v1\|aes\|" \|\| ct_hash \|\| context` | Binds to ciphertext + application context |

---

## 5. Algorithms

### 5.1 Encrypt(pk, plaintext, aad, context)

```
REQUIRE: len(aad) <= MAX_AAD_BYTES
REQUIRE: len(context) <= MAX_CONTEXT_BYTES
REQUIRE: len(plaintext) <= MAX_PLAINTEXT_BYTES

1.  x25519_eph_sk, x25519_eph_pk = X25519.keygen()
2.  x25519_ss = X25519.dh(x25519_eph_sk, pk.x25519)
3.  mlkem_ct, mlkem_ss = ML-KEM-768.Encaps(pk.mlkem)
4.  combined_ikm = x25519_ss || mlkem_ss
5.  shared_secret = HKDF-Extract-Expand(
        ikm = combined_ikm,
        salt = empty,
        info = "citadel-hybrid-v1",
        len = 32
    )
6.  kem_ct = x25519_eph_pk || mlkem_ct
7.  ct_hash = SHA3-256(kem_ct)
8.  info = "citadel-hybrid-env-v1|aes|" || ct_hash || context
9.  aes_key = HKDF-Extract-Expand(
        ikm = shared_secret,
        salt = empty,
        info = info,
        len = 32
    )
10. nonce = random(12)
11. aead_ct = AES-256-GCM.Seal(aes_key, nonce, plaintext, aad)
12. header = [0x01, 0xA3, 0xB1, 0x00, 0x04, 0x60]
13. RETURN header || kem_ct || nonce || aead_ct
```

### 5.2 Decrypt(sk, ciphertext, aad, context)

```
REQUIRE: len(aad) <= MAX_AAD_BYTES
REQUIRE: len(context) <= MAX_CONTEXT_BYTES

1.  IF len(ciphertext) < MIN_CIPHERTEXT: RETURN DecryptionError
2.  IF ciphertext[0] != 0x01: RETURN DecryptionError
3.  IF ciphertext[1] != 0xA3: RETURN DecryptionError
4.  IF ciphertext[2] != 0xB1: RETURN DecryptionError
5.  IF ciphertext[3] != 0x00: RETURN DecryptionError
6.  IF BE16(ciphertext[4:6]) != 1120: RETURN DecryptionError
7.  x25519_ct = ciphertext[6:38]
8.  mlkem_ct = ciphertext[38:1126]
9.  nonce = ciphertext[1126:1138]
10. aead_ct = ciphertext[1138:]
11. IF len(aead_ct) < TAG_BYTES: RETURN DecryptionError
12. x25519_ss = X25519.dh(sk.x25519, x25519_ct)
13. mlkem_ss = ML-KEM-768.Decaps(sk.mlkem, mlkem_ct)
14.     // ML-KEM uses implicit rejection internally
15. combined_ikm = x25519_ss || mlkem_ss
16. shared_secret = HKDF-Extract-Expand(
        ikm = combined_ikm,
        salt = empty,
        info = "citadel-hybrid-v1",
        len = 32
    )
17. kem_ct = x25519_ct || mlkem_ct
18. ct_hash = SHA3-256(kem_ct)
19. info = "citadel-hybrid-env-v1|aes|" || ct_hash || context
20. aes_key = HKDF-Extract-Expand(
        ikm = shared_secret,
        salt = empty,
        info = info,
        len = 32
    )
21. plaintext = AES-256-GCM.Open(aes_key, nonce, aead_ct, aad)
22.     // On failure: RETURN DecryptionError
23. RETURN plaintext
```

---

## 6. Security Requirements

### 6.1 Error Uniformity

All decryption failures MUST return an identical, opaque error. Implementations MUST NOT distinguish:

- Wire format validation failures
- KEM decapsulation failures
- AEAD authentication failures
- Wrong key / wrong AAD / wrong context

### 6.2 Timing Uniformity

Implementations SHOULD ensure decrypt() timing does not vary significantly based on:

- Which validation check fails
- Position of tampered bytes
- Presence/absence of authentication failure

### 6.3 Constraint Validation Order

1. AAD length MUST be validated before any cryptographic operation
2. Context length MUST be validated before any cryptographic operation
3. Plaintext length MUST be validated before any cryptographic operation
4. Wire format MUST be validated before KEM decapsulation

---

## 7. Interoperability Notes

### 7.1 ML-KEM-768 Ciphertext

The `mlkem_ct` field contains the raw 1088-byte ML-KEM-768 ciphertext as specified in FIPS 203. No additional framing.

### 7.2 X25519 Public Key

The `x25519_ct` field contains the raw 32-byte X25519 public key (u-coordinate). No additional framing.

### 7.3 Byte Order

All multi-byte integers are big-endian.

### 7.4 HKDF Salt

All HKDF operations use an empty (zero-length) salt, which causes HKDF-Extract to use a zero-filled key of HashLen bytes.

---

## 8. Test Vector Format

Test vectors are provided in JSON format with hex-encoded byte strings:

```json
{
  "name": "basic_roundtrip",
  "seed": "hex...",           // For deterministic keygen (if applicable)
  "public_key": "hex...",
  "secret_key": "hex...",
  "plaintext": "hex...",
  "aad": "hex...",
  "context": "hex...",
  "nonce": "hex...",          // Fixed nonce for reproducibility
  "ciphertext": "hex...",
  "expected": "success" | "failure"
}
```

See `test_vectors.json` for canonical test vectors.

---

## 9. References

- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 5116: An Interface and Algorithms for Authenticated Encryption
- NIST SP 800-56C Rev. 2: Recommendation for Key-Derivation Methods
