# Citadel Envelope Wire Format v2

**Version:** 2.0.0-draft1  
**Status:** frozen implementation target  
**Date:** 2026-07-15

This document specifies the non-streaming Citadel envelope v2 format. It is
byte complete: every input to parsing, key derivation, and authenticated
encryption has one canonical encoding. The existing v1 decrypt path remains a
migration input. New encryption emits v2.

This is a software protocol specification, not a claim of FIPS validation,
independent review, production certification, or immunity from side channels.

## 1. Notation and limits

- `||` is byte concatenation.
- `BE16`, `BE32`, and `BE64` are unsigned big-endian integers.
- All hashes are SHA3-256 and produce 32 bytes.
- Integers MUST use the fixed width shown; alternate encodings are invalid.

```
MAGIC                 = "CTD2" = 43 54 44 32
VERSION               = 02
FLAGS                 = 00
SUITE_KEM             = A3  # X25519 + ML-KEM-768
SUITE_KDF             = C1  # HKDF-SHA-256
SUITE_AEAD            = B1  # AES-256-GCM
HEADER_LEN            = 98
HEADER_BOUND_LEN      = 86  # HEADER_LEN - NONCE_LEN; the nonce-free prefix bound by the KDF/AAD
KEM_CT_LEN            = 1120
NONCE_LEN             = 12
TAG_LEN               = 16
MIN_ENVELOPE_LEN      = 1234  # HEADER_LEN + KEM_CT_LEN + TAG_LEN
MAX_PLAINTEXT_LEN     = 67108864  # 64 MiB
MAX_AAD_LEN           = 65536     # 64 KiB
MAX_CONTEXT_LEN       = 4096      # 4 KiB
```

## 2. Wire layout

```
Offset  Size  Field
------  ----  ---------------------------------------------------
0       4     magic = 43 54 44 32 ("CTD2")
4       1     version = 02
5       1     flags = 00
6       1     KEM suite = A3
7       1     KDF suite = C1
8       1     AEAD suite = B1
9       1     reserved = 00
10      2     header_len = BE16(98)
12      2     kem_ct_len = BE16(1120)
14      8     plaintext_len = BE64(N)
22      32    recipient_key_hash
54      32    context_hash
86      12    nonce
98      1120  kem_ct = x25519_ephemeral_public || mlkem768_ciphertext
1218    N+16  aead_ct = AES-GCM ciphertext || tag
```

The total length MUST equal `HEADER_LEN + KEM_CT_LEN + plaintext_len +
TAG_LEN`. Truncation, trailing bytes, unknown suite values, nonzero flags or
reserved bytes, and noncanonical lengths MUST be rejected with the same opaque
decryption error.

The first four bytes distinguish envelope v2 from the pre-existing legacy
stream format whose first two bytes are `02 01`. A parser MUST dispatch on the
complete v2 magic before considering legacy formats.

## 3. Header fields

`recipient_key_hash = SHA3-256(serialized_hybrid_public_key)`, where the public
key is exactly the 32-byte X25519 public key followed by the 1184-byte ML-KEM-768
encapsulation key.

`context_hash = SHA3-256(context)`. The full length-prefixed context is also
bound below. The header hash is an early, fixed-width consistency field; it is
not a substitute for authenticating the context itself.

## 4. Canonical encodings

### 4.1 KDF transcript

```
kdf_transcript =
    "citadel-envelope-v2/kdf" || 00 ||
    BE16(HEADER_BOUND_LEN) || header[0..HEADER_BOUND_LEN] ||
    BE16(KEM_CT_LEN) || kem_ct ||
    BE32(len(context)) || context
```

The KDF transcript binds the **nonce-free header prefix** `header[0..86]`, and its
length prefix is `BE16(86)` — **not** the full 98-byte header. The 12-byte nonce at
`header[86..98]` is deliberately excluded: under FIPS Scenario 2 the module generates
the nonce internally during seal (`RandomizedNonceKey`), so the derived key cannot
depend on it. The nonce is still integrity-protected by AES-256-GCM itself — a flipped
nonce yields a wrong tag — so excluding it here does not weaken tamper detection.

### 4.2 AEAD associated data

```
aead_associated_data =
    "citadel-envelope-v2/aad" || 00 ||
    BE16(HEADER_BOUND_LEN) || header[0..HEADER_BOUND_LEN] ||
    BE16(KEM_CT_LEN) || kem_ct ||
    BE32(len(context)) || context ||
    BE32(len(caller_aad)) || caller_aad
```

The associated data binds the same nonce-free header prefix `header[0..86]` as the
KDF transcript (length prefix `BE16(86)`), for the identical reason.

The domain labels include the shown terminal zero byte. No field may be
omitted, reordered, normalized, or encoded with a variable-width integer.

## 5. Hybrid key schedule

The KEM provider produces two 32-byte component secrets:
`x25519_ss` and `mlkem_ss`. X25519 outputs that are not contributory (including
the all-zero shared secret) MUST be rejected.

```
ikm  = x25519_ss || mlkem_ss
salt = SHA256("citadel-envelope-v2/extract-salt")
prk  = HKDF-SHA256-Extract(salt, ikm)
key  = HKDF-SHA256-Expand(prk, kdf_transcript, 32)
```

The 32-byte `key` is used only as the AES-256-GCM key for this envelope.

This construction is a project hybrid combiner design. Use of standardized
components does not by itself make the combined construction NIST-approved.

## 6. Seal

1. Reject plaintext, context, or AAD above their limits.
2. Validate and serialize the recipient public key.
3. Encapsulate X25519 and ML-KEM-768; reject noncontributory X25519.
4. Generate a fresh 12-byte random nonce.
5. Construct the exact header, KEM ciphertext, KDF transcript, and key.
6. Construct the exact AEAD associated data.
7. AES-256-GCM seal the plaintext and return `header || kem_ct || aead_ct`.

A deterministic test-only entry point MAY inject key-generation coins and a
nonce. It MUST be unavailable from default production builds.

## 7. Open

1. Reject context or AAD above their limits.
2. Parse into fixed-size views without attacker-directed allocation.
3. Validate magic, version, suites, flags, reserved byte, canonical lengths,
   plaintext limit, context hash, and exact total length.
4. Decapsulate both KEM components; reject noncontributory X25519.
5. Reconstruct the header and both canonical transcripts exactly as received.
6. Derive the AEAD key and authenticate/decrypt.
7. Derive the recipient public key from the secret key and compare its hash to
   `recipient_key_hash` using constant-time comparison.
8. Release plaintext only if every check succeeds.

Every failure from the public open operation MUST be the same opaque error.
The implementation does not claim constant-time whole-operation behavior;
The timing screens described in `TIMING.md` remain limitations rather than erased evidence.

## 8. Migration and downgrade behavior

- The default seal API MUST emit v2.
- The default open API MUST accept valid v2 and valid historical v1 envelopes.
- An input beginning with `CTD2` MUST never fall back to v1 after any v2 error.
- Unknown versions, mixed headers, stripped magic, suite substitutions, and
  appended bytes MUST fail closed.
- New v1 sealing is unavailable by default. If retained for migration tests, it
  MUST require the explicit `legacy-envelope-v1` Cargo feature and an API whose
  name identifies it as compatibility-only.
- Existing stream-v3 is not changed by this specification. The old stream-v2
  parser remains separately feature gated.

## 9. Required validation artifacts

- Checked-in deterministic valid vector with all intermediate public inputs.
- Independent reconstruction of the KDF and AEAD result for that vector.
- Header, KEM transcript, nonce, ciphertext, tag, context, and caller-AAD
  mutation rejection tests.
- Downgrade and cross-version confusion tests.
- Historical v1 decrypt corpus and migration round trips.
- Property tests for length/truncation/trailing-data rejection.
- Parser fuzzing with no panic, out-of-bounds access, or unbounded allocation.

## 10. References

- NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard.
- NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms.
- NIST SP 800-56C Rev. 2, Recommendation for Key-Derivation Methods.
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function.
- RFC 7748, Elliptic Curves for Security (X25519).
- RFC 5116, An Interface and Algorithms for Authenticated Encryption.

