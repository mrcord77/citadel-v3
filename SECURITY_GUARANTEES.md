# Citadel V3 — Security Guarantees

**Status:** Unaudited beta. These are design-level claims, not independently verified guarantees.
See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## What Citadel Protects

### Confidentiality of encrypted data
Ciphertext produced by Citadel is computationally indistinguishable from random bytes
to any party without access to the corresponding secret key. This holds under the
security of both the classical arm (X25519 ECDH for suite `0xA3`, P-384 ECDH for suite
`0xA4`) and the post-quantum arm (ML-KEM-768 / ML-KEM-1024, NIST FIPS 203), and requires
only one of the two to remain secure (hybrid defense-in-depth). This combiner property
is machine-checked in CryptoVerif for both suites and both arms (abstract-combiner model;
see `THREAT_MODEL.md` "Formal verification").

### Authenticity and integrity of encrypted data
Every ciphertext includes an AES-256-GCM authentication tag. Any modification to the
ciphertext, the AAD, or the context string causes decryption to fail. The system uses
constant-time comparison to prevent timing-based forgery.

### Key material at rest (production mode)
When `CITADEL_MASTER_KEY` is set, all DEK secret keys are wrapped with AES-256-GCM
before storage. A stolen `keys/*.json` file is not useful without the master key.

### Auth failure evidence
Failed authentication attempts are written to the tamper-evident JSONL audit log
(`citadel-audit.jsonl`), not only to the rotating tracing log. Attackers cannot
erase authentication history by rotating log files.

### Audit continuity and persistence errors
The API validates the existing audit log and resumes its sequence/hash chain at startup.
Concurrent audit appends are serialized. A malformed or incomplete log stops startup
without rewriting evidence. A live append failure is latched and causes explicit HTTP
503 responses, including health, until storage is repaired and the process restarted.
Key metadata changes are not transactionally rolled back by an audit error; a 503 may
therefore require checking state before retrying a mutating operation. Local hash chains
need an independent checkpoint to detect complete replacement or tail deletion.

### Replay protection (scope and limits — see below)

---

## Replay Protection Guarantees

### Memory backend (development only)
**Guarantee:** Replays are rejected within a single process lifetime.  
**NOT guaranteed:** After process restart, nonces are forgotten. Any ciphertext captured
before a restart can be replayed within the TTL window (default 24h).  
**Clock drift:** Uses `std::time::Instant` (monotonic). Not affected by wall-clock drift.  
**Storage failure:** N/A — no storage.  
**Use for:** Development and testing only. Never production.

### File backend (single-node production)
**Guarantee:** Each successful claim is persisted before decryption proceeds. The
file and, on Unix, its parent directory are synchronized before acknowledgement.
Claims in `CITADEL_DATA_DIR/replay.json` survive restart within their TTL, assuming
storage honors those synchronization operations. There is no batching window.
Windows crash durability has not been verified by the Linux regression checks.
**NOT guaranteed:** Multi-instance safety. If two API instances share the same data
directory, race conditions can allow a replay to succeed if the ciphertext arrives
at the second instance before replication completes.  
**Clock drift:** TTL uses Unix timestamps (wall clock). Significant clock drift (> minutes)
could cause premature TTL expiry. Use NTP-synchronized clocks.  
**Storage failure:** If `replay.json` cannot be written (`claim()` fails), the replay
store is fail-closed — the decryption is denied. Data integrity is preserved.  
**Use for:** Single-node production deployments.

### Redis backend (multi-node production)
**Guarantee:** Replays are rejected across restarts and across multiple API instances,
as long as all instances share the same Redis cluster.  
**NOT guaranteed:** If Redis becomes unavailable and `fail_closed=true` (recommended),
all decryption is denied. If `fail_closed=false`, a Redis outage creates a replay window.  
**Clock drift:** Redis TTL uses Redis server time. Keep API hosts and Redis time synchronized.  
**Storage failure:** With `fail_closed=true` (default in production): Redis unavailability
causes decryption denial (safe). With `fail_closed=false`: replay window opens during outage.  
**Use for:** Multi-node production deployments.

---

## What Citadel Does NOT Protect

### Against a compromised CITADEL_MASTER_KEY
If the master key is extracted, all stored DEK secret keys can be unwrapped.
Rotate all keys immediately if master key compromise is suspected.

### Against a compromised server process
Citadel holds decrypted DEK material in memory during key operations. A process-level
attacker with memory access can extract key material.

### Against operator misconfiguration
Citadel enforces hard startup gates. It cannot protect against:
- Using a weak or reused master key
- Disabling fail-closed replay with `fail_closed=false`
- Running in development mode (`CITADEL_ENV=development`) in production
- Skipping key rotation beyond policy intervals

### Against timing side-channels in external systems
The core crypto operations use constant-time comparison (via `subtle::ConstantTimeEq`).
Network timing, OS scheduling, and CPU cache effects in the surrounding system are
outside Citadel's control.

### Key lifecycle without operator action
Citadel enforces expiry policies automatically (background task every 60s). However,
rotation and rewrap require operator initiation. Keys do not self-rotate.

---

## Multi-Instance Assumptions

Multiple API instances can share a Redis replay store safely.
Multiple API instances MUST NOT share a file replay store.
Multiple API instances sharing a load balancer: per-IP rate limiting is per-instance
(effective rate = configured RPS × instance count).

---

## Required Operator Actions for Security Model to Hold

1. `CITADEL_MASTER_KEY` must be unique, 32 bytes of OS-CSPRNG entropy, never reused.
2. `CITADEL_REPLAY_STORE=file` or `=redis` must be set in any non-development deployment.
3. Key rotation must be performed before policy expiry (see `check_rotation_due()`).
4. `citadel-audit.jsonl` must be backed up to append-only storage outside the API host.
5. Master key must be stored in a secrets manager (Vault, AWS KMS, etc.), not in env files.

---

## Cryptographic Primitives

| Primitive | Algorithm | Standard | Version |
|-----------|-----------|----------|---------|
| KEM classical (`0xA3`) | X25519 ECDH | RFC 7748 | x25519-dalek 2.x |
| KEM classical (`0xA4`) | P-384 ECDH | NIST SP 800-186 / SEC1 | p384 =0.14.0 |
| KEM post-quantum (`0xA3`) | ML-KEM-768 | NIST FIPS 203 | ml-kem =0.3.2 |
| KEM post-quantum (`0xA4`) | ML-KEM-1024 | NIST FIPS 203 | ml-kem =0.3.2 |
| AEAD | AES-256-GCM | NIST SP 800-38D | aes-gcm 0.10 |
| KDF | HKDF-SHA256 | RFC 5869 | hkdf 0.12 |
| MAC (auth) | HMAC-SHA256 | RFC 2104 | hmac 0.12 |
| Hash | SHA-256 / SHA3-256 | FIPS 180-4 | sha2/sha3 0.10 |

### Note on ml-kem crate status

The `ml-kem` crate implements NIST FIPS 203 (ML-KEM, formerly Kyber). The crate
carries an "experimental" designation in its own documentation, meaning it has not yet
received a formal third-party security audit.

**This does not reduce Citadel's `0xA3` security guarantee** because of the hybrid design:
an attacker must break BOTH X25519 and ML-KEM-768 to recover the shared secret. If
ML-KEM-768 is broken (by cryptanalysis or implementation flaw), X25519 still protects
the plaintext. The hybrid construction provides defense-in-depth. The same reasoning
applies to `0xA4` (P-384 + ML-KEM-1024).

---

## Audit Status

**Independent security audit: NOT COMPLETED.**  
This document reflects design intent and code inspection. No external party has
verified these guarantees hold in the implementation. Do not rely on these guarantees
for production deployments of sensitive data until an independent audit is complete.
