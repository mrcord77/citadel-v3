# Citadel

Post-quantum hybrid encryption and key management server.

Citadel combines a classical and a post-quantum key-encapsulation mechanism with AES-256-GCM data encryption, following NIST's hybrid approach for the post-quantum transition. Two envelope suites are supported: **`0xA3`** (X25519 + ML-KEM-768) and **`0xA4`** (P-384 + ML-KEM-1024, NIST category 5, CNSA 2.0-aligned). Applications encrypt and decrypt through a REST API; Citadel manages the keys — generation, rotation, revocation, access control, and audit logging. An optional `fips` feature routes all envelope operations through the AWS-LC cryptographic library (see [Cryptography](#cryptography)).

**Status:** Working beta-stage implementation. Unaudited. No production deployments. The per-claim validation record is [`VALIDATION_MATRIX.md`](VALIDATION_MATRIX.md); see [Security](#security) below.

---

## What It Does

```
Your Application              Citadel                         Database
       |                         |                               |
       |-- POST /encrypt ------->|                               |
       |                         |-- hybrid KEM (X25519+ML-KEM)  |
       |                         |-- derive AES-256 key (HKDF)   |
       |                         |-- encrypt with AES-256-GCM    |
       |<-- encrypted blob ------|                               |
       |                                                         |
       |-- store blob ------------------------------------------>|
```

Your application never touches raw key material. The encrypted blob is self-contained — it includes the wrapped key, algorithm identifiers, and ciphertext. Store it in any database. Decrypt by sending it back to Citadel with the same AAD and context.

## Architecture

The request path runs through three crates (see [Project Structure](#project-structure)
below for all seven):

```
citadel-envelope    Hybrid encryption core (X25519 + ML-KEM-768 + AES-256-GCM)
citadel-keystore    Key lifecycle management, 4-level hierarchy, threat-adaptive policies
citadel-api         HTTP server, scoped API key auth, rate limiting, real-time dashboard
```

## Quick Start

### Docker (recommended)

```bash
# Clone
git clone https://github.com/mrcord77/citadel-v3.git
cd citadel-v3

# Start (dev mode: plaintext key, demo seed — never use this profile in production)
docker compose up -d

# Verify
curl http://localhost:8443/health
# {"status":"ok","version":"0.2.0"}
```

Dashboard (after running the steps above): http://localhost:8443 — sign in with API key `dev-secret` (set by the dev compose file; never use this value outside local development)

For a production deployment (hashed API key, Redis-backed replay protection, TLS),
see [QUICKSTART.md](QUICKSTART.md).

### From Source

Requires a recent stable Rust — see the `rust-version` field in each crate's `Cargo.toml`
for its exact minimum supported version.

> **Note:** Use `rustup` (`rustup toolchain install stable`) rather than a distro-packaged
> `cargo`, which is often too old. The `fips` feature additionally needs clang, CMake, Perl,
> and Go to build AWS-LC; the default pure-Rust build does not.

```bash
cargo build --release -p citadel-api
CITADEL_ENV=development \
CITADEL_ALLOW_PLAINTEXT_KEYS=1 \
CITADEL_API_KEY="your-secret-key" \
CITADEL_SEED_DEMO=true \
./target/release/citadel-api
```

The default build/test graph excludes the comparison-only AWS-LC provider. Compile the
standalone provider comparison explicitly with:

```bash
cargo check -p citadel-envelope --benches --features aws-lc-comparison --locked
```

Run the canonical Ubuntu judge (two unchanged-source runs plus JSON receipts) with:

```bash
bash scripts/test-citadel-ubuntu.sh
```

## Usage

### Python

```python
import requests

api = "http://localhost:8443"
headers = {"Authorization": "Bearer your-secret-key"}

# Encrypt
r = requests.post(f"{api}/api/keys/{dek_id}/encrypt", headers=headers, json={
    "plaintext": "sensitive data",
    "aad": "record-001",        # binds ciphertext to this record
    "context": "patient-records" # application-defined context (structural only)
})
blob = r.json()

# Decrypt
r = requests.post(f"{api}/api/decrypt", headers=headers, json={
    "blob": blob,
    "aad": "record-001",
    "context": "patient-records"
})
plaintext = r.json()["plaintext"]
```

See [citadel_example.py](citadel_example.py) for a complete working example with AAD binding, key rotation, and threat-aware application behavior.

### curl

```bash
# Status
curl http://localhost:8443/api/status -H "Authorization: Bearer $KEY"

# List keys
curl http://localhost:8443/api/keys -H "Authorization: Bearer $KEY"

# Encrypt
curl -X POST http://localhost:8443/api/keys/$DEK_ID/encrypt \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello","aad":"test","context":"demo"}'
```

## API Endpoints

| Endpoint | Method | Scope | Description |
|----------|--------|-------|-------------|
| `/health` | GET | — | Health check |
| `/api/status` | GET | read | Threat level, key counts |
| `/api/metrics` | GET | read | Security metrics |
| `/api/keys` | GET | read | List all keys |
| `/api/keys` | POST | manage | Generate new key |
| `/api/keys/:id` | GET | read | Get key details |
| `/api/keys/:id/activate` | POST | manage | Activate a pending key |
| `/api/keys/:id/rotate` | POST | manage | Rotate key (new version) |
| `/api/keys/:id/revoke` | POST | manage | Permanently revoke key |
| `/api/keys/:id/destroy` | POST | manage | Destroy key material |
| `/api/keys/:id/encrypt` | POST | encrypt | Encrypt data |
| `/api/decrypt` | POST | encrypt | Decrypt data |
| `/api/keys/:id/sign` | POST | encrypt | Sign a message with the key's ML-DSA-65 signing key |
| `/api/verify` | POST | read | Verify an ML-DSA-65 signature |
| `/api/keys/:id/verifying-key` | GET | read | Fetch a key's ML-DSA-65 public verifying key |
| `/api/assertions/issue` | POST | encrypt | Issue a signed assertion |
| `/api/assertions/verify` | POST | read | Verify a signed assertion |
| `/api/threat` | GET | read | Threat intelligence details |
| `/api/threat/event` | POST | manage | Inject a threat event (domain-scoped keys are rejected) |
| `/api/threat/reset` | POST | admin | Reset the adaptive threat level |
| `/api/policies` | GET | read | Active key policies |
| `/api/expire` | POST | admin | Expire keys past their expiry time |
| `/api/auth/whoami` | GET | read | Current API key info |
| `/api/auth/keys` | GET | admin | List API keys |
| `/api/auth/keys` | POST | admin | Create API key |
| `/api/auth/keys/:id` | DELETE | admin | Revoke API key |

## Key Hierarchy

```
Root Key
  └── Domain Key (per environment / business unit)
        └── KEK — Key Encrypting Key (wraps DEKs)
              └── DEK — Data Encrypting Key (encrypts application data)
```

Follows NIST SP 800-57. Each level contains the blast radius of a compromise — a leaked DEK doesn't expose other DEKs because the KEK is separate.

## API Key Scopes

| Scope | Permissions |
|-------|-------------|
| `read` | View keys, status, metrics, threat level |
| `encrypt` | Encrypt and decrypt data |
| `manage` | Create, rotate, revoke, destroy keys |
| `admin` | All of the above + manage API keys |

`admin` implies all other scopes. Principle of least privilege: give monitoring dashboards `read`, application services `read + encrypt`, admin tools `admin`.

## Adaptive Threat System

Citadel monitors security events and automatically adjusts key policies:

| Level | Trigger | Response |
|-------|---------|----------|
| LOW | Normal operations | Standard crypto-periods |
| GUARDED | Minor anomalies | Slightly tighter rotation |
| ELEVATED | Suspicious patterns | Compressed rotation schedules, auto-rotate policy forced on |
| HIGH | Active threat indicators | Further compression, reduced usage limits |
| CRITICAL | Under attack | Maximum restrictions |

Events that raise threat level: failed authentication, decryption failures, rapid access patterns, manual escalation. Score decays over time. "Forced on" tightens the effective *policy* immediately (rotation age, grace period, usage limits) — it does not itself execute a rotation; keys still rotate on their normal schedule check, just against the newly-compressed parameters.

**Try it live:** the dashboard (`http://localhost:8443` after [Quick Start](#quick-start)) has an
"Inject Threat Events" panel that calls this system directly (`POST /api/threat/event`) — click any
event button and watch the Adaptive Policy Engine table update in real time: rotation ages compress,
grace periods shrink, auto-rotate forces on. Click **Reset** to immediately clear the recorded events
and confirm policies relax back to baseline. This is the fastest way to see the adaptive system
actually work rather than take the table above on faith.

## Cryptography

Citadel ships two envelope suites, chosen by a self-describing wire suite byte (no negotiation):

| Suite | Classical KEM | Post-quantum KEM | AEAD | KDF |
|-------|---------------|------------------|------|-----|
| `0xA3` | X25519 (RFC 7748) | ML-KEM-768 (FIPS 203) | AES-256-GCM (SP 800-38D) | HKDF-SHA256 (SP 800-56C) |
| `0xA4` | P-384 (FIPS 186-5) | ML-KEM-1024 (FIPS 203) | AES-256-GCM (SP 800-38D) | HKDF-SHA256 (SP 800-56C) |

`0xA4` is NIST category 5 and CNSA 2.0-aligned. Hybrid construction: both shared secrets are concatenated and fed through HKDF, so security holds if **either** the classical or the post-quantum KEM remains secure.

### FIPS backend (optional `fips` feature)

By default all cryptography runs in pure-Rust crates. Building with `--features fips` routes every envelope operation through the **AWS-LC** cryptographic library, executing inside the exact build that CMVP validated as **AWS-LC-FIPS 3.1.0** (certificates #5298 / #5314), with AES-GCM using the approved random-IV construction (GCM IV Scenario 2).

**This does not make Citadel a FIPS-validated or FIPS-compliant product.** The operating environment is not tested under CMVP; key generation and ML-KEM seed expansion remain pure-Rust; and no regulatory compliance claim is made. The status and its bounds are stated in [`SECURITY_MATURITY.md`](SECURITY_MATURITY.md).

### Wire Format

```
version[1] || suite_kem[1] || suite_aead[1] || flags[1] || kem_ct_len[2] ||
x25519_ephemeral_pk[32] || mlkem768_ct[1088] || nonce[12] || aead_ct[variable]
```

The layout above illustrates suite `0xA3`; suite `0xA4` substitutes a P-384 ephemeral key and the ML-KEM-1024 ciphertext. Self-describing, versioned, no negotiation (prevents downgrade attacks). [SPEC.md](SPEC.md) specifies the v1 wire format; [WIRE_SPEC_V2.md](WIRE_SPEC_V2.md) specifies the current envelope-v2 header.

### Security Properties

- **Constant-time comparison** — API key verification via `subtle` crate prevents timing attacks
- **Zeroization** — All shared secrets and AES keys wrapped in `Zeroizing<T>`, zeroed on drop
- **Uniform errors** — Decryption failures return identical error messages (no decryption oracle)
- **Integrity-chained audit log** — SHA-256 hash chain detects log tampering
- **Rate limiting** — Per-IP token bucket with threat escalation on violations

## Security

Citadel composes NIST-standardized primitives (ML-KEM, X25519, P-384, AES-256-GCM, HKDF-SHA256) from established Rust crates. It does not implement any cryptographic algorithm itself; the work is in correct composition, and in validating that composition thoroughly.

### How we validated and audited it

- **Known-answer tests** against NIST ACVP vectors for ML-KEM-768 and ML-KEM-1024 and Wycheproof vectors for P-384 ECDH, plus a byte-for-byte differential against a second, independent ML-KEM implementation.
- **Adversarial testing** of the envelope on both the pure-Rust and AWS-LC backends: every tampered input in the malleability sweep is rejected, with zero accepted forgeries and zero panics (thousands of mutations and truncations per backend); 200,000 seals produce distinct nonces; and cross-suite envelopes are rejected. This suite was also re-run end to end by a separate automated review gate, which found no accepted forgery, nonce collision, or panic.
- **Machine-checked proof** (CryptoVerif) that the `0xA4` combiner design keeps the derived key secret as long as either the classical or the post-quantum arm survives.
- **Fuzzing** of the wire-format parser, the full decryption path, the seal/open round trip, and the FFI free path.
- **Adversarial keystore and FFI tests**: corrupted ciphertext, replay injection, truncated blobs, wrong-key, null handling, concurrent keygen, wrong-buffer-length, and zero-before-free.
- **Constant-time evaluation** of the shipped paths with dudect (see [TIMING.md](TIMING.md) for the exact results).
- With `--features fips`, the envelope operations execute inside the exact AWS-LC build that CMVP validated as AWS-LC-FIPS 3.1.0 (certificates #5298 / #5314).

The full security model, replay-protection behavior per backend, the primitive table, and the per-claim status are in [SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md).

### What we do not claim

Everything above is our own validation and auditing work, on our own tools and tests. We do not claim any third-party assurance: Citadel has not had an independent third-party security audit, is not FIPS 140-3 / CMVP validated as a deployment, and carries no external certification. As with any pre-audit cryptographic software, evaluate it against your own requirements before relying on it for sensitive data. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Compliance

Mapped against 34 NIST SP 800-57 controls: 26 satisfied, 7 partial, 1 gap. See [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) for the full mapping.

Relevant frameworks: NIST SP 800-57 (key management), CNSA 2.0 (PQC timeline), HIPAA (encryption at rest), SOC 2 (access controls and audit).

## Project Structure

```
citadel-v3/
├── citadel-core/          # Shared types and primitives
├── citadel-envelope/      # Hybrid encryption core (suites 0xA3/0xA4; optional AWS-LC `fips` backend)
├── citadel-keystore/      # Key lifecycle, 4-level hierarchy, adaptive threat policies
├── citadel-api/           # HTTP server, scoped auth, rate limiting, dashboard
├── citadel-cli/           # Command-line interface
├── citadel-signer/        # ML-DSA-65 signing service
├── citadel-ffi/           # C ABI + Python/Java/C bindings
├── LICENSE, LICENSE-EXCEPTION, NOTICE, COPYING, COMMERCIAL_LICENSE.md
├── SPEC.md                # Authoritative wire specification
├── THREAT_MODEL.md        # Security goals and attacker model
├── SECURITY_GUARANTEES.md # What is and is not protected
├── VALIDATION_MATRIX.md   # Per-claim test evidence and gate status
└── COMPLIANCE_MATRIX.md   # NIST 800-57 control mapping
```

## Documentation

| Document | Audience |
|----------|----------|
| [QUICKSTART.md](QUICKSTART.md) | Getting started |
| [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) | SDK integration guide |
| [SPEC.md](SPEC.md) | v1 wire format specification |
| [WIRE_SPEC.md](WIRE_SPEC.md) | v1 wire format, formal RFC-2119 notation |
| [WIRE_SPEC_V2.md](WIRE_SPEC_V2.md) | v2 wire format (current envelope format) |
| [FORMAT.md](FORMAT.md) | Envelope encoding and binding-rules overview |
| [MIGRATION.md](MIGRATION.md) | Python prototype → Rust migration guide |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security goals and assumptions |
| [VALIDATION_MATRIX.md](VALIDATION_MATRIX.md) | Per-claim test evidence and gate status |
| [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) | NIST 800-57 compliance mapping |
| [SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md) | What is and is not protected |
| [SECURITY_MATURITY.md](SECURITY_MATURITY.md) | Deployment-readiness scope and limits |
| [SIDE_CHANNEL_NOTES.md](SIDE_CHANNEL_NOTES.md) | Timing/side-channel status |
| [TIMING.md](TIMING.md) | Full timing/dudect validation record |
| [REPLAY_STORE_GUARANTEES.md](REPLAY_STORE_GUARANTEES.md) | Replay-protection guarantees by backend |
| [REPLAY_TRUST_BOUNDARIES.md](REPLAY_TRUST_BOUNDARIES.md) | Replay-protection trust boundaries |
| [PROVIDER_DECISION_LOG.md](PROVIDER_DECISION_LOG.md) | ML-KEM provider selection history |
| [PROVIDER_BAKEOFF_2026.md](PROVIDER_BAKEOFF_2026.md) | ML-KEM provider bakeoff scorecard |
| [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) | Dependency advisory and license-exception status |
| [CITADEL_OVERVIEW.md](CITADEL_OVERVIEW.md) | Commercial positioning |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [SUPPORT.md](SUPPORT.md) | Support tiers |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution policy |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [API_FREEZE.md](API_FREEZE.md) | API stability guarantees |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment guide |
| [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) | Commercial license terms |

## License

Citadel is dual-licensed:

- **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — for open-source use. Full text in [COPYING](COPYING) / [AGPL-3.0.txt](AGPL-3.0.txt).
- **Commercial License** — for proprietary or commercial use. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

AGPL permits commercial use, provided you comply with its terms — including that if you run a modified version as a network service, you make the source available to users of that service. The commercial license is the alternative for organizations that cannot or do not want to comply with those AGPL obligations (for example, embedding Citadel in a closed-source product or service without releasing source).

**OpenSSL/AWS-LC linking exception.** When built with the `fips` feature, Citadel links the AWS-LC library, which carries code under the OpenSSL License and the Original SSLeay License (both AGPL-incompatible). An additional permission under AGPL section 7 permits conveying that combined build; see [LICENSE-EXCEPTION](LICENSE-EXCEPTION). The default pure-Rust build links no OpenSSL-licensed code and does not rely on the exception. Third-party attributions are collected in [NOTICE](NOTICE).

Contact: commit@reposignal.io

## Author

Andre Cordero — andre.cordero36@gmail.com
