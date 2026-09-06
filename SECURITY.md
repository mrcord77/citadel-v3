# Security Policy

## Current Status

**Citadel is unaudited software.**

The implementation:
- Uses NIST-standardized primitives (ML-KEM-768, ML-KEM-1024, P-384, AES-256-GCM, HKDF-SHA256, X25519)
- Follows established hybrid construction patterns (`0xA3`: X25519 + ML-KEM-768; `0xA4`: P-384 + ML-KEM-1024)
- Has broad automated coverage; CI [run 31141328479](https://github.com/mrcord77/citadel-v3/actions/runs/31141328479) (2026-08-06) passed 500 tests across the workspace, ACVP/KAT, and stress suites combined, with 9 explicitly ignored and 0 failed
- Has dudect-based timing validation covering all attacker-controlled-input classes
- Has NOT undergone independent security audit

## Supported Versions

| Version | Support Status |
|---------|---------------|
| 0.2.x   | Active (security fixes) |
| < 0.2   | Unsupported |

Only the latest release receives security fixes.

## Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

### Preferred: GitHub Security Advisory

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Provide details (see below)

### Alternative: Direct Contact

Email: andre.cordero36@gmail.com

### What to Include

- Affected versions / commit hash
- Minimal reproduction case
- Expected vs. actual behavior
- Impact assessment
- Whether timing side-channels or DoS is involved

### Response Timeline

| Severity | Initial Response | Target Fix |
|----------|-----------------|------------|
| Critical | 24 hours | 72 hours |
| High     | 48 hours | 1 week |
| Medium   | 1 week | 2 weeks |
| Low      | 2 weeks | Next release |

## Scope

### In Scope

- **Memory safety** — parsing panics, buffer overflows, use-after-free
- **Cryptographic correctness** — wrong outputs, key leakage, nonce reuse
- **Oracle behavior** — distinguishable errors that leak information
- **Misuse resistance failures** — accepting malformed inputs, downgrade attacks
- **Key handling bugs** — missing zeroization, accidental exposure
- **Wire format vulnerabilities** — version confusion, suite downgrade

### Out of Scope

- Key management, access control, or compliance certification
- Platform-level compromise (OS, hardware)
- Side-channel attacks requiring physical access or co-residency
- Denial of service via large inputs (documented limitation)
- Issues in dependencies (report upstream, notify us)

## Security Guarantees

### What We Guarantee

1. **Hybrid security** — if either X25519 or ML-KEM-768 remains secure, plaintext is protected
2. **AAD/context binding** — wrong AAD or context causes decryption failure
3. **Tampering detection** — any modification to ciphertext causes failure
4. **Uniform errors** — all decryption failures produce identical error type
5. **Wire format stability** — v1 format will always be decodable
6. **Attacker-controlled-input timing** — dudect validation passes for all classes where the attacker varies the input (ciphertext, tag, AAD, KEM bytes)

### What We Do NOT Guarantee

1. **Key-material timing independence** — historical whole-key ML-KEM comparisons produced timing differences on tested x86-64 providers. Follow-up RustCrypto attribution reproduced a large public-key-part distinction caused by public-`rho` matrix reconstruction, while repeated secret-only screens and their controls did not flag. This narrows but does not erase the platform-level limitation or establish constant-time behavior on every target; see `TIMING.md` and `gauntlet/VALIDATION_FOLLOWUP.md`.
2. **Side-channel resistance** — not tested against power/EM/cache attacks beyond dudect
3. **FIPS compliance** — uses NIST primitives, not a certified module
4. **Constant-time validation** — source code follows CT discipline, but hardware data-dependent execution is unresolved

## Dependency Security

Citadel depends on:

| Crate | Purpose | Version | Maintainer |
|-------|---------|---------|-----------|
| `ml-kem` | Post-quantum KEM (ML-KEM-768) | =0.3.2 | RustCrypto |
| `ml-dsa` | Post-quantum signatures (ML-DSA-65) | =0.1.0-rc.9 | RustCrypto |
| `x25519-dalek` | Classical ECDH | 2.x | Dalek |
| `aes-gcm` | Symmetric encryption | 0.10 | RustCrypto |
| `hkdf` | Key derivation | 0.12 | RustCrypto |
| `sha2`, `sha3` | Hash functions | 0.10 | RustCrypto |
| `zeroize` | Secure memory clearing | 1.7 | RustCrypto |
| `subtle` | Constant-time operations | 2.5 | Dalek |

All cryptographic dependencies are exact-pinned; any upgrade is an explicit, reviewed decision.

### ML-KEM provider: RustCrypto `ml-kem 0.3.2`

The production ML-KEM-768 provider is RustCrypto `ml-kem 0.3.2`, pinned exactly with zeroization enabled. It passes the checked-in 25 keygen, 25 encapsulation, and 10 decapsulation final FIPS 203 vectors directly through Citadel's selected provider, a 10,000-round-trip release test, negative key/import tests, and differential checks against libcrux. The replaced PQClean chain and its RUSTSEC-2026-0161 through -0163 advisories are absent from the production lockfile. RustCrypto explicitly states that this crate has not been independently audited; local conformance tests do not erase that limitation. See `PROVIDER_BAKEOFF_2026.md` and `PROVIDER_DECISION_LOG.md`.

The 60 bundled ACVP vectors (25 keygen, 25 encapsulation, 10 decapsulation) execute directly through the selected RustCrypto provider under the test-only `kat` feature. The same vectors also run through libcrux and are compared byte-for-byte as an independent differential check. Deterministic encapsulation is never used by normal production operations.

We track security advisories for all dependencies via `cargo audit`.

### ML-DSA provider assurance

The signing path exact-pins `ml-dsa 0.1.0-rc.9` and enables its secret-key
zeroization feature. That proves a memory-lifecycle property, not independent
implementation assurance. Direct official FIPS 204 vectors through the exact
release path and a maintained-provider assurance decision remain open work,
tracked internally.

### Build toolchain requirement

**Minimum build toolchain: Rust / Cargo 1.74+**

No C compiler is required: the production cryptographic providers (RustCrypto
`ml-kem`, `ml-dsa`, `aes-gcm`, `x25519-dalek`, `hkdf`) are pure Rust. (The retired
PQClean chain, which needed a `cc` C compiler, is no longer in the tree.)

## Timing Validation

See `TIMING.md` for the complete timing validation model, including:
- Secret/public inventories
- Enforced invariants
- Known limitation: key-value-dependent decapsulation timing (platform-level)
- Bare-metal dudect results across three providers
- Attacker-controlled-input class pass/fail
- Required grant/security wording
- Production risk assessment and mitigations
- Follow-up work priorities

## Upgrade Policy

### Minor Versions (0.2.x → 0.2.y)

- Bug fixes and security patches
- No breaking API changes
- Wire format compatible
- Safe to upgrade immediately

### Post-1.0 Policy

- Semantic versioning strictly followed
- LTS versions designated annually
- Security fixes backported to LTS

## Incident Response

If a critical vulnerability is discovered:

1. **Immediate** — assess scope and impact
2. **24 hours** — develop patch, prepare advisory
3. **48 hours** — release patched version
4. **72 hours** — publish security advisory
5. **1 week** — post-mortem published

## Cryptographic Agility

The wire format includes suite identifiers to support future algorithms:

- New KEM suites can be added (different `suite_kem` byte)
- New AEAD suites can be added (different `suite_aead` byte)
- Old suites remain decodable (no silent downgrades)

## Audit Status

| Component | Method | Status |
|-----------|--------|--------|
| ACVP KAT vectors | 60/60 through the RustCrypto production provider directly, + byte-for-byte libcrux differential | Internal, automated |
| Primitive conformance | Google Wycheproof vectors through the exact pinned aes-gcm / x25519 / hkdf | Internal, 0 failures |
| Envelope composition | proptest vs the real `Citadel::seal/open` (tamper, wrong-key, AAD/context binding, no-downgrade) | Internal |
| Memory safety | `cargo miri` (UB) + AddressSanitizer on the FFI | Internal, 0 findings |
| Parser panic/UB-freedom | Kani bounded model checking (proof, not sample) | Internal, verified ≤256B |
| Key-lifecycle & domain isolation | proptest vs the real keystore state machine + cross-domain isolation tests | Internal |
| Concurrency | Loom exhaustive interleaving (one-shot capability nonce) | Internal |
| Constant-time | dudect + ctgrind (valgrind) localized to the ml-kem dependency | Internal |
| Protocol | ProVerif symbolic model (secrecy + no-downgrade proved) | Internal |
| Fuzz testing | cargo-fuzz + continuous ClusterFuzzLite (daily, persistent corpus) | Ongoing |
| Combiner design | analytical review vs the KEM-combiner literature | Internal, no flaw found |

See `gauntlet/` and `gauntlet/receipts/SUMMARY.md` for the full free-validation
battery and machine-readable receipts.

**No independent audit has been conducted.** All rows above are internal
self-validation (external tools, but not an independent auditor's sign-off).

## Contact

- **Security issues**: andre.cordero36@gmail.com
- **General questions**: GitHub Discussions
- **Commercial support**: andre.cordero36@outlook.com
