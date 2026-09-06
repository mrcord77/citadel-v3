# Side-Channel Notes - Citadel V3

**Status:** Internally evaluated; no independent side-channel audit has been performed.

## Allowed External Claim

> Citadel uses constant-time comparison for secret equality, opaque decryption errors,
> and timing screens for shipped paths. It has not undergone an independent side-channel
> audit and does not claim platform-wide constant-time validation.

## What Is Intentionally Uniform

### Error responses

All decryption failures return the same opaque error: `{"error":"decryption failed"}`.
The response does not distinguish wrong key, wrong AAD, wrong context, truncated
ciphertext, replay rejection, or corrupted data.

### Secret comparisons and API authentication

Envelope secret comparisons use constant-time primitives. API keys are stored as
HMAC-SHA256 values and `citadel-api/src/main.rs` compares the encoded hashes with
`subtle::ConstantTimeEq`. The former note that API-key hashes used ordinary `==` was
stale and is superseded.

### Timing at the API layer

The decrypt boundary uses opaque errors and a response-time floor. This reduces obvious
remote timing cliffs but is not a proof that every deployment is timing-independent.

## What Is Not Proven

- **Whole-operation constant time:** ML-KEM and classical KEM behavior ultimately
  depends on providers, generated code, CPU behavior, and deployment conditions.
- **ML-KEM key independence:** Historical whole-key comparisons flagged. Follow-up
  attribution reproduced a public-key-part distinction from public-`rho` matrix
  reconstruction; repeated secret-only screens did not flag. This is a narrower result,
  not a platform-wide proof.
- **Cache and microarchitectural resistance:** Targeted timing and ctgrind work exists,
  but no exhaustive cache, assembly, power/frequency, Spectre-class, or EM analysis has
  been performed.
- **Memory scraping:** Key material exists in process memory during operations.
  Zeroization is used where supported but has not been independently audited.

## Crates Relied On for Timing Properties

| Crate | Use | Evidence boundary |
|---|---|---|
| `x25519-dalek` | X25519 DH | Provider design; not independently verified here |
| `ml-kem` 0.3.2 | ML-KEM | Exact-pinned; conformance and timing tested; not independently audited |
| `p384` 0.14.0 | P-384 ECDH | Constant-time formulas by design; generated assembly not vendor-assessed |
| `aes-gcm` | AEAD | Provider design and local timing screens; platform-dependent |
| `subtle` | Secret equality/selection | Used on explicit comparison paths |
| `hmac` | API-key hashing and stream authentication | Verified through the selected RustCrypto implementation |

## External Audit Priorities

1. ML-KEM decapsulation at source, generated-assembly, and microarchitectural levels.
2. P-384 and X25519 generated code on supported target CPU families.
3. End-to-end decrypt timing under realistic concurrency and response-floor behavior.
4. Key-material lifetime and zeroization across success, failure, and restart paths.

See `TIMING.md` for the timing policy and historical platform results, and
`gauntlet/VALIDATION_FOLLOWUP.md` for the latest targeted attribution.

*Last updated: 2026-09-06*
