# Citadel timing validation model

Citadel's timing rule is secret independence, not equal time for every input.

Constant-time discipline means control flow, memory access patterns, and timing must not depend on secrets. It does not mean attacker-chosen malformed public inputs must cost the same as valid ciphertexts. Public-format differences are allowed to differ in timing when the attacker can classify the input without knowing any secret.

## Secret and public inventories

Secrets:

- decapsulation/private keys;
- decapsulated shared secrets;
- KDF output and AEAD keys;
- tag-comparison intermediates;
- unauthenticated plaintext before authentication succeeds.

Public inputs / public outcomes:

- envelope length and structural parse validity;
- public suite/version/header bytes;
- attacker-provided AAD and context;
- the success/failure bit returned by the API;
- library-level public-format class, such as truncated vs parse-valid ciphertext.

## Enforced invariants

- Secret comparisons must use constant-time primitives such as `subtle`.
- KEM decapsulation must not leak secret-key-dependent information through distinguishable failure behavior.
- Unauthenticated plaintext must never be released on failure.
- API errors for decrypt failures must stay opaque.
- Remote `/api/decrypt` responses use a deadline-style response floor so obvious traffic-analysis cliffs do not expose key existence or lifecycle state.

## Known limitation: key-value-dependent decapsulation timing (platform-level)

### Finding

Source inspection of the ML-KEM-768 implementations found no ordinary
constant-time violations:

- no secret-dependent branches;
- no secret-dependent table lookups;
- fixed-size loops;
- constant-time verify/cmov patterns;
- arithmetic-only Montgomery reduction and NTT operations.

However, bare-metal dudect testing on dedicated x86-64 Linux hardware shows
reproducible key-material-dependent timing signals in ML-KEM-768 decapsulation.
Same-key and same-key/two-ciphertext-pool controls pass, so the harness is not
simply distinguishing ciphertext pools or class layout.

### Observed results

Tested on DigitalOcean Premium Intel vCPU (x86-64), Ubuntu 24.04,
Rust 1.96/1.97, release profile, 2026-07-09.

| Provider | Control (same-key) | key-A-vs-key-B |
|---|---|---|
| PQClean (pqcrypto-mlkem 0.1.1) | PASS, \|t\| = 2.18 | FAIL: 41, 17, 136 |
| libcrux (libcrux-ml-kem 0.0.9) | PASS, \|t\| = 1.92 | FAIL: \|t\| = 61 |
| AWS-LC (aws-lc-rs 1.17.1) | PASS, \|t\| = 2.20 | FAIL: 3.5, 36, 61, 1106, 47 |

No tested ML-KEM-768 provider consistently passed key-A-vs-key-B dudect on
tested x86-64 hardware. The cross-provider reproduction (three independently
developed implementations, two languages, one C-with-assembly) rules out an
implementation-specific code defect with high confidence.

### RustCrypto component attribution (2026-09-06)

The historical key-A-vs-key-B comparisons above vary an entire generated key and
therefore do not distinguish its secret and public components. A later campaign against
the shipped RustCrypto `ml-kem` 0.3.2 path varied those components independently, used
paired null controls, two seeds, and both label orders at 100,000 generated samples/case:

- all 8 decapsulation control/secret-only cases passed (`max |t| = 2.93693`);
- all 8 public-part/whole-key cases failed (`|t| = 127.48` to `589.37`);
- all 12 key-import control/secret/public cases passed (`max |t| = 3.99145`).

Source tracing and a diagnostic-only cache experiment localize the large RustCrypto
component to matrix reconstruction from public seed `rho`. ML-KEM's rejection sampler
can consume different amounts of public pseudorandom input for different public keys.
The effect is therefore retained as a public-key-dependent performance/key-identification
characteristic, not classified by itself as secret leakage. The secret-only non-flags
are supporting evidence, not a constant-time proof, and do not retroactively resolve
the historical cross-provider whole-key results. See `gauntlet/VALIDATION_FOLLOWUP.md`.

### Interpretation

This is **not** evidence of a cryptographic break of ML-KEM.

This is **not** evidence that the source code branches on secrets.

It **is** evidence that current ML-KEM-768 decapsulation, on this tested
hardware and build environment, has not been locally validated as
key-material-timing-independent.

### Likely cause

Below-source-level microarchitectural effects. ML-KEM polynomial arithmetic
necessarily performs many multiplications involving secret coefficients
(`fqmul` → `(int32_t)a * b` where `a` is a secret key coefficient). Even when
source code is branchless and memory access is fixed, modern x86-64 CPUs can
expose value-dependent timing through:

- data-operand-dependent instruction timing in integer multipliers;
- power/frequency response to operand values (Hertzbleed-class);
- cache/prefetch effects on large key objects (2400-byte secret keys);
- other microarchitectural mechanisms.

This is consistent with published Hertzbleed-class concerns, where
constant-time source discipline is not sufficient to guarantee timing
independence on real CPUs.

### Attacker-controlled-input classes

All attacker-controlled-input timing classes pass dudect:

- ciphertext variation (different valid ciphertexts, same key): PASS
- tag/AAD corruption (two failure modes): PASS
- KEM-byte corruption (two corruption positions): PASS

The dependence is on **static key material**, which an attacker cannot vary
per query. The service layer additionally applies opaque errors and a
deadline-scheduled response floor. An attacker querying `/api/decrypt` varies
the ciphertext, and the ciphertext-variation classes pass.

### What this blocks

- "Constant-time validated" — **cannot claim.**
- "Side-channel proof" or "side-channel hardened" — **cannot claim.**
- Certification-style timing claims — **blocked until resolved.**

### What this does not block

- Ordinary networked production use with opaque errors, response floors,
  and rate limits — **not automatically blocked.**
- FIPS 203 compliance (the algorithm is correct) — **not affected.**
- Post-quantum security claims (the cryptographic construction is sound) —
  **not affected.**

### Required wording for grant and security materials

> Citadel uses standardized FIPS 203 ML-KEM-768 in a hybrid construction with
> X25519 and AES-256-GCM. The production ML-KEM provider is RustCrypto `ml-kem`
> 0.3.2 (pure Rust). It largely follows constant-time discipline; a ctgrind
> (valgrind) analysis localized one secret-indexed table lookup (`Eta::ONES[val]`)
> in the crate's CBD noise sampling. For the ML-KEM-768 parameter set that table
> is 32 bytes — a single cache line, with an always-in-range index — so it is not
> practically exploitable, though it remains a constant-time anti-pattern in the
> dependency (see `gauntlet/tier8_ct/`). Our dudect-based timing
> validation suite passes all attacker-controlled-input classes (ciphertext
> variation, tag corruption, AAD corruption, KEM-byte corruption).
>
> Key-value-dependent decapsulation timing is detectable at the microbenchmark
> level on tested x86-64 hardware, reproduced across three independently
> developed ML-KEM implementations (PQClean, libcrux, AWS-LC). Source
> inspection found no code-level constant-time violations; the effect is
> consistent with hardware-level data-dependent execution
> (Hertzbleed-class). This is documented as a known platform-level
> limitation. We do not claim constant-time validation or side-channel
> hardening for ML-KEM decapsulation on this platform.
>
> The service boundary applies opaque error responses, response-time floors,
> and three-tier rate limiting. No remotely exploitable timing oracle has been
> demonstrated.

### Production risk assessment

The observed dependence is on static key material, not on attacker-supplied
input. A remote attacker querying `/api/decrypt` varies the ciphertext; the
per-key timing offset is constant across every query against a given key, so
it does not give a query-adaptive oracle. What it could leak, in the worst
case, is a small amount of information about the static key
(Hertzbleed-style attacks need exactly this shape, and they require
co-residency, enormous query volumes, and no frequency pinning).

Deployments where caution is warranted:

- hostile-multitenant hosts sharing cores with untrusted code;
- long-lived high-value static keys serving unbounded decapsulation queries.

For those deployments, key rotation and dedicated tenancy reduce exposure.

### Recommended mitigations

1. Keep remote API response floors and opaque errors.
2. Rate-limit decrypt attempts (already implemented: three-tier rate limiting).
3. Avoid exposing raw decapsulation as an attacker-queryable oracle.
4. Document that local co-resident attackers are out of scope unless hardware
   isolation is provided.
5. Prefer hardware isolation (TEE, dedicated tenancy) for high-assurance
   deployments.
6. Track provider and CPU behavior over time.
7. Re-run dudect on multiple CPU families (AMD, ARM) to characterize the
   effect across microarchitectures.
8. Consider adding an alternate KEM or fallback once additional NIST standards
   are available.

### Do not fix by adding delays

Do not add dummy work, artificial delays, or timing equalization inside the
ML-KEM decapsulation path. Such fixes are optimizer-fragile, drift from the
real execution path over time, add complexity to security-critical code, and
do not address the root cause (hardware data-dependent execution).

If remote equalization is required, enforce it at the service boundary with
opaque errors and a response floor — not inside the crypto primitive.

### Follow-up work (priority order)

1. **Effect size (Δ):** Measure the median per-call timing difference between
   key A and key B in nanoseconds with confidence intervals. Sub-nanosecond
   Δ materially strengthens the "not practically exploitable" argument.
2. **CPU frequency pinning:** Re-run with turbo boost disabled and CPU
   governor set to fixed frequency. If the signal collapses, it localizes
   to power/frequency response (cleanest possible explanation).
3. **Multiple key pairs:** Test 20+ random A/B pairs to show the effect is
   generic, not a quirk of two particular keys.
4. **Second microarchitecture:** Test on AMD and/or ARM to determine if the
   effect is Intel-specific.
5. **Instrumentation-level analysis:** Run one provider through
   Microwalk/ctgrind/valgrind secret tainting to formally separate "code is
   CT" from "hardware isn't."
6. **Gate criterion refinement:** For key-value classes, adopt a compound
   gate: fail on |t| > 4.5 **and** Δ above a stated floor (a few cycles).
   Retain |t|-only gating for attacker-controlled-input classes where zero
   tolerance is correct.

## P-384 ECDH arm (suite `0xA4`) — harness + preliminary screen

Suite `0xA4` adds one new secret-dependent primitive over `0xA3`: **P-384 ECDH** via the
pure-Rust `p384` crate (the ML-KEM-1024 arm is the same family as the already-characterized
ML-KEM-768). The classical arm is isolated for dudect by
`kem_p384::diagnostic_p384_ecdh_only` (feature `timing-diagnostics`), which runs exactly the
ECDH `decapsulate` performs — parse the ephemeral point, `diffie_hellman` with the static
scalar, return the 48-byte x-coordinate. Two benches in `benches/timing_sidechannel.rs`:

| Bench | Tier | Leak it catches |
|---|---|---|
| `bench_stage_p384_ecdh_key_a_vs_key_b_success` | Diagnostic | Static-key-material-dependent timing in P-384 ECDH. Not attacker-varyable per query. |
| `bench_stage_p384_ecdh_same_key_pool_a_vs_pool_b_control` | Harness control / attacker-controlled screen | Two pools of *varying* valid ciphertexts, same key — same public class. This is both the null control AND the remote-relevant ciphertext-variation screen. |
| `bench_info_p384_ecdh_fixed_vs_random_ciphertext` | Informational | One *identical* ciphertext repeated vs varying — deliberately NOT same-public-class; demonstrates the fixed-input cache artifact. Not a gate. |

### Preliminary screen — 2026-07-26 (NOT authoritative)

Run on a **noisy WSL2-on-Windows dev box** (release, `--features timing-diagnostics`), which
is explicitly *not* the quiet dedicated Linux the ML-KEM results above used. Sub-threshold
values drift run-to-run on this box (e.g. key-A-vs-key-B read 1.51 then 2.15) but stay `< 4.5`:

| Bench | max \|t\| | n (post-crop) | verdict |
|---|---|---|---|
| `..._key_a_vs_key_b_success` | ~1.5–2.2 | ~13K (est. ~70–142K needed) | no signal, but **underpowered** |
| `..._same_key_pool_a_vs_pool_b_control` | ~1.4–2.5 | ~43–100K | no signal (same-public-class) |
| `bench_info_..._fixed_vs_random_ciphertext` | **~106** | 46K | **artifact, not a leak** (see below) |

**The `~106` is not a leak — and reading it correctly is the whole point.** That bench compares
one *identical* ciphertext repeated against varying ciphertexts, which is not a same-public-class
comparison: the fixed input stays cache/branch-predictor-hot and runs systematically faster,
regardless of any secret. The decisive disambiguator is the same-public-class control immediately
above it — *varying-vs-varying valid ciphertexts, same key* — which stays `< 4.5`. If the ECDH
leaked on ciphertext value or key material, that control would move; it does not. So the huge `t`
localizes to the fixed-input measurement artifact and confirms this file's "same-public-class
only" rule, rather than indicating a timing oracle.

### Box-capability baseline + well-powered P-384 result (2026-07-26)

Two control experiments settle how to read the P-384 numbers on this noisy box.

**(a) The box is capable — it detects ML-KEM's documented signal decisively:**

| Bench (same box, same harness) | max \|t\| | n | (5/tau)^2 | verdict |
|---|---|---|---|---|
| `rustcrypto_mlkem_key_a_vs_key_b` | **38.5** | 38K | 647 | signal — well-powered |
| `stage_mlkem_key_a_vs_key_b` | **27.8** | 59K | 1923 | signal — well-powered |
| ML-KEM same-key controls (×4) | ≤ 1.7 | 65–100K | — | clean |

ML-KEM sits far above threshold, well-powered, controls clean — unambiguous. So the harness and
box CAN surface a real key-material leak.

**(b) P-384 ECDH key-material — well-powered, but it STRADDLES the threshold and does not
persist.** The first 100K screen read ~1.8 (underpowered). Bumped to 1M samples and run four
times independently:

| `p384_ecdh_key_a_vs_key_b` run | max \|t\| | n (post-crop) |
|---|---|---|
| A | 6.67 | 293K |
| B | 6.83 | 293K |
| C | **2.18** | 621K |
| D | 3.88 | 533K |
| same-key control @ 1M | 1.45 | 846K |

The signal does **not** persist above `4.5` (two runs over, two under) and does **not** grow with
sample count (run C had the *most* samples yet the *lowest* `|t|`). A real effect scales with
`sqrt(n)`; this bounces in a ~2–7 band uncorrelated with `n`. That is the signature of the box's
**measurement noise floor**, not a resolved key-material leak — categorically unlike ML-KEM's
solid 27–38. The same-key control stays clean throughout (≤ 1.7, and 1.45 at 1M).

**Honest conclusion: INCONCLUSIVE on this hardware.** We can claim neither a clean negative nor a
confirmed leak for the P-384 key-material class — the noise floor (~2–7) is too high to resolve
whether a weak sub-ML-KEM effect exists. This is *weaker* than ML-KEM's finding (which is a
confirmed signal) and does not clear P-384 either. An authoritative determination requires the
quiet, frequency-pinned dedicated-Linux procedure below, which lowers the noise floor enough to
resolve the ~2–7 band.

*(Methodology note: a single 1M run (6.67) looked like a signal; four runs showed it does not
persist. Borderline dudect results near threshold MUST be confirmed across independent runs
before being called either way — see the two superseded reads above.)*

**What the attacker-controlled / remote class shows:** the same-public-class pool control
(attacker varies the ciphertext, not the key — the remote threat model) is **clean** across all
runs (`|t|` ≤ 2.9, 1.45 at 1M), consistent with ML-KEM's attacker-controlled classes passing.

**Claim status:** *"P-384 ECDH is constant-time on the shipped path"* remains **NOT established**
(spec 033 §7 row 1) — and now explicitly *inconclusive, not clean*: the well-powered run neither
confirmed nor excluded a weak key-material effect. The remote/attacker-controlled class is clean.

### Can this box be salvaged with core-pinning? No (2026-07-26)

Tried the only no-root lever available on WSL: `taskset` the bench to an isolated core (core 15
of 16). It did **not** tighten P-384 — it made it *more* erratic:

| pinned P-384 `key_a_vs_key_b` @ 1M | \|t\| | n (post-crop) |
|---|---|---|
| run 1 | 1.93 | 242K |
| run 2 | **22.48** | 67K (93% cropped) |
| run 3 | 3.43 | 67K |
| control | 2.19 | 621K |
| ML-KEM sanity | **82.0** | 43K |

The run-2 spike arrived with dudect discarding 93% of samples as outliers — a scheduling-jitter
artifact, not a reproducible effect (runs 1/3 stayed low). ML-KEM stayed rock-solid at 82. A real
key-material signal is reproducible and survives cropping; P-384's is neither. **Conclusion: the
WSL-on-Windows virtualization noise floor is not removable without root (`cpupower`/turbo/isolcpus)
or a different host. This box cannot resolve P-384 — confirmed empirically, pinned and unpinned.**

Authoritative determination requires a **quiet, dedicated Ubuntu** (the ML-KEM numbers above used
a DigitalOcean Intel vCPU): root for `cpupower frequency-set -g performance` + turbo disable +
`taskset`/`isolcpus`, no competing load, `--samples`≥1M. Native/bare-metal or a throwaway cloud VM
— *not* WSL. Rust `1.9x`, `cargo bench --bench timing_sidechannel -p citadel-envelope --features
timing-diagnostics -- --filter p384` (and the ML-KEM baseline as the capability control).

**Dedicated-hardware run (Andre / optional, additive):** running both benches — plus the
attacker-controlled ciphertext-variation class, which is the one that matters for the remote
API — on a quiet Intel/AMD/ARM Linux box with frequency pinning, per the "Quiet-machine
validation run procedure" below, at full 100K+ samples, would lower the noise floor enough to
resolve the ~2–7 band **empirically**. But see the next subsection: dudect can only ever *fail
to reject* constant-time, so that run is additive evidence, not the authoritative resolver of the
claim. It is worth doing to move the empirical row from *inconclusive* toward *consistent-with-CT*;
it cannot move the claim past the provider's own ceiling.

### Authoritative resolution — the design guarantee is the ceiling (2026-07-27)

The framing above treated the dedicated-hardware dudect run as the authoritative determination.
That is the wrong epistemics and is corrected here. **dudect is a one-sided test: it can detect a
timing signal (reject the constant-time null), but a clean result never *proves* constant-time — it
only fails to reject.** So no amount of timing data, on any box, can be the authoritative source for
a *positive* "is constant-time" claim. The authoritative source is what the provider **designs,
implements, and documents**, verified by source inspection. Both were checked (facts, not vibes):

1. **Provider design posture — `p384` 0.14.0 `README.md` "⚠️ Security Warning" (verbatim):**
   > "This crate has been designed with the goal of ensuring that secret-dependent operations are
   > performed in constant time (using the `subtle` crate and constant-time formulas). However, it
   > has not been thoroughly assessed to ensure that generated assembly is constant time on common
   > CPU architectures. […] This crate has not been independently audited!"

2. **Shipped path — source-inspected.** The `0xA4` ECDH shared secret is computed via
   `elliptic_curve::ecdh::diffie_hellman` (0.14.1), whose body is
   `let secret_point = (public_point * secret_key.borrow().as_ref()).to_affine();` — the
   **constant-time `Mul`** on `ProjectivePoint` (secret scalar × attacker-supplied point). RustCrypto's
   variable-time routines are the *explicitly named* `*_vartime` / `lincomb_vartime` methods; **none
   appear on this path.** Point validation (`from_sec1_bytes`) rejects off-curve / identity inputs
   before the multiply. So the shipped path uses the constant-time formula the README describes.

**Claim resolution (this is the true ceiling for a pure-Rust, unaudited provider):**

| Level | Status | Basis |
|---|---|---|
| **Source / algorithm** (secret-dependent ops use constant-time formulas + `subtle`; shipped path is the CT `Mul`, no `_vartime`) | **Established** | `p384` 0.14.0 README + code inspection of `diffie_hellman` (above) |
| **Generated assembly on specific CPUs** | **Not vendor-assessed** | provider states it explicitly; same status already recorded for `ml-kem 0.3.2` |
| **Independent audit** | **False** | provider states "not been independently audited" |
| **Empirical (dudect, this box)** | **Inconclusive, consistent-with-CT** | well-powered 1M×4 shows no signal above the ~2–7 noise floor that resolves ML-KEM's real 27–38 signal; one-sided test, so this is *supporting*, never *proof* |

The dedicated-hardware run remains available and would strengthen the empirical row, but the
**overall claim cannot advance past "designed and implemented constant-time (source-verified);
assembly not vendor-assessed; not independently audited"** without a third-party assembly/side-channel
audit — which is the same audit gate already tracked for the ML-KEM provider and for Citadel overall.
P6 is therefore resolved to its ceiling: the claim is recorded at exactly what the evidence supports,
and the open dependency is the audit, not a timing box.

## Dudect bench policy

Hard-gated dudect benches compare only same-public-class inputs: same public wire shape, same parse outcome, and same observable success/failure class. A gated pair must name the leak it would catch.

| Bench | Tier | Leak it catches |
|---|---|---|
| `bench_tag_first_byte_vs_last_byte_failure` | Gate | Early-exit AEAD tag comparison. |
| `bench_wrong_aad_vs_wrong_tag_failure` | Gate | Secret-dependent divergence in the authentication failure path. |
| `bench_kem_corruption_a_vs_b_failure` | Gate | KEM/KDF behavior that differs by corrupted KEM value rather than following an implicit-rejection style pipeline. |
| `bench_key_material_fixed_vs_random_success` | Diagnostic gate | Timing dependence on key material during successful decrypt. This only blocks release if the matching null-control bench passes. |
| `bench_null_fixed_vs_random_harness_control` | Harness control | Same fixed-vs-random class construction as the key-material diagnostic, but with key-independent dummy work. If this exceeds threshold, the fixed-vs-random harness is confounded by layout/cache/input-selection effects. |
| `bench_stage_*` | Diagnostic | Localizes a failing key-material diagnostic to hybrid KEM, X25519-only, ML-KEM-only, KDF, AEAD, or key-A-vs-key-B controls. Stage diagnostics are logged for root-cause analysis; the top-level release decision remains the primary key-material diagnostic plus its null control. |
| `bench_stage_mlkem_same_key_shared_buffer_control` | Harness control | Confirms the ML-KEM shared-buffer harness does not distinguish arbitrary dudect classes when key material is fixed. |
| `bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success` | Harness control | Confirms two independent valid ciphertext pools for the same ML-KEM key do not explain a key-A-vs-key-B signal. |
| `bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success` | Provider diagnostic | Detects secret-key-material-dependent timing in the active ML-KEM provider after address/layout and ciphertext-pool controls pass. |
| `bench_pqclean_mlkem_*` | Provider comparison | Dev-only PQClean-backed comparison benches. |
| `bench_info_valid_vs_short_public_format` | Informational | Expected public-format timing gap from structural parse early return. |
| `bench_info_wrong_key_a_vs_b_failure` | Informational | Wrong-key failure behavior; useful drift signal, but not a clean gate because it mixes key variation with guaranteed authentication failure. |

Use the standard dudect threshold (`|t| < 4.5`) for gated benches. A persistent `|t|` above threshold, especially one that grows with sample count across independent runs, is a release blocker for gated classes.

The fixed-vs-random key-material bench has a paired null control. Interpret it as follows:

- key-material passes and null control passes: no timing signal detected in that diagnostic;
- key-material fails and null control passes: block release and localize the signal across ML-KEM decapsulation, KDF/AEAD, X25519, and envelope glue;
- key-material fails and null control also fails: mark REVIEW, because the measurement harness itself distinguishes classes before proving a primitive leak;
- key-material passes and null control fails: mark REVIEW and repair the harness before relying on that diagnostic.

When localization is needed, prefer interpreting key-A-vs-key-B stage controls before fixed-vs-random stage controls. A fixed-vs-random stage result can be contaminated by cache residency or key-object reuse patterns; key-A-vs-key-B keeps both classes hot and gives stronger evidence of key-material-dependent timing.

For large secret objects such as ML-KEM-768 decapsulation keys, key-A-vs-key-B
diagnostics must use a matching shared-buffer null control before they are
treated as evidence. The control copies selected key/ciphertext bytes into the
same preallocated buffers before the timed closure and assigns classes
independently of the selected sample. If that control passes, a key-A-vs-key-B
shared-buffer failure is stronger evidence that the provider/platform remains
timing-distinguishable after address/layout effects have been removed.

Informational benches are logged but ignored by the release gate. They are drift detectors: if a public-format timing gap changes shape after a refactor, investigate whether secret-dependent work moved across a public parse boundary.

## HTTP timing policy

HTTP timing is evaluated separately from library dudect.

- Public-class differences may use practical thresholds. Statistical significance alone is expected with enough samples.
- Secret-dependent HTTP pairs must not get a magnitude escape hatch. If a same-secret-class signal reproduces across independent runs and grows with sample count, the response floor failed and the release should block.
- Low-sample p99/max values are not hard gates. At small `n`, one scheduler spike can dominate the maximum. A suspicious tail should trigger a larger-sample run, not an immediate fix-by-guessing.

## Quiet-machine validation run procedure

All timing validation runs in WSL Ubuntu or bare-metal Linux. Never run cargo
on Windows directly (SAC blocks unsigned build scripts).

### Standalone ML-KEM repro (no Citadel envelope)

The `mlkem_standalone` bench calls PQClean, libcrux, and AWS-LC ML-KEM-768
directly — no Citadel types, no hybrid wrapper, no KDF, no AEAD.

```bash
cd /path/to/citadel-v3
source ~/.cargo/env 2>/dev/null || true

# Controls — must stay |t| < 4.5
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter pqclean_same_key_control
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter pqclean_same_key_two_pool_control

# Key-A-vs-key-B — all three providers
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter pqclean_key_a_vs_key_b
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter libcrux_key_a_vs_key_b
cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter awslc_key_a_vs_key_b
```

### Full Citadel timing suite

```bash
# Controls
cargo bench --bench timing_sidechannel -p citadel-envelope -- --filter bench_stage_mlkem_same_key_shared_buffer_control
cargo bench --bench timing_sidechannel -p citadel-envelope -- --filter bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success

# Key-A-vs-key-B through Citadel wrapper
cargo bench --bench timing_sidechannel -p citadel-envelope -- --filter bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success
```
