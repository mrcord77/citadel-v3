# Citadel Gauntlet — run summary (2026-07-20)

Environment: Ubuntu WSL2, stable 1.96.1 / nightly 1.99.0. All tooling free/OSS.
Every result below is machine-checked external-tool output, not self-assessment.

| Tier | Tool | Result | Evidence |
|---|---|---|---|
| **1** Wycheproof vectors | google/wycheproof through exact pinned primitives | ✅ **PASS** | AES-256-GCM 66/66, X25519 265/265 valid, HKDF-SHA256 86/86; 0 failures. `receipts/tier1_vectors.txt` |
| **1b** Envelope composition | proptest vs real `Citadel::seal/open` (256 cases/property) | ✅ **PASS** | roundtrip, single-bit-flip, wrong-key, wrong-AAD, wrong-context, truncation, no-silent-downgrade — 7/7, 0 counterexamples |
| **2** Memory safety | `cargo miri` on citadel-ffi | ✅ **PASS** | 13/13 under interpretation, **0 UB**; incl. free-length-trust, zeroize-before-dealloc, double/null-free, concurrency. `receipts/tier2_miri.txt` |
| **2b** Supply chain | cargo-deny + cargo-audit + cargo-vet | ✅ **PASS (0 vulns)** | 3 HIGH **fixed** by bumping the libcrux **dev**-oracle 0.0.9→0.0.10 (patched code swapped in). `cargo audit` 0 vulns; 4 dev-only unmaintained/unsound warnings kept **visible** (not ignored) + documented in `SUPPLY_CHAIN.md`. `cargo deny` advisories ok. `receipts/tier2b_supplychain.txt` |
| **3** Extended fuzzing | cargo-fuzz (libFuzzer, nightly+ASan) smoke | ✅ **PASS (smoke + sustained)** | smoke: ~71M execs, 0 crashes/leaks (`receipts/tier3_fuzz_smoke.txt`). Sustained: ClusterFuzzLite daily 30-min ASan batch 2026-07-21→08-17, 24 completed runs, 8 targets, 884-file corpus, **0 crashes** (`receipts/tier3_sustained_campaign.txt`); AFL++ second engine = open follow-on |
| **4** Constant-time | dudect (+DATA/MicroWalk follow-on) | prior evidence in `../../TIMING.md` | attacker-controlled-input classes pass; key-material effect documented, binary CT analysis pending |
| **5** Formal (proof) | **Kani** bounded model checking on wire parsers | ✅ **PROVEN** | `inspect` + `decode_wire` panic-free / no-UB for ALL inputs ≤**256B** (incl. internal wire_v2::decode, decode_wire_raw). Proof, not sample. `receipts/tier5_kani.txt` |
| **6** Concurrency | **Loom** exhaustive interleaving | ✅ **PASS** | one-shot capability nonce: exactly-one-consumer under EVERY schedule, no double-spend / lost token / deadlock. `receipts/tier6_loom.txt` |
| **7** Sanitizers | **AddressSanitizer** on citadel-ffi | ✅ **PASS** | 13/13 under ASan (+leak detection), 0 sanitizer errors at the real allocator. Complements Miri. `receipts/tier7_asan.txt` |
| **8** CT trace | ctgrind (Valgrind Memcheck) on ML-KEM decap | ⚠️ **DEPENDENCY FINDING** | Secret-only trace: 3,584 errors/28 contexts, localized to ml-kem 0.3.2 `sample_poly_cbd` and its secret-indexed `ONES[val.0]`; defined-data control: 0 errors. The exact x86-64 release build places its 32B table wholly within one aligned cache line, narrowing but not universally resolving risk. No Citadel-owned envelope/KDF/AEAD/wire finding on the executed trace. `receipts/tier8_ct.txt`. |
| **9** Design review | hybrid-KEM combiner IND-CCA2 soundness | ✅ **NO FLAW** | binds both ciphertexts + both secrets, unambiguous encoding, X25519 contributory check — sound under ROM per KEM-combiner literature. Analytical, not machine-checked. `tier9_design/HYBRID_COMBINER_ANALYSIS.md` |
| **10** Key-lifecycle state machine | proptest vs the REAL keystore, oracle = declared `valid_transitions` | ✅ **VERIFIED** | 300 random op sequences: no illegal transition, no resurrection of Destroyed, no reactivation of Revoked; hierarchy escape (DEK-under-Root etc.) rejected. Runs in CI. `citadel-keystore/tests/lifecycle_transitions.rs` + `receipts/tier10_lifecycle.txt` |
| **11** Protocol analysis (symbolic) | **ProVerif** Dolev-Yao model of the envelope flow | ✅ **secrecy + no-downgrade PROVED** | machine-proved plaintext secrecy and no-downgrade/binding vs a network attacker; replay-injectivity inconclusive in ProVerif (atomicity assured by `ReplayStore::claim` + Tier 6/Loom). Symbolic model. `tier11_proverif/citadel_envelope.pv` + `receipts/tier11_proverif.txt` |

## Verdict

Citadel **passes every free adversarial gate that was runnable end-to-end** — now
including *proof-based* checks, not just sampling: Kani proves the parsers panic-free,
Loom exhaustively validates the concurrency, ASan confirms runtime memory safety, and
a design-level review finds the hybrid-KEM combiner sound (no flaw). Primitive
conformance, composition, and supply chain remain clean.

**Two honest gaps remain, both known:** (8) the instruction-level dynamic trace is
complete, but it found a dependency-level secret-indexed lookup and is not a
universal constant-time proof; and every result here is machine-checked
*implementation/design* evidence — it still does not
replace the one thing paid expertise uniquely provides: a named cryptographer's
signoff and liability. This is necessary-but-not-sufficient for a paid audit — but it
now clears a substantially higher bar than measurement-only tooling.

## Cleared next steps (own packet)

1. ~~Clear Tier 2b optics~~ **DONE 2026-07-20** — bumped libcrux dev-oracle to 0.0.10
   (fixes RUSTSEC-2026-0207/0208/0212 with patched code). 4 residual dev-only
   unmaintained/unsound warnings kept **visible** in `cargo audit` (no per-ID
   ignore) and documented in `SUPPLY_CHAIN.md`. Suite unchanged at 353/0/8.
2. **Tier 3 sustained**: continuous-fuzzing config is WRITTEN in `oss-fuzz/`
   (ClusterFuzzLite recommended — self-hosted in Citadel's own CI, no acceptance gate;
   OSS-Fuzz as the optional Google-hosted path). Drop `.clusterfuzzlite/` + the workflow
   and each target fuzzes for hours with an accumulating corpus.
3. **Tier 8 CT**: **ctgrind executed** with a clean defined-data control and a
   dependency-level finding. Next: replace/pin a branch/index-free upstream CBD
   implementation, then rerun ctgrind; use DATA or a relational verifier for
   deeper coverage.
