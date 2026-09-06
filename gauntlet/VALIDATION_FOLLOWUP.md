# Validation repairs and timing follow-up

These changes repair the validation tools. They do not change Citadel's production
cryptographic operations, wire formats, or previously delivered restart repairs.

## Implemented repairs

- `run.sh` preserves cargo-deny, cargo-audit, fuzz discovery/run, and benchmark
  failures. Unknown tier names fail; tier1b alone actually runs its shared crate.
- Timing runs enable the required feature, retain full output, require every
  registered benchmark to complete, and evaluate the unchanged |t| >= 4.5 threshold.
  A flagged control is INCONCLUSIVE, not PASS. Informational public-format benches
  remain explicitly identified. Neither PASS nor command exit 0 proves constant time.
- Missing or empty Rust test summaries and empty fuzz discovery cannot pass.
- Tier1 uses AES-GCM 0.11.0 with zeroize. Its lockfile was aligned from the production
  lockfile, then resolved for the standalone test workspace. The dependency gate
  compares the four directly tested primitive versions, sources, required resolved
  primitive features, and transitive dependency versions/sources. It does not claim
  identical application-wide feature unification or identical generated machine code.
- `timing_attribution.rs` separates ML-KEM import from decoded-key decapsulation,
  and P-384 point decoding from ECDH. It uses shared input storage and class-independent
  ciphertext/point sampling, with explicit controls and reversed-label support.
- `run_timing_attribution.py` builds the actual diagnostic, records command/status/raw
  CSV for each case, and blocks an overall pass when controls flag, a secret screen
  flags, or execution fails. A decapsulation difference isolated to the public portion
  of an expanded key is reported as `PUBLIC-DIFFERENCE`, not as a secret-timing failure.
- `run_ffi_sanitizers.sh` keeps leak detection enabled and propagates its exit status.

## Targeted verification on 2026-09-06

- Validation tooling: 22 regression tests passed, 0 failed.
- Aligned vector/composition crate through repaired runner: 10 passed, 0 failed.
  Intermediate repeats tested successive gate repairs; do not sum them as new tests.
- New timing diagnostics: 25 completed measurements, 100,000 generated samples each;
  14 measurements exceeded the existing threshold. This is not 14 vulnerabilities.
- Two initial AAD diagnostic attempts failed because the new harness allocated a
  14-byte buffer for 15-byte AAD. The buffer was repaired and the affected diagnostic
  rerun. Both failed attempts remain in the evidence; neither is counted as a pass.
- New campaign runner integration completed two of those 25 measurements.
- The initial FFI assertions passed, but that sanitizer invocation exited 23 because
  LSan could not read the required `/proc` task information. This environment failure
  was resolved and rerun successfully in the follow-up below.
- No full workspace suite rerun. No production crypto or prior restart code changed.

## Timing interpretation

The host reports AMD EPYC 9V74 with a hypervisor. Processes were pinned to available
CPU 0 and run sequentially, without our compilation/fuzz workloads running alongside
them. This is still shared virtual hardware, without dedicated frequency control.

ML-KEM-768 expanded-key diagnostics independently vary s[0..1152] and the public
key plus its hash [1152..2368], holding rejection secret z constant. They use random
invalid ciphertexts and assert equal fallback outputs where z is shared. These are
synthetic diagnostic keys, not real matching keypairs and not a complete leakage model.
The `keys` mode instead compares two generated keys with different z values.

Public-part-only decapsulation produced t=-497.72, +530.03 with labels reversed,
and +820.77 for a second pair. Inspection of ml-kem 0.3.2 finds public-rho-dependent
rejection sampling in algebra.rs::sample_ntt, called by pke.rs::EncryptionKey::encrypt
inside decapsulation. This supports a public-key-dependent contribution; it does
not establish that every observed difference is harmless or caused by that loop.

Secret-part-only decapsulation produced t=-17.09, +2.31 with labels reversed, and
-6.41 for a second pair. Decapsulation controls also flagged (+8.31, -14.85), as did
some import controls. Import and decapsulation therefore remain INCONCLUSIVE.
No cryptographic dependency was patched or replaced on the strength of these results.

P-384 isolated ECDH control t=+1.85 and different-secret t=-1.36 were below threshold.
Point-decoding controls also stayed below threshold. These limited screens passed;
they do not close the earlier hardware/control concern across deployments.

AAD/tag comparison t=+4.89 flagged; reversed labels gave +2.68 and control -1.94.
The result remains mixed and unresolved. The runner retains the flagged result.
AAD fixtures use OS randomness; a bench seed alone does not reproduce those keys.
ML-KEM and P-384 primitive fixtures use the bench seed. Raw timing samples are retained.

## Follow-up verification on 2026-09-06

The repaired tools were rerun sequentially on the same pinned WSL2 virtual CPU, with
no compilation or fuzz workload running alongside the measurements. These screens are
supporting evidence, not a constant-time proof and not a replacement for a controlled
dedicated-host campaign.

- FFI ASan plus LSan: all 23 assertions passed and the sanitizer process exited 0.
  The earlier exit 23 was an invocation/environment problem, not a confirmed leak.
- AAD attribution: all 8 control/public measurements passed across two seeds and
  both label orders; maximum observed `|t|` was 3.68301. The earlier isolated AAD flag
  was not reproduced.
- ML-KEM import attribution: all 12 control/secret/public measurements passed across
  two seeds and both label orders; maximum observed `|t|` was 3.99145.
- ML-KEM decapsulation: all 8 control/secret-only measurements passed; maximum observed
  `|t|` was 2.93693. Two additional 50,000-pair baseline secret/control repetitions
  also produced no flags. The earlier small secret-only signal was not reproduced.
- ML-KEM public-part and whole-generated-key decapsulation comparisons failed in every
  seed/order (`|t|` from 127.48 to 589.37), while their paired secret-only and null
  controls passed. This reproducibly isolates a public-key-dependent component.
- P-384 parse controls: all 4 passed; maximum observed `|t|` was 1.87327. P-384
  ECDH controls and secret screens: all 8 passed; maximum observed `|t|` was 3.71199.

Source tracing localizes the RustCrypto `ml-kem` 0.3.2 public-part distinction to
matrix reconstruction from public seed `rho`: rejection sampling can consume a
different number of public pseudorandom bytes for different public keys. Caching the
expanded public matrix in a diagnostic copy removed the whole-operation difference.
That cache experiment is diagnostic-only and is not shipped. Upstream `ml-kem` does
not expose the matrix internals needed for Citadel to add this cache without forking a
cryptographic provider, so no speculative provider fork was introduced.

The conclusion is bounded: the AAD and secret-only signals were not reproduced on this
host; that does not prove their absence on every platform. The public-key distinction
is real and retained as a performance/key-identification characteristic, but `rho` and
the encapsulation key are public, so it is not by itself evidence of secret leakage.

## Reproduce only the affected checks

From the repository root:

    python3 gauntlet/test_validation_tools.py
    bash gauntlet/run.sh tier1

For follow-up timing on a controlled Linux target host:

    python3 gauntlet/run_timing_attribution.py --out timing-results

This deliberately runs only the new attribution cases. Use `--modes decap` to limit
work to one unresolved primitive. It supports `--cpu`, `--seeds`, and `--samples`.
The default is 100,000 samples/case, two seeds, and both label orders. Keep all
receipts, including failed controls. Do not raise thresholds or add artificial delays.

For memory checking, install the nightly toolchain with rust-src first, then:

    bash gauntlet/run_ffi_sanitizers.sh

A detector crash is not a passing result. The successful follow-up above used an
environment in which LSan could inspect `/proc` normally.

## Remaining work

Repeat the timing cases on controlled target hardware. A stable control is necessary
before attributing small differences to secret processing. If a secret signal appears
and persists, isolate its operation/instructions and validate a reviewed repair or
provider change against its affected vectors and rejection behavior. Track an upstream
public-matrix cache/API as a performance improvement, not as an emergency secret-leak
patch. Public-key differences remain recorded separately from secret-leak conclusions.
The existing restart fixes remain applicable; their durability/performance tradeoffs
are unchanged by this package.
