# Validation repairs and unresolved timing findings

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
  CSV for each case, and blocks an overall pass when controls flag or execution fails.
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
- FFI assertions: 23 passed; overall sanitizer execution exited 23 because LSan could
  not read the required /proc task information. Leak checking remains BLOCKED.
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

For memory checking on a host where LSan can inspect its process normally, install
the nightly toolchain with rust-src first, then:

    bash gauntlet/run_ffi_sanitizers.sh

A detector crash is not a passing result. This package does not change host security
settings or claim the blocked leak check has been completed.

## Remaining work

Repeat the affected timing cases on controlled target hardware. A stable control is
necessary before attributing small differences to secret processing. If a secret
signal persists, isolate its operation/instructions and validate a reviewed repair
or provider change against its affected vectors and rejection behavior. Larger
public-key differences remain recorded separately from any secret-leak conclusion.
The existing restart fixes remain applicable; their durability/performance tradeoffs
are unchanged by this package.
