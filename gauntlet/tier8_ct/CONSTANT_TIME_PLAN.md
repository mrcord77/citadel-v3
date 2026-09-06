# Tier 8 — Constant-Time as a Proof (not a measurement)

**Status: harness implemented and executed.** The checked-in harness uses a C shim
over Valgrind Memcheck client requests (no crabgrind/bindgen/libclang). It marks
only the secret portions of the expanded ML-KEM key, avoiding public-key taint
false positives. See `../receipts/tier8_ct.txt` for the recorded run and caveats.

**Reproduce:**
```bash
cd gauntlet/tier8_ct/ctgrind_harness
VALGRIND_INCLUDE=$HOME/.local/include cargo build --release --locked
~/.local/bin/valgrind --error-exitcode=1 --track-origins=yes \
  ./target/release/ctgrind_harness
# Defined-data baseline; this should report zero errors:
~/.local/bin/valgrind --error-exitcode=1 --track-origins=yes \
  ./target/release/ctgrind_harness --control
```
A clean run is dynamic evidence of no secret-dependent branch/addressing on the
executed path for that input; it is not a proof over every input or platform. Any
"Conditional jump ... depends on uninitialised value" or secret-derived invalid
read pinpoints a candidate leaking instruction for investigation.

## Why this tier exists

`TIMING.md` documents a *measured* key-material-dependent timing effect in ML-KEM
decapsulation (via dudect — a black-box statistical test). dudect can only say
"we saw/didn't see a difference." It cannot **locate** a leak or **prove** its
absence. Tier 8 upgrades that to instruction-level evidence.

Target: the ML-KEM-768 decapsulation path (`kem::decapsulate` /
`diagnostic_mlkem_decapsulate_only`) and the AEAD tag comparison.

## Tools (all free/OSS), in order of leverage

1. **ctgrind (valgrind memcheck client requests)** — mark secret bytes as
   "uninitialized," run under valgrind; any branch or memory index that depends on
   a secret byte is reported with a stack trace. Cheapest, most direct.
   - Install: `sudo apt-get install -y valgrind`
   - Instrument: wrap the secret key bytes with `VALGRIND_MAKE_MEM_UNDEFINED` before
     decapsulation in a `#[cfg(feature="ctgrind")]` harness.
   - Run: `valgrind --error-exitcode=1 ./target/debug/ct_harness`
2. **DATA** (Graz, github.com/IAIK/DATA) — differential address-trace analysis;
   runs the binary under Pin/valgrind with two secret classes and does statistical
   leakage detection at address granularity. Heavier setup; the definitive dynamic tool.
3. **haybale-pitchfork** (github.com/PLSysSec/haybale-pitchfork) — *symbolic*
   execution over LLVM bitcode that **proves** constant-time (or yields a
   counterexample path). No sampling. Needs LLVM + boolector:
   - `sudo apt-get install -y llvm-dev libclang-dev boolector`
   - Emit bitcode for the decap function, point pitchfork at it, mark secret args.
4. **MicroWalk** / **Binsec/Rel** — alternatives for microarchitectural / relational
   CT verification if 1–3 are inconclusive.

## Expected outcome

Either (a) find no violation on the exercised trace, adding instruction-level
dynamic evidence, or (b) locate a secret-dependent branch/access that becomes a
concrete fix. A universal proof requires a relational verifier such as
haybale-pitchfork or Binsec/Rel; ctgrind alone cannot supply one.

## To run this tier

```bash
sudo apt-get install -y valgrind libc6-dbg
# then run the optimized harness above; optional DATA/haybale per this plan
```
Valgrind may also be installed rootlessly; it still needs compatible loader debug
symbols visible in its debug-info search path.
