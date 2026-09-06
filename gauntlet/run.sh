#!/usr/bin/env bash
# Citadel Adversarial Gauntlet — orchestrator.
# Runs each available tier, writes a receipt per tier, prints one PASS/FAIL
# summary, and exits non-zero if a selected tier failed or was inconclusive.
#
# Usage:
#   bash run.sh                 # every tier the toolchain supports
#   bash run.sh tier1 tier2b    # a subset
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"        # citadel_v3
REC="${GAUNTLET_RECEIPTS:-$HERE/receipts}"
mkdir -p "$REC" || exit 1
SUMMARY="$REC/LAST_RUN.md"   # auto-generated per run; curated SUMMARY.md is hand-maintained

STAMP="${GAUNTLET_STAMP:-unstamped}"  # pass a timestamp in; scripts can't call date deterministically in some envs
declare -A RESULT
for tier in ${*:-tier1 tier1b tier2 tier2b tier3 tier4}; do
  case "$tier" in tier1|tier1b|tier2|tier2b|tier3|tier4) ;; *) echo "Unknown tier: $tier" >&2; exit 2;; esac
done

SELECT="${*:-tier1 tier1b tier2 tier2b tier3 tier4}"

run_tier() { # name, human, command...
  local key="$1" human="$2"; shift 2
  case " $SELECT " in *" $key "*) ;; *) return 0;; esac
  echo "=================================================================="
  echo ">> $key — $human"
  echo "=================================================================="
  local rc=0
  "$@" || rc=$?
  case "$rc" in
    0) RESULT[$key]="PASS" ;;
    2) RESULT[$key]="INCONCLUSIVE" ;;
    *) RESULT[$key]="FAIL" ;;
  esac
}

rust_tests() {
  local receipt="$1"; shift
  "$@" >"$receipt" 2>&1 || { cat "$receipt"; return 1; }
  cat "$receipt"
  python3 "$HERE/check_test_results.py" "$receipt"
}

# ---- Tier 1 + 1b: crypto vectors + composition ----------------------------
t1() {
  python3 "$HERE/check_dependencies.py" >"$REC/tier1_dependencies.txt" 2>&1 || { cat "$REC/tier1_dependencies.txt"; return 1; }
  ( cd "$HERE/tier1_vectors" && rust_tests "$REC/tier1_vectors.txt" cargo test --locked )
}
case " $SELECT " in *" tier1b "*) SELECT="$SELECT tier1";; esac
run_tier tier1 "Wycheproof primitive vectors + proptest composition" t1
RESULT[tier1b]="${RESULT[tier1]:-NOT_RUN}"   # same crate

# ---- Tier 2: memory safety (Miri) -----------------------------------------
t2() {
  command -v cargo >/dev/null || return 2
  cargo +nightly miri --version >/dev/null 2>&1 || { echo "miri absent — rustup component add miri --toolchain nightly"; return 2; }
  ( cd "$ROOT" && MIRIFLAGS="-Zmiri-disable-isolation" \
      rust_tests "$REC/tier2_miri.txt" cargo +nightly miri test --locked -p citadel-ffi )
}
run_tier tier2 "cargo miri UB detection (FFI boundary)" t2

# ---- Tier 2b: supply chain -------------------------------------------------
t2b() {
  ( cd "$ROOT" || exit 1
    local rc=0
    echo "### cargo deny check"
    cargo deny check || rc=1
    echo "### cargo audit"
    cargo audit || rc=1
    exit "$rc"
  ) 2>&1 | tee "$REC/tier2b_supplychain.txt"
}
run_tier tier2b "cargo-deny + cargo-audit supply chain" t2b

# ---- Tier 3: extended fuzzing ---------------------------------------------
t3() {
  cargo fuzz --help >/dev/null 2>&1 || { echo "cargo-fuzz absent"; return 2; }
  local secs="${FUZZ_SECS:-60}"
  # cargo-fuzz needs nightly for -Zsanitizer; select via env, not `+nightly`.
  ( cd "$ROOT/citadel-envelope" || cd "$ROOT"
    export RUSTUP_TOOLCHAIN=nightly
    local rc=0 targets
    targets=$(cargo fuzz list) || return 1
    [ -n "${targets//[[:space:]]/}" ] || { echo "No fuzz targets discovered"; return 2; }
    for tgt in $targets; do
      echo "--- fuzzing $tgt for ${secs}s ---"
      cargo fuzz run "$tgt" -- -max_total_time="$secs" -rss_limit_mb=4096 2>&1 || rc=1
    done
    return "$rc" ) | tee "$REC/tier3_fuzz.txt"
}
run_tier tier3 "cargo-fuzz sustained run (libFuzzer)" t3

# ---- Tier 4: constant-time -------------------------------------------------
t4() {
  ( cd "$ROOT" || exit 1
    cargo bench --locked -p citadel-envelope --bench timing_sidechannel --features timing-diagnostics
  ) >"$REC/tier4_timing.txt" 2>&1 || { cat "$REC/tier4_timing.txt"; return 1; }
  cat "$REC/tier4_timing.txt"
  python3 "$HERE/check_timing.py" "$REC/tier4_timing.txt" \
    "$ROOT/citadel-envelope/benches/timing_sidechannel.rs" --json "$REC/tier4_timing.json"
}
run_tier tier4 "dudect constant-time classes (+DATA/MicroWalk follow-on)" t4

# ---- Summary --------------------------------------------------------------
{
  echo "# Citadel Gauntlet — run summary ($STAMP)"
  echo
  echo "| Tier | Result |"
  echo "|---|---|"
  for k in tier1 tier1b tier2 tier2b tier3 tier4; do
    printf "| %s | %s |\n" "$k" "${RESULT[$k]:-NOT_RUN}"
  done
} | tee "$SUMMARY" || exit 1

fail=0
for k in "${!RESULT[@]}"; do case "${RESULT[$k]}" in FAIL|INCONCLUSIVE) fail=1;; esac; done
echo
[ "$fail" -eq 0 ] && echo "GAUNTLET: selected tiers passed (see scope above)" || echo "GAUNTLET: at least one tier FAILED or was INCONCLUSIVE"
exit "$fail"
