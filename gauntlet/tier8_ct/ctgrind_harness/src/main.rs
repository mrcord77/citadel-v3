//! Tier 8 — ctgrind constant-time check of ML-KEM-768 decapsulation.
//!
//! Marks the ML-KEM secret-key bytes as "undefined" via valgrind client
//! requests, then runs Citadel's decapsulation. Under valgrind/memcheck, ANY
//! conditional branch or memory address that depends on a secret byte is
//! reported ("Conditional jump ... depends on uninitialised value(s)"). Clean =
//! no secret-dependent control flow / addressing on this path (for this input).
//!
//! This targets exactly the operation `TIMING.md` flags a measured wobble on.

use core::ffi::c_void;

use citadel_envelope::timing_diagnostics::{hybrid_encapsulate, mlkem_decapsulate_from_key_bytes};
use citadel_envelope::wire::{KEM_CIPHERTEXT_BYTES, KEM_SECRET_KEY_BYTES};
use citadel_envelope::{HybridX25519MlKem768Provider as Provider, KemProvider};

extern "C" {
    /// Mark `n` bytes at `p` as uninitialised (valgrind memcheck client request).
    fn ct_mark_undefined(p: *mut c_void, n: usize);
}

fn main() {
    let control = std::env::args().any(|arg| arg == "--control");

    // Well-formed keypair + ciphertext (values are irrelevant to ctgrind; memcheck
    // tracks definedness, not values — we only need the real code path to run).
    let (pk, sk) = Provider::keygen();
    let sk_bytes: [u8; KEM_SECRET_KEY_BYTES] = sk.to_bytes();
    let (_ss, ct_vec) = hybrid_encapsulate(&pk).expect("encapsulate");
    let mut ct = [0u8; KEM_CIPHERTEXT_BYTES];
    ct.copy_from_slice(&ct_vec);

    // Mark ONLY the genuinely-secret regions undefined. The ML-KEM-768 expanded
    // decapsulation key (FIPS 203) is dk_PKE(1152) || ek(1184) || H(ek)(32) || z(32);
    // ek and H(ek) are PUBLIC. Marking the whole key confounds the result — the
    // matrix regeneration (rejection sampling from ek's seed) and the key-import
    // hash check operate on public data and would flag as false positives.
    // sk_bytes = x25519(32) || dk(2400), so within the 2432-byte buffer:
    //   [32 .. 1184)  dk_PKE  (SECRET)   [1184 .. 2368) ek       (public)
    //   [2368 .. 2400) H(ek)  (public)   [2400 .. 2432) z        (SECRET)
    if !control {
        unsafe {
            ct_mark_undefined(sk_bytes[32..1184].as_ptr() as *mut c_void, 1152); // dk_PKE
            ct_mark_undefined(sk_bytes[2400..2432].as_ptr() as *mut c_void, 32); // z
        }
    }

    // Operation under test. Do NOT branch on the (secret-derived) result.
    let out = mlkem_decapsulate_from_key_bytes(&sk_bytes, &ct);
    let _ = std::hint::black_box(out);

    eprintln!(
        "ctgrind: ML-KEM decapsulation completed ({})",
        if control { "defined-data control" } else { "secret taint enabled" }
    );
}
