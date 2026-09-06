// SPDX-License-Identifier: AGPL-3.0-or-later
//! Follow-up diagnostics, not a constant-time certification.
//! --mode import|decap|p384-parse|p384-ecdh|aad
//! --vary control|secret|public|keys; --swap reverses labels.
//! ML-KEM secret/public isolation uses synthetic expanded keys and random invalid
//! ciphertexts, preserving the implicit-rejection result. These are diagnostic
//! counterfactuals, never keys offered to the application or exported for use.
#![allow(deprecated)]
use citadel_envelope::{Aad, Citadel, Context};
use dudect_bencher::{
    ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts},
    BenchRng, Class, CtRunner,
};
use ml_kem::{
    kem::Decapsulate,
    ml_kem_768::{Ciphertext, DecapsulationKey, ExpandedDecapsulationKey},
    ExpandedKeyEncoding,
};
use p384::{ecdh::diffie_hellman, PublicKey as EcPublic, SecretKey as EcSecret};
use rand::{Rng, RngCore};
use std::{hint::black_box, path::PathBuf, sync::OnceLock};

struct Config {
    mode: String,
    vary: String,
    samples: usize,
    swap: bool,
}
static CONFIG: OnceLock<Config> = OnceLock::new();
fn label(right: bool, swap: bool) -> Class {
    if right ^ swap {
        Class::Right
    } else {
        Class::Left
    }
}

fn measure(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cfg = CONFIG.get().unwrap();
    match cfg.mode.as_str() {
        "import" | "decap" => mlkem(runner, rng, cfg),
        "p384-parse" | "p384-ecdh" => p384(runner, rng, cfg),
        "aad" => aad(runner, rng, cfg),
        _ => unreachable!(),
    }
}

fn mlkem(runner: &mut CtRunner, rng: &mut BenchRng, cfg: &Config) {
    let mut seed_a = [0u8; 64];
    let mut seed_b = [0u8; 64];
    rng.fill_bytes(&mut seed_a);
    rng.fill_bytes(&mut seed_b);
    let a = DecapsulationKey::from_seed(seed_a.into());
    let b = DecapsulationKey::from_seed(seed_b.into());
    let bytes_a = a.to_expanded_bytes();
    let mut bytes_b = b.to_expanded_bytes();
    // ML-KEM-768 expanded key: s[1152] || ek[1184] || H(ek)[32] || z[32].
    match cfg.vary.as_str() {
        "control" => bytes_b = bytes_a.clone(),
        "secret" => bytes_b[1152..].copy_from_slice(&bytes_a[1152..]),
        "public" => {
            bytes_b[..1152].copy_from_slice(&bytes_a[..1152]);
            bytes_b[2368..].copy_from_slice(&bytes_a[2368..]);
        }
        "keys" => {}
        _ => unreachable!(),
    }
    let keys = [
        DecapsulationKey::from_expanded_bytes(&bytes_a).unwrap(),
        DecapsulationKey::from_expanded_bytes(&bytes_b).unwrap(),
    ];
    let encoded = [bytes_a, bytes_b];
    let mut ciphertexts = Vec::new();
    for _ in 0..1024 {
        let mut bytes = [0u8; 1088];
        rng.fill_bytes(&mut bytes);
        let ct: Ciphertext = bytes.into();
        if cfg.vary != "keys" {
            // With the same z, both malformed ciphertext paths must agree.
            assert_eq!(keys[0].decapsulate(&ct), keys[1].decapsulate(&ct));
        }
        ciphertexts.push(ct);
    }
    // Confirm synthetic imports preserve the intended public/secret partition.
    if cfg.vary == "secret" || cfg.vary == "control" {
        assert_eq!(keys[0].encapsulation_key(), keys[1].encapsulation_key());
    }
    let mut shared_encoded = ExpandedDecapsulationKey::default();
    let mut shared_ct = Ciphertext::default();
    // Same decoded object address for both classes. Clone/drop occurs outside timing.
    for _ in 0..cfg.samples {
        let right = rng.gen::<bool>();
        shared_ct.copy_from_slice(&ciphertexts[rng.gen_range(0..ciphertexts.len())]);
        shared_encoded.copy_from_slice(&encoded[usize::from(right)]);
        let shared_key = black_box(keys[usize::from(right)].clone());
        let class = label(right, cfg.swap);
        if cfg.mode == "import" {
            runner.run_one(class, || {
                black_box(
                    DecapsulationKey::from_expanded_bytes(black_box(&shared_encoded)).unwrap(),
                );
            });
        } else {
            runner.run_one(class, || {
                black_box(shared_key.decapsulate(black_box(&shared_ct)));
            });
        }
    }
}

fn p384(runner: &mut CtRunner, rng: &mut BenchRng, cfg: &Config) {
    fn key(rng: &mut BenchRng) -> EcSecret {
        loop {
            let mut b = [0u8; 48];
            rng.fill_bytes(&mut b);
            if let Ok(key) = EcSecret::from_slice(&b) {
                return key;
            }
        }
    }
    let a = key(rng);
    let b = if cfg.vary == "control" {
        a.clone()
    } else {
        key(rng)
    };
    let keys = [a, b];
    let mut points = Vec::new();
    for _ in 0..256 {
        points.push(key(rng).public_key());
    }
    // Point choice is independent of class; both classes use the same public pool.
    let mut shared_bytes = [0u8; 97];
    for _ in 0..cfg.samples {
        let right = rng.gen::<bool>();
        let shared_key = black_box(keys[usize::from(right)].clone());
        let point = points[rng.gen_range(0..points.len())];
        shared_bytes.copy_from_slice(point.to_sec1_bytes().as_ref());
        let shared_point = black_box(point);
        let scalar = shared_key.to_nonzero_scalar();
        if cfg.mode == "p384-parse" {
            runner.run_one(label(right, cfg.swap), || {
                black_box(EcPublic::from_sec1_bytes(black_box(&shared_bytes)).unwrap());
            });
        } else {
            runner.run_one(label(right, cfg.swap), || {
                black_box(diffie_hellman(
                    black_box(&scalar),
                    black_box(shared_point.as_affine()),
                ));
            });
        }
    }
}

fn aad(runner: &mut CtRunner, rng: &mut BenchRng, cfg: &Config) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    let good = *b"dudect-aad-good";
    let bad = *b"dudect-aad-BAD!";
    let ctx = Context::raw(b"attribution");
    let ct = cit.seal(&pk, &[42u8; 256], &Aad::raw(&good), &ctx).unwrap();
    let mut bad_ct = ct.clone();
    let last = bad_ct.len() - 1;
    bad_ct[last] ^= 1;
    assert!(cit.open(&sk, &ct, &Aad::raw(&bad), &ctx).is_err());
    assert!(cit.open(&sk, &bad_ct, &Aad::raw(&good), &ctx).is_err());
    // Use the same public core called by Citadel::open, accepting borrowed AAD.
    let core = citadel_envelope::envelope::Envelope::new();
    let mut shared_ct = ct.clone();
    let mut shared_aad = [0u8; 15];
    for _ in 0..cfg.samples {
        let right = rng.gen::<bool>();
        let wrong_aad = cfg.vary == "control" || !right;
        shared_ct.copy_from_slice(if wrong_aad { &ct } else { &bad_ct });
        shared_aad.copy_from_slice(if wrong_aad { &bad } else { &good });
        runner.run_one(label(right, cfg.swap), || {
            let _ = black_box(core.open(
                &sk,
                black_box(&shared_ct),
                black_box(&shared_aad),
                ctx.as_bytes(),
            ));
        });
    }
}

fn main() {
    let mut cfg = Config {
        mode: "decap".into(),
        vary: "control".into(),
        samples: 100_000,
        swap: false,
    };
    let mut seed = 20260906;
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bench" => {}
            "--mode" => cfg.mode = args.next().expect("mode required"),
            "--vary" => cfg.vary = args.next().expect("variation required"),
            "--samples" => cfg.samples = args.next().unwrap().parse().unwrap(),
            "--seed" => seed = args.next().unwrap().parse().unwrap(),
            "--out" => out = Some(PathBuf::from(args.next().unwrap())),
            "--swap" => cfg.swap = true,
            _ => panic!("unknown argument: {arg}"),
        }
    }
    assert!(cfg.samples >= 10_000, "at least 10000 samples required");
    assert!(["import", "decap", "p384-parse", "p384-ecdh", "aad"].contains(&cfg.mode.as_str()));
    assert!(["control", "secret", "public", "keys"].contains(&cfg.vary.as_str()));
    assert!(!cfg.mode.starts_with("p384") || ["control", "secret"].contains(&cfg.vary.as_str()));
    assert!(cfg.mode != "aad" || ["control", "public"].contains(&cfg.vary.as_str()));
    println!(
        "mode={} vary={} generated_samples={} swap={} seed={}",
        cfg.mode, cfg.vary, cfg.samples, cfg.swap, seed
    );
    CONFIG.set(cfg).ok().unwrap();
    run_benches_console(
        BenchOpts {
            file_out: out,
            ..BenchOpts::default()
        },
        vec![BenchMetadata {
            name: BenchName("bench_attribution"),
            seed: Some(seed),
            benchfn: measure,
        }],
    )
    .unwrap();
}
