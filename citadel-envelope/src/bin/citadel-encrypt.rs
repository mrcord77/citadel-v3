// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Citadel CLI — post-quantum hybrid file encryption
//!
//! Usage:
//!   citadel keygen --name <n>
//!   citadel seal   --key <PUBKEY_FILE> --in <FILE> [--aad <AAD>] [--ctx <CTX>]
//!   citadel open   --key <SECKEY_FILE> --in <FILE> [--aad <AAD>] [--ctx <CTX>]

use std::fs;
use std::path::PathBuf;
use std::process;

use citadel_envelope::{Aad, Citadel, Context, PublicKey, SecretKey};
use zeroize::Zeroizing;

fn usage() -> ! {
    eprintln!(
        "Citadel — post-quantum hybrid encryption (X25519 + ML-KEM-768 + AES-256-GCM)\n\
         \n\
         Commands:\n\
         \n\
         Generate a keypair:\n\
         \n\
         citadel keygen --name <n>\n\
         Writes <n>.pub (public key) and <n>.sec (secret key)\n\
         \n\
         Encrypt a file:\n\
         \n\
         citadel seal --key <PUBKEY>.pub --in <FILE> [--aad <AAD>] [--ctx <CTX>]\n\
         Writes <FILE>.ctd\n\
         \n\
         Decrypt a file:\n\
         \n\
         citadel open --key <SECKEY>.sec --in <FILE>.ctd [--aad <AAD>] [--ctx <CTX>]\n\
         Writes <FILE> (strips .ctd extension, or appends .dec)\n"
    );
    process::exit(1);
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    process::exit(1);
}

fn parse_args() -> (String, Vec<(String, String)>) {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let command = args[1].clone();
    let mut flags: Vec<(String, String)> = Vec::new();

    let mut i = 2;
    while i < args.len() {
        if args[i].starts_with("--") && i + 1 < args.len() {
            flags.push((args[i].clone(), args[i + 1].clone()));
            i += 2;
        } else {
            die(&format!("unexpected argument: {}", args[i]));
        }
    }

    (command, flags)
}

fn get_flag(flags: &[(String, String)], name: &str) -> Option<String> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

fn require_flag(flags: &[(String, String)], name: &str) -> String {
    get_flag(flags, name).unwrap_or_else(|| die(&format!("missing required flag: {}", name)))
}

fn cmd_keygen(flags: &[(String, String)]) {
    let name = require_flag(flags, "--name");

    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let pub_path = format!("{}.pub", name);
    let sec_path = format!("{}.sec", name);

    // Write raw key bytes
    fs::write(&pub_path, pk.to_bytes())
        .unwrap_or_else(|e| die(&format!("write {}: {}", pub_path, e)));
    let sk_bytes = Zeroizing::new(sk.to_bytes());
    fs::write(&sec_path, sk_bytes.as_slice())
        .unwrap_or_else(|e| die(&format!("write {}: {}", sec_path, e)));

    eprintln!("keypair generated:");
    eprintln!(
        "  public key:  {} ({} bytes)",
        pub_path,
        pk.to_bytes().len()
    );
    eprintln!("  secret key:  {} ({} bytes)", sec_path, sk_bytes.len());
    eprintln!();
    eprintln!("keep {0} safe. share {1} freely.", sec_path, pub_path);
}

fn cmd_seal(flags: &[(String, String)]) {
    let key_file = require_flag(flags, "--key");
    let in_file = require_flag(flags, "--in");
    let aad_str = get_flag(flags, "--aad").unwrap_or_default();
    let ctx_str = get_flag(flags, "--ctx").unwrap_or_else(|| "citadel-cli-v1".to_string());

    let out_file = format!("{}.ctd", in_file);

    // Load public key
    let pk_bytes =
        fs::read(&key_file).unwrap_or_else(|e| die(&format!("read {}: {}", key_file, e)));
    let pk = PublicKey::from_bytes(&pk_bytes).unwrap_or_else(|_| die("invalid public key file"));

    // Load plaintext
    let plaintext = Zeroizing::new(
        fs::read(&in_file).unwrap_or_else(|e| die(&format!("read {}: {}", in_file, e))),
    );

    // Encrypt
    let citadel = Citadel::new();
    let aad = Aad::raw(aad_str.as_bytes());
    let ctx = Context::raw(ctx_str.as_bytes());
    let ciphertext = citadel
        .seal(&pk, &plaintext, &aad, &ctx)
        .unwrap_or_else(|_| die("encryption failed"));

    // Write ciphertext
    fs::write(&out_file, &ciphertext)
        .unwrap_or_else(|e| die(&format!("write {}: {}", out_file, e)));

    eprintln!(
        "sealed {} -> {} ({} bytes plaintext -> {} bytes ciphertext)",
        in_file,
        out_file,
        plaintext.len(),
        ciphertext.len()
    );
}

fn cmd_open(flags: &[(String, String)]) {
    let key_file = require_flag(flags, "--key");
    let in_file = require_flag(flags, "--in");
    let aad_str = get_flag(flags, "--aad").unwrap_or_default();
    let ctx_str = get_flag(flags, "--ctx").unwrap_or_else(|| "citadel-cli-v1".to_string());

    // Determine output filename
    let out_file = if in_file.ends_with(".ctd") {
        in_file.trim_end_matches(".ctd").to_string()
    } else {
        format!("{}.dec", in_file)
    };

    // Don't overwrite the input
    let out_path = PathBuf::from(&out_file);
    let in_path = PathBuf::from(&in_file);
    if out_path == in_path {
        die("output path would overwrite input — rename the input file");
    }

    // Load secret key
    let sk_bytes = Zeroizing::new(
        fs::read(&key_file).unwrap_or_else(|e| die(&format!("read {}: {}", key_file, e))),
    );
    let sk = SecretKey::from_bytes(&sk_bytes).unwrap_or_else(|_| die("invalid secret key file"));

    // Load ciphertext
    let ciphertext =
        fs::read(&in_file).unwrap_or_else(|e| die(&format!("read {}: {}", in_file, e)));

    // Decrypt
    let citadel = Citadel::new();
    let aad = Aad::raw(aad_str.as_bytes());
    let ctx = Context::raw(ctx_str.as_bytes());
    let plaintext = Zeroizing::new(citadel.open(&sk, &ciphertext, &aad, &ctx).unwrap_or_else(
        |_| die("decryption failed (wrong key, corrupted, or mismatched aad/context)"),
    ));

    // Write plaintext
    fs::write(&out_file, &plaintext).unwrap_or_else(|e| die(&format!("write {}: {}", out_file, e)));

    eprintln!(
        "opened {} -> {} ({} bytes ciphertext -> {} bytes plaintext)",
        in_file,
        out_file,
        ciphertext.len(),
        plaintext.len()
    );
}

fn main() {
    let (command, flags) = parse_args();

    match command.as_str() {
        "keygen" => cmd_keygen(&flags),
        "seal" => cmd_seal(&flags),
        "open" => cmd_open(&flags),
        _ => {
            eprintln!("unknown command: {}", command);
            usage();
        }
    }
}
