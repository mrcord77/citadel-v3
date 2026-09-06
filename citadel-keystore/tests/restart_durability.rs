// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression checks for acknowledged replay persistence and audit-chain recovery.
use citadel_keystore::audit::{AuditAction, AuditEvent, AuditSinkSync, IntegrityChainSink};
use citadel_keystore::replay_store::{FileReplayStore, ReplayStore};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Barrier};
use std::time::Duration;

fn event(name: &str) -> AuditEvent {
    AuditEvent::system_event(AuditAction::PolicyRegistered {
        policy_id: name.into(),
    })
}

#[test]
fn acknowledged_claim_is_on_disk_without_drop_or_force_flush() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.json");
    let ttl = Duration::from_secs(3600);
    let first = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(first.claim(b"acknowledged", ttl).unwrap());
    // The original store is still alive: destructor flushing cannot make this pass.
    let recovered = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(!recovered.claim(b"acknowledged", ttl).unwrap());
}

#[test]
fn unwritable_claim_is_never_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing/replay.json");
    let ttl = Duration::from_secs(3600);
    let store = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(store.claim(b"denied", ttl).is_err());
    // Conservatively retained, even if the caller retries before storage recovery.
    assert!(!store.claim(b"denied", ttl).unwrap());
}

#[test]
fn failed_release_keeps_reservation_and_existing_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.json");
    let ttl = Duration::from_secs(3600);
    let store = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(store.claim(b"reserved", ttl).unwrap());
    // Deterministic write failure even when tests run as root.
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    assert!(store.release(b"reserved").is_err());
    assert!(!store.claim(b"reserved", ttl).unwrap());
    let recovered = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(!recovered.claim(b"reserved", ttl).unwrap());
}

#[test]
fn failed_claim_does_not_erase_previously_durable_claims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.json");
    let ttl = Duration::from_secs(3600);
    let store = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(store.claim(b"first", ttl).unwrap());
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    assert!(store.claim(b"second", ttl).is_err());
    let recovered = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(!recovered.claim(b"first", ttl).unwrap());
}

#[test]
fn failed_decrypt_release_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replay.json");
    let ttl = Duration::from_secs(3600);
    let store = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(store.claim(b"released", ttl).unwrap());
    store.release(b"released").unwrap();
    let recovered = FileReplayStore::new(&path, ttl, true).unwrap();
    assert!(recovered.claim(b"released", ttl).unwrap());
}

#[test]
fn audit_continues_existing_chain_across_restarts_and_concurrency() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    for round in 0..3 {
        let chain = Arc::new(IntegrityChainSink::open_file(&path).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|worker| {
                let chain = chain.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for i in 0..8 {
                        chain
                            .try_record(event(&format!("{round}-{worker}-{i}")))
                            .unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let mut prev = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
    assert_eq!(text.lines().count(), 192);
    for (seq, line) in text.lines().enumerate() {
        let e: AuditEvent = serde_json::from_str(line).unwrap();
        assert_eq!(e.sequence, Some(seq as u64));
        assert_eq!(e.prev_hash.as_deref(), Some(prev.as_str()));
        prev = format!("{:x}", Sha256::digest(line.as_bytes()));
    }
    IntegrityChainSink::open_file(&path).unwrap();
}

#[test]
fn corrupt_or_partial_audit_is_rejected_without_rewriting_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let chain = IntegrityChainSink::open_file(&path).unwrap();
    chain.try_record(event("original")).unwrap();
    chain.try_record(event("second")).unwrap();
    drop(chain);
    let original = std::fs::read_to_string(&path).unwrap();
    for damaged in [
        original.replacen("original", "tampered", 1),
        original.trim_end_matches('\n').to_owned(),
        "{invalid json}\n".to_owned(),
        original.replacen("\"sequence\":1", "\"sequence\":0", 1),
    ] {
        assert_ne!(damaged, original);
        std::fs::write(&path, &damaged).unwrap();
        assert!(IntegrityChainSink::open_file(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
    }
}

#[test]
fn audit_append_failure_is_reported_and_does_not_advance_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let saved = dir.path().join("saved.jsonl");
    let chain = IntegrityChainSink::open_file(&path).unwrap();
    chain.try_record(event("first")).unwrap();
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(chain.try_record(event("must-fail")).is_err());
    assert!(chain.check_health().is_err());
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    // No append past an uncertain failure until recovery has verified the file.
    assert!(chain.try_record(event("must-still-fail")).is_err());
    let recovered = IntegrityChainSink::open_file(&path).unwrap();
    recovered.try_record(event("recovered")).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    let last: AuditEvent = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last.sequence, Some(1));
    assert_eq!(text.lines().count(), 2);
}
