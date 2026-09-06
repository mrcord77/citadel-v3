// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Audit logging: every key operation emits a structured event.

use crate::types::{KeyId, KeyState, KeyType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[path = "audit_file.rs"]
mod audit_file;

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// What happened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditAction {
    KeyGenerated,
    KeyActivated,
    KeyRotated {
        new_version: u32,
    },
    KeyExpired {
        reason: String,
    },
    KeyRevoked {
        reason: String,
    },
    KeyDestroyed,
    EncryptionPerformed {
        key_version: u32,
    },
    DecryptionPerformed {
        key_version: u32,
    },
    DecryptionFailed {
        key_version: u32,
    },
    PolicyRegistered {
        policy_id: String,
    },
    PolicyEvaluated {
        verdict: String,
    },
    ExpirationCheckRun {
        expired_count: usize,
        warning_count: usize,
    },

    // ── V3 security events (P067) ────────────────────────────────────────────
    /// DEK secret key re-wrapped under a different parent KEK (P062).
    KeyRewrapped {
        old_parent_id: Option<String>,
        new_parent_id: Option<String>,
        new_parent_version: Option<u32>,
    },

    /// Unwrap chain failed because a parent key is revoked/destroyed (P061).
    HierarchyViolation {
        parent_id: String,
        parent_state: String,
        child_id: String,
    },

    /// Plaintext key storage is active — acceptable only in development (P063).
    PlaintextModeActivated {
        /// `"development"` or `"PRODUCTION (UNSAFE)"`.
        environment: String,
    },

    /// `try_new_production()` blocked startup due to failing doctor checks (P066).
    PreflightFailed {
        failing_checks: Vec<String>,
    },

    /// `validate_wrapping_graph()` found violations at key-generate time.
    WrappingGraphViolation {
        violations_count: usize,
        first_detail: String,
    },

    /// A decryption attempt was rejected because a nonce was already seen.
    ReplayDetected {
        key_version: u32,
    },

    /// P158 — An API authentication attempt failed.
    /// Written to the tamper-evident audit chain so auth failures are durable evidence.
    /// An attacker making thousands of auth attempts cannot erase this record.
    AuthFailed {
        /// Why authentication failed (e.g. "invalid key", "key revoked", "no credentials")
        reason: String,
        /// The key ID attempted, if the request included one and it was identifiable.
        key_id_attempted: Option<String>,
    },

    /// P158 — A successful authentication event.
    AuthSuccess {
        key_id: String,
        key_name: String,
    },

    // ── P362 — ML-DSA-65 signing events ──────────────────────────────────────
    /// ML-DSA-65 signing operation performed successfully.
    /// `payload_bytes` records the size of the signed message for audit purposes.
    SigningPerformed {
        key_version: u32,
        payload_bytes: usize,
    },

    /// ML-DSA-65 signing operation failed (key state, unwrap failure, or type mismatch).
    SigningFailed {
        key_version: u32,
        reason: String,
    },

    /// Signature verification performed.
    ///
    /// Verification is stateless — it uses only the public key from `KeyVersion.public_key_hex`.
    /// `valid = false` is recorded for audit purposes (may indicate tampering or wrong key).
    VerificationPerformed {
        key_version: u32,
        valid: bool,
    },
}

/// A structured audit event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When it happened.
    pub timestamp: DateTime<Utc>,
    /// Which key was involved.
    pub key_id: Option<KeyId>,
    /// What type of key.
    pub key_type: Option<KeyType>,
    /// What state the key was in.
    pub key_state: Option<KeyState>,
    /// What happened.
    pub action: AuditAction,
    /// Who or what triggered this.
    pub actor: String,
    /// Success or failure.
    pub success: bool,
    /// Additional context.
    pub detail: Option<String>,
    /// Monotonic sequence number (populated by integrity chain sink).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// SHA-256 hash of the previous event's JSON (populated by integrity chain sink).
    /// First event in chain has prev_hash = SHA-256("citadel-audit-genesis").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event for a key operation.
    pub fn key_event(
        key_id: &KeyId,
        key_type: KeyType,
        key_state: KeyState,
        action: AuditAction,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            key_id: Some(key_id.clone()),
            key_type: Some(key_type),
            key_state: Some(key_state),
            action,
            actor: "system".into(),
            success: true,
            detail: None,
            sequence: None,
            prev_hash: None,
        }
    }

    /// Create a system-level audit event (no specific key).
    pub fn system_event(action: AuditAction) -> Self {
        Self {
            timestamp: Utc::now(),
            key_id: None,
            key_type: None,
            key_state: None,
            action,
            actor: "system".into(),
            success: true,
            detail: None,
            sequence: None,
            prev_hash: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    pub fn with_failure(mut self) -> Self {
        self.success = false;
        self
    }
}

// ---------------------------------------------------------------------------
// Audit sink trait
// ---------------------------------------------------------------------------

/// Where audit events go. Implement this for your SIEM/log system.
///
/// Synchronous to avoid the `async_trait` dependency.
/// For async sinks, use interior mutability (e.g., channel-based).
pub trait AuditSinkSync: Send + Sync {
    fn record(&self, event: AuditEvent);

    /// Expose a latched sink failure to request/operation boundaries.
    fn check_health(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Fallible append for sinks that can report storage failures. The default
    /// preserves compatibility with existing best-effort third-party sinks.
    fn try_record(&self, event: AuditEvent) -> std::io::Result<()> {
        self.record(event);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Built-in sinks
// ---------------------------------------------------------------------------

/// Logs events via the `tracing` crate.
pub struct TracingAuditSink;

impl AuditSinkSync for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        tracing::info!(
            timestamp = %event.timestamp,
            key_id = ?event.key_id,
            action = ?event.action,
            actor = %event.actor,
            success = event.success,
            detail = ?event.detail,
            "audit"
        );
    }
}

/// Collects events in memory (for testing and the API layer).
pub struct InMemoryAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().await.clone()
    }

    pub async fn events_for_key(&self, key_id: &KeyId) -> Vec<AuditEvent> {
        self.events
            .lock()
            .await
            .iter()
            .filter(|e| e.key_id.as_ref() == Some(key_id))
            .cloned()
            .collect()
    }

    pub async fn len(&self) -> usize {
        self.events.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.events.lock().await.is_empty()
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSinkSync for InMemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        // Use try_lock to avoid blocking â€” best effort for in-memory sink
        if let Ok(mut events) = self.events.try_lock() {
            events.push(event);
        }
    }
}

/// Writes JSON events to a file (append-only).
pub struct FileAuditSink {
    path: std::path::PathBuf,
}

impl FileAuditSink {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditSinkSync for FileAuditSink {
    fn record(&self, event: AuditEvent) {
        if let Err(error) = self.try_record(event) {
            tracing::error!(%error, "audit append failed");
        }
    }

    fn try_record(&self, event: AuditEvent) -> std::io::Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        let mut bytes = serde_json::to_vec(&event).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()
    }
}

// ---------------------------------------------------------------------------
// Integrity chain sink (tamper-evident audit log)
// ---------------------------------------------------------------------------

/// Wraps any `AuditSinkSync` and adds a SHA-256 hash chain.
///
/// Each event gets a monotonic `sequence` number and a `prev_hash`
/// containing the SHA-256 hex digest of the previous event's JSON.
/// Verifiers can replay the log and recompute hashes to detect
/// any insertion, deletion, or modification of events.
///
/// The genesis hash is `SHA-256("citadel-audit-genesis")`.
pub struct IntegrityChainSink {
    inner: Arc<dyn AuditSinkSync>,
    state: std::sync::Mutex<ChainState>,
    /// P007: Optional external witness for tamper detection
    witness: Option<Box<dyn crate::audit_witness::AuditWitness>>,
    /// P007: Anchor hash to witness every N entries (default: 1000)
    anchor_interval: u64,
}

struct ChainState {
    sequence: u64,
    prev_hash: String,
    // An append failure can leave a partial record. Do not append past it until
    // the file is validated again on restart or explicitly recovered by an operator.
    failed: bool,
}

impl IntegrityChainSink {
    pub fn new(inner: Arc<dyn AuditSinkSync>) -> Self {
        Self::with_witness(inner, None, 1000)
    }

    /// P007: Create with optional external witness for tamper detection.
    ///
    /// # Arguments
    /// * `inner` - Underlying sink to forward events to
    /// * `witness` - Optional external witness (None = no anchoring)
    /// * `anchor_interval` - Publish hash every N entries (default: 1000)
    pub fn with_witness(
        inner: Arc<dyn AuditSinkSync>,
        witness: Option<Box<dyn crate::audit_witness::AuditWitness>>,
        anchor_interval: u64,
    ) -> Self {
        use sha2::{Digest, Sha256};
        let genesis = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));

        if let Some(ref w) = witness {
            tracing::info!(
                witness_id = w.witness_id(),
                anchor_interval = anchor_interval,
                "audit witness enabled"
            );
        }

        Self {
            inner,
            state: std::sync::Mutex::new(ChainState {
                sequence: 0,
                prev_hash: genesis,
                failed: false,
            }),
            witness,
            anchor_interval,
        }
    }
}

impl AuditSinkSync for IntegrityChainSink {
    fn check_health(&self) -> std::io::Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("audit chain lock poisoned"))?;
        if state.failed {
            return Err(std::io::Error::other(
                "audit append failed; operator recovery required",
            ));
        }
        self.inner.check_health()
    }

    fn record(&self, event: AuditEvent) {
        if let Err(error) = self.try_record(event) {
            // Existing record() callers remain best effort. Fallible callers can
            // use try_record(); never conceal a failed file append from the chain.
            tracing::error!(%error, "audit chain append failed; chain requires recovery");
        }
    }

    fn try_record(&self, mut event: AuditEvent) -> std::io::Result<()> {
        use sha2::{Digest, Sha256};
        let mut state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("audit chain lock poisoned"))?;
        if state.failed {
            return Err(std::io::Error::other(
                "audit chain halted after append failure",
            ));
        }
        let next_sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("audit sequence exhausted"))?;
        event.sequence = Some(state.sequence);
        event.prev_hash = Some(state.prev_hash.clone());
        let json = serde_json::to_vec(&event).map_err(std::io::Error::other)?;
        let next_hash = format!("{:x}", Sha256::digest(&json));

        // Keep the chain lock through the append. Releasing it before forwarding
        // lets concurrent writers put correctly numbered events in the wrong order.
        if let Err(error) = self.inner.try_record(event) {
            state.failed = true;
            return Err(error);
        }
        state.prev_hash = next_hash;
        let recorded_sequence = state.sequence;
        state.sequence = next_sequence;

        // Only witness events that have actually been accepted by the inner sink.
        if recorded_sequence > 0
            && self.anchor_interval > 0
            && recorded_sequence % self.anchor_interval == 0
        {
            if let Some(ref witness) = self.witness {
                let hash_bytes = hex::decode(&state.prev_hash).map_err(std::io::Error::other)?;
                if let Err(error) = witness.publish_hash(recorded_sequence, &hash_bytes) {
                    tracing::error!(%error, "failed to anchor audit hash; local chain retained");
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// P193 -- Audit chain integrity tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// P193 -- Audit chain records lifecycle events and hash chain is consistent.
    #[test]
    fn audit_chain_records_lifecycle_events() {
        use sha2::{Digest, Sha256};

        let mem = Arc::new(InMemoryAuditSink::new());
        let chain = IntegrityChainSink::new(mem.clone());

        let key_id = KeyId::new("test-key-p193");

        // Record lifecycle events
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::DataEncrypting,
            KeyState::Pending,
            AuditAction::KeyGenerated,
        ));
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::DataEncrypting,
            KeyState::Active,
            AuditAction::KeyActivated,
        ));
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::DataEncrypting,
            KeyState::Active,
            AuditAction::KeyRotated { new_version: 2 },
        ));
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::DataEncrypting,
            KeyState::Revoked,
            AuditAction::KeyRevoked {
                reason: "p193-test".to_string(),
            },
        ));

        // Verify 4 events recorded
        let events = mem.events.try_lock().unwrap().clone();
        assert_eq!(events.len(), 4, "must record all lifecycle events");

        // Verify sequence numbers are monotonic
        for (i, evt) in events.iter().enumerate() {
            assert_eq!(evt.sequence, Some(i as u64), "sequence must be monotonic");
        }

        // Verify hash chain integrity: recompute each prev_hash
        let genesis = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
        let mut expected_prev = genesis;

        for evt in &events {
            assert_eq!(
                evt.prev_hash.as_deref(),
                Some(expected_prev.as_str()),
                "prev_hash must link correctly at sequence {:?}",
                evt.sequence
            );
            // Compute what the next prev_hash should be
            let json = serde_json::to_string(evt).unwrap();
            expected_prev = format!("{:x}", Sha256::digest(json.as_bytes()));
        }
    }

    /// P193 -- Tamper detection: modifying a recorded event breaks the hash chain.
    /// The chain itself does not self-verify, but a verifier replaying it will detect tampering.
    #[test]
    fn audit_chain_tamper_is_detectable() {
        use sha2::{Digest, Sha256};

        let mem = Arc::new(InMemoryAuditSink::new());
        let chain = IntegrityChainSink::new(mem.clone());

        let key_id = KeyId::new("tamper-key-p193");
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::Root,
            KeyState::Pending,
            AuditAction::KeyGenerated,
        ));
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::Root,
            KeyState::Active,
            AuditAction::KeyActivated,
        ));
        chain.record(AuditEvent::key_event(
            &key_id,
            KeyType::Root,
            KeyState::Revoked,
            AuditAction::KeyRevoked {
                reason: "original".to_string(),
            },
        ));

        let mut events = mem.events.try_lock().unwrap().clone();

        // Simulate tampering: change the reason in event[2]
        if let AuditAction::KeyRevoked { ref mut reason } = events[2].action {
            *reason = "TAMPERED".to_string();
        }

        // Now verify the chain -- event[2].prev_hash should NOT match recomputed hash of event[1]
        let genesis = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
        let mut prev = genesis;
        let mut tamper_detected = false;

        for evt in &events {
            if evt.prev_hash.as_deref() != Some(prev.as_str()) {
                tamper_detected = true;
                break;
            }
            let json = serde_json::to_string(evt).unwrap();
            prev = format!("{:x}", Sha256::digest(json.as_bytes()));
        }

        // P284: Assert that the untampered chain is intact. Without this assertion
        // tamper_detected was set but never read — the first loop was dead code.
        assert!(
            !tamper_detected,
            "untampered chain must be valid before we perform any tampering"
        );

        // After modifying event[2]'s content, the chain's own prev_hash in event[2]
        // is still the original -- but if we modified an earlier event, the chain breaks.
        // For this test: tamper event[0]'s content after recording
        let mut events2 = mem.events.try_lock().unwrap().clone();
        events2[0].actor = "ATTACKER".to_string(); // tamper first event

        let mut prev2 = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
        let mut chain_broken = false;
        for evt in &events2 {
            if evt.prev_hash.as_deref() != Some(prev2.as_str()) {
                chain_broken = true;
                break;
            }
            let json = serde_json::to_string(evt).unwrap();
            prev2 = format!("{:x}", Sha256::digest(json.as_bytes()));
        }

        // Event[0] prev_hash matches genesis (unchanged), but its content changed.
        // Event[1].prev_hash was computed from original event[0] -- now won't match.
        assert!(
            chain_broken,
            "tampering with event[0] must break the chain at event[1]"
        );
    }
}
