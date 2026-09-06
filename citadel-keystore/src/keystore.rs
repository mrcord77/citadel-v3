// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Main keystore: key lifecycle management with policy, audit, and envelope integration.
//!
//! V2 changes (P044, P045):
//!
//! **P044 — Real KEK hierarchy:**
//! When generating or rotating a key whose parent is a KeyEncrypting or Domain key,
//! the child's secret key is now sealed using the parent's Citadel public key
//! (hybrid X25519 + ML-KEM-768 envelope) and stored as `SecretKeyMaterial::CitadelWrapped`.
//! Unwrapping is async and recursive: the parent key's material is unwrapped first
//! (which may itself require unwrapping its own parent), up to a depth limit of 4.
//! Keys with no parent or whose parent is Root continue to use AES-256-GCM wrapping
//! with `CITADEL_MASTER_KEY`.
//!
//! **P045/P388 — Pluggable replay store (current model):**
//! `Keystore` holds `Box<dyn ReplayStore>` for nonce deduplication.
//! `MemoryReplayStore` is the default (dev/single-instance only).
//! Inject a persistent backend via `set_replay_store()`:
//!   - `FileReplayStore` — single-instance, restart-safe
//!   - `RedisReplayStore` — multi-instance (requires `redis-backend` feature)
//!
//! Semantics: `claim(key, ttl)` → exclusive one-time use; `release(key)` → undo.
//! Always use `fail_closed = true` in production.
//! (V2 types `ReplayCacheBackend`, `InMemoryReplayCache`, `FileReplayCache`
//! are deprecated — see `citadel_keystore::replay` module.)
//!
//! **P211 — Strict hierarchy enforcement at generate() time:**
//! `generate()` now calls `KeyRole::can_wrap()` for ALL key types — not just leaf keys.
//! Enforced: Root(no parent) → Domain → KeyEncrypting → DataEncrypting/HybridIdentity.
//! Any other parent/child relationship returns `HierarchyViolation` unless
//! `CITADEL_ALLOW_FLAT_DEKS=1` is set (test/dev override only).

use crate::audit::{AuditAction, AuditEvent, AuditSinkSync};
use crate::error::*;
use crate::policy::{self, KeyPolicy};
use crate::replay_store::{MemoryReplayStore, ReplayStore};
use crate::root_key_provider::{RootKeyError, RootKeyProvider};
use crate::storage::StorageBackend;
use crate::threat::{
    PolicyAdapter, SecurityMetrics, ThreatAssessor, ThreatConfig, ThreatEvent, ThreatEventKind,
    ThreatLevel,
};
use crate::types::*;
use std::pin::Pin;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::Utc;
use citadel_envelope::{Aad, Citadel, Context, PublicKey, SecretKey};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};
// P378 — StateEnforcer binding for in-keystore capability validation
use citadel_core::StateEnforcer;
use tokio::sync::RwLock;

// P372 — ML-DSA-65 signing delegates entirely to citadel-signer (single algorithm surface)
// ml-dsa crate no longer imported directly in keystore — all ML-DSA ops go through citadel-signer
// ---------------------------------------------------------------------------
// Maximum hierarchy depth for recursive unwrapping (prevents infinite loops)
// ---------------------------------------------------------------------------

/// Maximum number of recursive key-unwrap steps.
///
/// The four-level hierarchy (Root → Domain → KEK → DEK) needs at most
/// 3 levels of indirection to unwrap a DEK (DEK→KEK→Domain, then Domain is
/// AES-wrapped by CITADEL_MASTER_KEY). A depth limit of 4 gives one extra level
/// of headroom while preventing infinite recursion if wrapping_key_id chains
/// are somehow circular or deeper than expected.
const MAX_UNWRAP_DEPTH: u8 = 4;

/// AAD bound into all Citadel-hierarchy-wrapped key material (V2).
const HIERARCHY_WRAP_AAD: &[u8] = b"citadel-kek-hierarchy-v2";

// ---------------------------------------------------------------------------
// Encrypted blob (output of convenience encrypt)
// ---------------------------------------------------------------------------

/// A ciphertext with metadata about which key encrypted it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedBlob {
    /// Which key ID was used.
    pub key_id: String,
    /// Which version of that key.
    pub key_version: u32,
    /// The ciphertext bytes (hex-encoded for JSON safety).
    pub ciphertext_hex: String,
    /// When this blob was created.
    pub encrypted_at: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

pub struct Keystore {
    storage: Arc<dyn StorageBackend>,
    audit: Arc<dyn AuditSinkSync>,
    policies: HashMap<String, KeyPolicy>,
    envelope: Citadel,
    threat: Mutex<ThreatAssessor>,
    /// AES-256 master key for wrapping Root/Domain key material at rest.
    master_key: Option<Zeroizing<[u8; 32]>>,
    /// Provider identifier used to obtain the process-resident root wrapping key.
    root_key_provider_name: Option<&'static str>,
    /// Pluggable nonce deduplication store (P066 — fail-closed capable).
    replay_cache: Mutex<Box<dyn ReplayStore>>,
    /// P378 — Bound StateEnforcer for in-keystore capability token validation.
    ///
    /// When set, `encrypt_authorized`, `decrypt_authorized`, and `sign_authorized`
    /// call `authz.validate(&enforcer)` at the keystore boundary — not just in the API.
    ///
    /// Security model:
    ///   StateEnforcer: authorizes identity/domain/lifecycle access (issues AuthorizedContext)
    ///   Keystore:      validates capability issuance (token from live enforcer) + enforces key role
    ///   API:           calls authorize_* then passes AuthorizedContext to keystore boundary
    ///
    /// Without this binding, a structurally valid but stale AuthorizedContext (from a
    /// replaced or restarted enforcer) could reach the keystore. With this binding,
    /// the keystore self-validates — no caller discipline required.
    enforcer: Option<Arc<RwLock<StateEnforcer>>>,
}

/// P385 — Machine-readable authority scope for Keystore.
/// Keystore is the cryptographic role authority — complements StateEnforcer
/// which is the identity/lifecycle/operation authority. Both are required.
/// See citadel-core/src/state_enforcer.rs for the full authority model diagram.
pub const AUTHORITY_SCOPE: &str = "crypto-role-key-state-replay-execution";

impl Keystore {
    /// Create a new keystore with in-memory replay store (default).
    pub fn new(storage: Arc<dyn StorageBackend>, audit: Arc<dyn AuditSinkSync>) -> Self {
        let master_key = Self::load_master_key_from_env();
        let ks = Self {
            storage,
            audit: audit.clone(),
            policies: HashMap::new(),
            envelope: Citadel::new(),
            threat: Mutex::new(ThreatAssessor::new(ThreatConfig::default()).with_audit(audit)),
            master_key,
            root_key_provider_name: std::env::var("CITADEL_MASTER_KEY")
                .ok()
                .map(|_| "development-env-v1"),
            replay_cache: Mutex::new(Box::new(MemoryReplayStore::new(
                Duration::from_secs(86400),
                true,
            ))),
            enforcer: None, // P378: set via with_enforcer() after construction
        };
        ks.audit_plaintext_mode_if_active();
        ks
    }

    /// Create with an explicitly provided master key.
    pub fn with_master_key(
        storage: Arc<dyn StorageBackend>,
        audit: Arc<dyn AuditSinkSync>,
        master_key: [u8; 32],
    ) -> Self {
        let mut mk = Zeroizing::new([0u8; 32]);
        mk.copy_from_slice(&master_key);
        let ks = Self {
            storage,
            audit: audit.clone(),
            policies: HashMap::new(),
            envelope: Citadel::new(),
            threat: Mutex::new(ThreatAssessor::new(ThreatConfig::default()).with_audit(audit)),
            master_key: Some(mk),
            root_key_provider_name: Some("explicit-development-v1"),
            replay_cache: Mutex::new(Box::new(MemoryReplayStore::new(
                Duration::from_secs(86400),
                true,
            ))),
            enforcer: None, // P378: set via with_enforcer() after construction
        };
        ks.audit_plaintext_mode_if_active();
        ks
    }

    /// Create a keystore from an explicit custody provider.
    ///
    /// The provider controls acquisition and capability checks. The resulting
    /// key remains process-resident in zeroizing memory because the existing
    /// `enc:` wrapping format performs AES-GCM locally; this is not an HSM claim.
    pub fn with_root_key_provider(
        storage: Arc<dyn StorageBackend>,
        audit: Arc<dyn AuditSinkSync>,
        provider: &dyn RootKeyProvider,
    ) -> Result<Self, RootKeyError> {
        let master_key = provider.load_root_key()?;
        let mut keystore = Self::with_master_key(storage, audit, *master_key);
        keystore.root_key_provider_name = Some(provider.name());
        Ok(keystore)
    }

    /// Provider identifier for audit and deployment diagnostics.
    pub fn root_key_provider_name(&self) -> Option<&'static str> {
        self.root_key_provider_name
    }

    /// Create with custom threat configuration.
    pub fn with_threat_config(
        storage: Arc<dyn StorageBackend>,
        audit: Arc<dyn AuditSinkSync>,
        threat_config: ThreatConfig,
    ) -> Self {
        let master_key = Self::load_master_key_from_env();
        Self {
            storage,
            audit: audit.clone(),
            policies: HashMap::new(),
            envelope: Citadel::new(),
            threat: Mutex::new(ThreatAssessor::new(threat_config).with_audit(audit)),
            master_key,
            root_key_provider_name: std::env::var("CITADEL_MASTER_KEY")
                .ok()
                .map(|_| "development-env-v1"),
            replay_cache: Mutex::new(Box::new(MemoryReplayStore::new(
                Duration::from_secs(86400),
                true,
            ))),
            enforcer: None,
        }
    }

    /// Inject a custom replay store backend (P066 — replaces V2 ReplayCacheBackend).
    ///
    /// Use `FileReplayStore` for single-instance persistence across restarts.
    /// Use `RedisReplayStore` for multi-instance deployments.
    /// Always set `fail_closed = true` in production.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use citadel_keystore::{Keystore, MemoryReplayStore};
    /// use std::time::Duration;
    ///
    /// let mut ks = Keystore::new(storage, audit);
    /// // Replace with file-backed store for restart-safe protection:
    /// // ks.set_replay_store(FileReplayStore::new("./replay.json", Duration::from_secs(86400), true).expect("replay init"));
    /// ```
    pub fn set_replay_store(&mut self, store: Box<dyn ReplayStore>) {
        self.replay_cache = Mutex::new(store);
    }

    /// Legacy alias — calls `set_replay_store`.
    #[deprecated(since = "0.3.0", note = "use set_replay_store instead")]
    pub fn set_replay_cache(&mut self, store: Box<dyn ReplayStore>) {
        self.set_replay_store(store);
    }

    /// P378/P384 — Bind the authoritative `StateEnforcer` into the keystore (builder pattern).
    ///
    /// **Required in production (P384 fail-closed).** Without this call, all authorized
    /// methods (`encrypt_authorized`, `decrypt_authorized`, `sign_authorized`) return `Err`.
    ///
    /// The enforcer MUST be the SAME instance that issues `AuthorizedContext`s — the
    /// `issued_tokens` registry only contains nonces from its own `generate_capability_token()`.
    ///
    /// ```ignore
    /// let enforcer = Arc::new(RwLock::new(StateEnforcer::new()));
    /// let ks = Keystore::new(storage, audit)
    ///     .with_enforcer(Arc::clone(&enforcer));
    /// // Now: enforcer.authorize_encrypt(...) → auth_ctx → ks.encrypt_authorized(&auth_ctx, ...)
    /// ```
    pub fn with_enforcer(mut self, enforcer: Arc<RwLock<StateEnforcer>>) -> Self {
        self.enforcer = Some(enforcer);
        self
    }

    /// P384 — Bind the authoritative `StateEnforcer` (mutable variant of `with_enforcer`).
    ///
    /// Use when the keystore is already constructed and cannot be re-built with the
    /// builder pattern (e.g., in test helpers or late initialization scenarios).
    pub fn set_enforcer(&mut self, enforcer: Arc<RwLock<StateEnforcer>>) {
        self.enforcer = Some(enforcer);
    }

    // -----------------------------------------------------------------------
    // Master key management
    // -----------------------------------------------------------------------

    fn load_master_key_from_env() -> Option<Zeroizing<[u8; 32]>> {
        match std::env::var("CITADEL_MASTER_KEY") {
            Ok(hex_str) => match hex::decode(hex_str.trim()) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut key = Zeroizing::new([0u8; 32]);
                    key.copy_from_slice(&bytes);
                    tracing::info!(
                        "CITADEL_MASTER_KEY loaded - Root/Domain keys will be AES-wrapped at rest"
                    );
                    Some(key)
                }
                Ok(bytes) => {
                    tracing::error!(
                        len = bytes.len(),
                        "CITADEL_MASTER_KEY must be exactly 32 bytes (64 hex chars) - ignoring"
                    );
                    None
                }
                Err(e) => {
                    tracing::error!(err = %e, "CITADEL_MASTER_KEY invalid hex - ignoring");
                    None
                }
            },
            Err(_) => {
                tracing::warn!(
                    "CITADEL_MASTER_KEY not set - Root/Domain keys will be stored as plaintext hex."
                );
                None
            }
        }
    }

    // -----------------------------------------------------------------------
    // Key wrapping / unwrapping
    // -----------------------------------------------------------------------

    /// Wrap a key using AES-256-GCM with CITADEL_MASTER_KEY.
    ///
    /// Used for Root and Domain keys (no online parent KEK in hierarchy).
    /// Returns an error string instead of panicking.
    fn wrap_with_master_key(
        &self,
        key_id: &KeyId,
        version: u32,
        sk_bytes: &[u8],
    ) -> Result<SecretKeyMaterial, String> {
        let Some(ref mk) = self.master_key else {
            // Only reachable in dev mode (gate checked in generate/rotate).
            tracing::warn!(key = %key_id, version, "Dev mode: storing key as plaintext");
            return Ok(SecretKeyMaterial::Plaintext(hex::encode(sk_bytes)));
        };

        // Per-key wrapping key: HKDF(master_key, info="citadel-kek-v1:{key_id}:{version}")
        let hk = Hkdf::<Sha256>::new(None, mk.as_ref());
        let mut info = Vec::with_capacity(32);
        info.extend_from_slice(b"citadel-kek-v1:");
        info.extend_from_slice(key_id.as_str().as_bytes());
        info.push(b':');
        info.extend_from_slice(&version.to_be_bytes());

        let mut aes_key = Zeroizing::new([0u8; 32]);
        hk.expand(&info, aes_key.as_mut())
            .map_err(|e| format!("HKDF expand: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new((&*aes_key).into());
        let nonce = Nonce::from(nonce_bytes);
        let ct = cipher
            .encrypt(&nonce, sk_bytes)
            .map_err(|_| "AES-256-GCM encrypt failed")?;

        Ok(SecretKeyMaterial::Encrypted(format!(
            "enc:{}{}",
            hex::encode(nonce_bytes),
            hex::encode(ct)
        )))
    }

    /// Wrap a child key using the parent's Citadel public key (V2 KEK hierarchy).
    ///
    /// The child's secret key bytes are sealed inside a Citadel envelope addressed
    /// to the parent KEK. The AAD and context bind the ciphertext to this specific
    /// (child_key_id, child_version, parent_key_id) triple — re-using the wrapped
    /// material under a different key ID fails decryption.
    fn wrap_with_citadel_key(
        &self,
        child_key_id: &KeyId,
        child_version: u32,
        parent_id: &KeyId,
        parent_version: u32,
        parent_pk_hex: &str,
        sk_bytes: &[u8],
    ) -> Result<SecretKeyMaterial, String> {
        let pk_bytes = hex::decode(parent_pk_hex)
            .map_err(|e| format!("decode parent public key hex: {}", e))?;
        let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| "parse parent public key failed")?;

        let aad = Aad::raw(HIERARCHY_WRAP_AAD);
        // Context binds to child key ID + version + parent key ID.
        // Format: "kek-wrap-v2:{child_id}:{child_version}" / "{parent_id}"
        let ctx = Context::for_secrets(
            &format!("kek-wrap-v2:{}:{}", child_key_id.as_str(), child_version),
            parent_id.as_str(),
        );

        let ciphertext = self
            .envelope
            .seal(&pk, sk_bytes, &aad, &ctx)
            .map_err(|e| format!("Citadel seal for hierarchy wrap: {}", e))?;

        tracing::debug!(
            child = %child_key_id, child_ver = child_version,
            parent = %parent_id, parent_ver = parent_version,
            "wrapped child key with parent KEK Citadel public key"
        );

        Ok(SecretKeyMaterial::CitadelWrapped(format!(
            "ckw:{}",
            hex::encode(&ciphertext)
        )))
    }

    /// Decide wrapping strategy for a new key and return the wrapped material.
    ///
    /// **Cryptographic wrapping chain (P212):**
    ///
    /// - `Domain → KEK`: parent is `KeyEncrypting` or `Domain` → use parent's Citadel
    ///   public key (hybrid X25519 + ML-KEM-768 envelope, `CitadelWrapped`).
    /// - `Root` and `Domain` themselves → wrapped by `CITADEL_MASTER_KEY` (AES-256-GCM,
    ///   `ExternalMaster`). Root is a **logical authority** (offline), not a runtime unwrap key.
    ///
    /// This means the online cryptographic chain is `Domain → KEK → DEK`.
    /// Root provides structural/access-control hierarchy but is not present at decrypt time.
    /// See `hierarchy.rs::allow_external_master()` which explicitly allows both Root and DomainKek
    /// to be wrapped by ExternalMaster — this is the documented design.
    async fn wrap_secret_key_for(
        &self,
        key_id: &KeyId,
        version: u32,
        parent_id: Option<&KeyId>,
        sk_bytes: &[u8],
    ) -> Result<(SecretKeyMaterial, Option<String>, Option<u32>), String> {
        if let Some(pid) = parent_id {
            // Load parent metadata to determine its type and current public key.
            let parent_meta = self
                .storage
                .get(pid)
                .map_err(|e| format!("load parent {}: {}", pid, e))?
                .ok_or_else(|| format!("parent key {} not found", pid))?;

            match parent_meta.key_type {
                KeyType::KeyEncrypting | KeyType::Domain => {
                    let parent_version = parent_meta
                        .current_key_version()
                        .ok_or_else(|| format!("parent {} has no current version", pid))?;
                    let parent_ver_num = parent_version.version;
                    let pk_hex = parent_version.public_key_hex.clone();

                    let material = self.wrap_with_citadel_key(
                        key_id,
                        version,
                        pid,
                        parent_ver_num,
                        &pk_hex,
                        sk_bytes,
                    )?;

                    return Ok((
                        material,
                        Some(pid.as_str().to_string()),
                        Some(parent_ver_num),
                    ));
                }
                // Root keys and DataEncrypting parents: fall through to master-key wrapping.
                _ => {}
            }
        }

        // No parent or parent is Root/DataEncrypting — use CITADEL_MASTER_KEY.
        let material = self.wrap_with_master_key(key_id, version, sk_bytes)?;
        Ok((material, None, None))
    }

    /// Unwrap a key version's secret material, recursively if needed.
    ///
    /// # Recursion
    ///
    /// If `kv.secret_key_material` is `CitadelWrapped`, loads the wrapping
    /// parent key from storage and recursively unwraps it (up to `MAX_UNWRAP_DEPTH`).
    ///
    /// # Depth limit
    ///
    /// The four-level hierarchy (Root → Domain → KEK → DEK) requires at most 3
    /// levels of indirection. Depth 4 is a safety limit — exceeding it returns
    /// an error rather than looping indefinitely.
    #[allow(clippy::type_complexity)]
    fn unwrap_key_version<'life0, 'life1, 'life2>(
        &'life0 self,
        key_id: &'life1 KeyId,
        kv: &'life2 KeyVersion,
        depth: u8,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>, String>> + Send + 'life0>,
    >
    where
        'life1: 'life0,
        'life2: 'life0,
    {
        self.unwrap_key_version_inner(key_id, kv, depth, false)
    }

    /// Like `unwrap_key_version` but skips the parent-state cascade check.
    ///
    /// Used exclusively by `rewrap()` — when we are extracting the raw secret key
    /// bytes so we can re-wrap them under a new parent, we must be able to read
    /// through a revoked parent. The new wrapping will be under a healthy parent.
    #[allow(clippy::type_complexity)]
    fn unwrap_key_version_for_rewrap<'life0, 'life1, 'life2>(
        &'life0 self,
        key_id: &'life1 KeyId,
        kv: &'life2 KeyVersion,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>, String>> + Send + 'life0>,
    >
    where
        'life1: 'life0,
        'life2: 'life0,
    {
        self.unwrap_key_version_inner(key_id, kv, 0, true)
    }

    #[allow(clippy::type_complexity)]
    fn unwrap_key_version_inner<'life0, 'life1, 'life2>(
        &'life0 self,
        key_id: &'life1 KeyId,
        kv: &'life2 KeyVersion,
        depth: u8,
        skip_parent_state_check: bool,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<Zeroizing<Vec<u8>>, String>> + Send + 'life0>,
    >
    where
        'life1: 'life0,
        'life2: 'life0,
    {
        Box::pin(async move {
            if depth > MAX_UNWRAP_DEPTH {
                return Err(format!(
                    "key {} hierarchy too deep (>{} levels); possible circular wrapping",
                    key_id, MAX_UNWRAP_DEPTH
                ));
            }

            match &kv.secret_key_material {
                SecretKeyMaterial::Destroyed => {
                    Err("key material has been destroyed and cannot be recovered".into())
                }

                SecretKeyMaterial::Plaintext(hex_str) => {
                    if self.master_key.is_some() {
                        tracing::warn!(
                            key = %key_id,
                            version = kv.version,
                            "plaintext key in use; rotate to re-encrypt under CITADEL_MASTER_KEY"
                        );
                    }
                    hex::decode(hex_str)
                        .map(Zeroizing::new)
                        .map_err(|e| format!("plaintext hex decode: {}", e))
                }

                SecretKeyMaterial::Encrypted(enc) => {
                    // AES-256-GCM path (CITADEL_MASTER_KEY)
                    let mk = self.master_key.as_ref().ok_or_else(|| {
                        "key is AES-wrapped but CITADEL_MASTER_KEY is not set".to_string()
                    })?;

                    let payload = enc
                        .strip_prefix("enc:")
                        .ok_or("malformed Encrypted material: missing 'enc:' prefix")?;
                    if payload.len() < 24 {
                        return Err("encrypted key blob too short".into());
                    }

                    let nonce_bytes =
                        hex::decode(&payload[..24]).map_err(|e| format!("nonce hex: {}", e))?;
                    let ciphertext =
                        hex::decode(&payload[24..]).map_err(|e| format!("ct hex: {}", e))?;

                    let hk = Hkdf::<Sha256>::new(None, mk.as_ref());
                    let mut info = Vec::with_capacity(32);
                    info.extend_from_slice(b"citadel-kek-v1:");
                    info.extend_from_slice(key_id.as_str().as_bytes());
                    info.push(b':');
                    info.extend_from_slice(&kv.version.to_be_bytes());

                    let mut aes_key = Zeroizing::new([0u8; 32]);
                    hk.expand(&info, aes_key.as_mut())
                        .map_err(|e| format!("HKDF expand: {}", e))?;

                    let cipher = Aes256Gcm::new((&*aes_key).into());
                    let nonce = Nonce::try_from(nonce_bytes.as_slice())
                        .map_err(|_| "nonce must be 12 bytes".to_string())?;
                    cipher
                        .decrypt(&nonce, ciphertext.as_ref())
                        .map(Zeroizing::new)
                        .map_err(|_| {
                            "AES-256-GCM decryption failed — wrong master key or corruption"
                                .to_string()
                        })
                }

                SecretKeyMaterial::CitadelWrapped(ckw) => {
                    // V2 KEK hierarchy path.
                    let parent_key_id_str = kv.wrapping_key_id.as_deref().ok_or_else(|| {
                        format!(
                            "key {} v{} is CitadelWrapped but wrapping_key_id is missing",
                            key_id, kv.version
                        )
                    })?;
                    let parent_key_id = KeyId::new(parent_key_id_str);

                    // Load parent key metadata.
                    let parent_meta = self
                        .storage
                        .get(&parent_key_id)
                        .map_err(|e| format!("load parent {}: {}", parent_key_id_str, e))?
                        .ok_or_else(|| {
                            // P069: descriptive error — parent is gone, use rewrap() to recover.
                            format!(
                                "parent key '{}' not found (needed to unwrap '{}' v{}) — \
                             hierarchy broken; use rewrap() to re-wrap under a present parent",
                                parent_key_id_str, key_id, kv.version
                            )
                        })?;

                    // P061 — KEK revocation cascade: check parent state before unwrapping.
                    // Skipped during rewrap (skip_parent_state_check=true) because rewrap is
                    // an administrative operation that must reach through a revoked parent to
                    // extract the SK bytes and place them under a healthy new parent.
                    if !skip_parent_state_check
                        && !matches!(parent_meta.state, KeyState::Active | KeyState::Rotated)
                    {
                        let reason = format!(
                            "parent key {} is in state {} — hierarchy access denied for {} v{}",
                            parent_key_id_str, parent_meta.state, key_id, kv.version
                        );
                        // In unwrap_key_version(), we don't have full KeyMetadata — use
                        // the parent's type as a proxy for logging. The child id is in key_id.
                        self.audit.record(AuditEvent::key_event(
                            key_id,
                            parent_meta.key_type, // parent's type (closest available)
                            parent_meta.state,
                            crate::audit::AuditAction::HierarchyViolation {
                                parent_id: parent_key_id_str.to_string(),
                                parent_state: format!("{}", parent_meta.state),
                                child_id: key_id.as_str().to_string(),
                            },
                        ));
                        return Err(reason);
                    }

                    // Find the specific parent version that was used to wrap.
                    // `wrapping_key_version` records this at wrap time.
                    let parent_ver_num = kv.wrapping_key_version.ok_or_else(|| {
                        format!(
                            "key {} v{} is CitadelWrapped but wrapping_key_version is missing",
                            key_id, kv.version
                        )
                    })?;

                    let parent_kv = parent_meta
                        .get_version(parent_ver_num)
                        .ok_or_else(|| {
                            format!(
                                "parent key {} v{} not found (needed to unwrap {} v{})",
                                parent_key_id_str, parent_ver_num, key_id, kv.version
                            )
                        })?
                        .clone(); // Clone to avoid borrow across await point.

                    // Recursively unwrap the parent's secret key (same skip flag).
                    let parent_sk_bytes = self
                        .unwrap_key_version_inner(
                            &parent_key_id,
                            &parent_kv,
                            depth + 1,
                            skip_parent_state_check,
                        )
                        .await?;

                    // Parse parent secret key.
                    let parent_sk = SecretKey::from_bytes(&parent_sk_bytes).map_err(|_| {
                        format!("parse parent {} secret key failed", parent_key_id_str)
                    })?;

                    // Decode the Citadel ciphertext.
                    let payload = ckw
                        .strip_prefix("ckw:")
                        .ok_or("malformed CitadelWrapped material: missing 'ckw:' prefix")?;
                    let ciphertext = hex::decode(payload)
                        .map_err(|e| format!("decode CitadelWrapped: {}", e))?;

                    // Reconstruct domain-separated AAD/context (must exactly match wrap time).
                    let aad = Aad::raw(HIERARCHY_WRAP_AAD);
                    let ctx = Context::for_secrets(
                        &format!("kek-wrap-v2:{}:{}", key_id.as_str(), kv.version),
                        parent_key_id_str,
                    );

                    self.envelope
                    .open(&parent_sk, &ciphertext, &aad, &ctx)
                    .map(Zeroizing::new)
                    .map_err(|_| {
                        format!(
                            "CitadelWrapped decryption failed for key {} v{} (wrong parent key or corruption)",
                            key_id, kv.version
                        )
                    })
                }
            }
        }) // close Box::pin(async move { in unwrap_key_version_inner
    }

    // -----------------------------------------------------------------------
    // Nonce field extraction helper
    // -----------------------------------------------------------------------

    fn extract_wrap_nonce(material: &SecretKeyMaterial) -> Option<String> {
        match material {
            SecretKeyMaterial::Encrypted(enc) if enc.len() > 28 => Some(enc[4..28].to_string()),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Policy management
    // -----------------------------------------------------------------------

    pub fn register_policy(&mut self, policy: KeyPolicy) {
        self.audit
            .record(AuditEvent::system_event(AuditAction::PolicyRegistered {
                policy_id: policy.id.as_str().to_string(),
            }));
        self.policies.insert(policy.id.as_str().to_string(), policy);
    }

    pub fn get_policy(&self, id: &PolicyId) -> Option<&KeyPolicy> {
        self.policies.get(id.as_str())
    }

    // -----------------------------------------------------------------------
    // P063 + P066: Plaintext mode audit and production preflight
    // -----------------------------------------------------------------------

    /// Emit an audit event (and log) when plaintext key storage is active (P063).
    /// Called from `new()` and `with_master_key()` automatically.
    fn audit_plaintext_mode_if_active(&self) {
        let plaintext_active = std::env::var("CITADEL_ALLOW_PLAINTEXT_KEYS").as_deref() == Ok("1");
        if !plaintext_active {
            return;
        }
        let is_dev = std::env::var("CITADEL_ENV").as_deref() == Ok("development");
        let environment = if is_dev {
            "development"
        } else {
            "PRODUCTION (UNSAFE)"
        };
        // Record in audit trail regardless of environment.
        self.audit.record(AuditEvent::system_event(
            AuditAction::PlaintextModeActivated {
                environment: environment.to_string(),
            },
        ));
        if is_dev {
            tracing::warn!(
                environment,
                "plaintext key storage is active — acceptable for development only"
            );
        } else {
            tracing::error!(
                environment,
                "CRITICAL: plaintext key storage is active outside development mode.                  Set CITADEL_ENV=development or set CITADEL_MASTER_KEY to enable encryption."
            );
        }
    }

    // Production-safe startup is handled by `create_keystore()` in `citadel-api`.
    //
    // P152: `try_new_production()` is removed -- it duplicated the env-var checks
    // that `create_keystore()` already performs with better diagnostic messages.
    // Having two parallel production-safety systems created drift risk.
    //
    // The authoritative production gate is `citadel-api/src/main.rs::create_keystore()`,
    // which checks CITADEL_MASTER_KEY, CITADEL_ENV, and CITADEL_REPLAY_STORE in order,
    // with specific [FATAL] messages and remediation instructions for each failure.
    //
    // `Keystore::new()` remains the standard constructor for both production
    // (via create_keystore) and tests.
    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    pub async fn generate(
        &self,
        name: impl Into<String>,
        key_type: KeyType,
        policy_id: Option<PolicyId>,
        parent_id: Option<KeyId>,
    ) -> Result<KeyId, GenerateError> {
        // P364 — ML-DSA-65 signing keys must use generate_signing_key() not generate().
        // generate() calls self.envelope.generate_keypair() which produces X25519+ML-KEM-768
        // (KEM) material. Signing keys need ML-DSA-65 material — completely different bytes.
        // If generate() were allowed to create a Signing key it would silently store wrong material.
        if matches!(key_type, KeyType::Signing) {
            return Err(GenerateError(KeystoreError::HierarchyViolation(
                "KeyType::Signing keys must be created with generate_signing_key(), not generate(). \
                 generate() creates KEM keys; signing keys require ML-DSA-65 keypairs.".into()
            )));
        }

        // Fail-closed master key check (same as V1).
        if self.master_key.is_none() {
            let dev_mode = std::env::var("CITADEL_ALLOW_PLAINTEXT_KEYS").as_deref() == Ok("1")
                && std::env::var("CITADEL_ENV").as_deref() == Ok("development");
            if !dev_mode {
                return Err(GenerateError(KeystoreError::StorageError(
                    "CITADEL_MASTER_KEY is not set. Set CITADEL_MASTER_KEY or \
                     set CITADEL_ALLOW_PLAINTEXT_KEYS=1 and CITADEL_ENV=development."
                        .into(),
                )));
            }
        }

        // P211 — Strict hierarchy enforcement using KeyRole::can_wrap().
        //
        // Replaces P063/P184 partial enforcement (DataEncrypting + HybridIdentity only).
        // Now covers ALL key types at generation time:
        //
        //   Root           — must have NO parent
        //   Domain (DomainKek) — parent must be Root
        //   KeyEncrypting (Kek)  — parent must be Domain
        //   DataEncrypting (Dek) — parent must be KeyEncrypting
        //   HybridIdentity      — parent must be KeyEncrypting
        //
        // can_wrap() in hierarchy.rs encodes these rules exactly. This block
        // is the single enforcement point — any call to generate() with a
        // parent/child pair that violates the hierarchy is rejected here, not
        // silently stored and discovered later by the doctor or audit.
        //
        // Escape hatch: CITADEL_ALLOW_FLAT_DEKS=1 AND CITADEL_ENV=development
        // are BOTH required to bypass parent-type checks (P214). Requiring both
        // matches the pattern established for other dev-only gates and prevents
        // accidental production weakening from a single env var.
        {
            use crate::hierarchy::KeyRole;
            let child_role = KeyRole::from(key_type);
            // P214: require BOTH flags — matches the CITADEL_ALLOW_PLAINTEXT_KEYS pattern.
            let flat_override = std::env::var("CITADEL_ALLOW_FLAT_DEKS").as_deref() == Ok("1")
                && std::env::var("CITADEL_ENV").as_deref() == Ok("development");

            match &parent_id {
                None => {
                    // Without a parent only Root is valid.
                    if !matches!(key_type, KeyType::Root) && !flat_override {
                        return Err(GenerateError(KeystoreError::HierarchyViolation(format!(
                            "{:?} keys require a parent. \
                             Valid hierarchy: Root → Domain → KeyEncrypting → DataEncrypting. \
                             Set CITADEL_ALLOW_FLAT_DEKS=1 with CITADEL_ENV=development to override \
                             for testing only.",
                            key_type
                        ))));
                    }
                    if !matches!(key_type, KeyType::Root) {
                        tracing::warn!(
                            key_type = ?key_type,
                            "P211/P214 override: creating non-Root key with no parent. \
                             CITADEL_ALLOW_FLAT_DEKS=1 + CITADEL_ENV=development are set. \
                             Not for production use."
                        );
                    }
                }
                Some(pid) => {
                    // With a parent: parent_role.can_wrap(child_role) must be true.
                    let parent_meta = self
                        .storage
                        .get(pid)
                        .map_err(|e| {
                            GenerateError(KeystoreError::StorageError(format!(
                                "load parent for hierarchy check {}: {}",
                                pid, e
                            )))
                        })?
                        .ok_or_else(|| {
                            GenerateError(KeystoreError::HierarchyViolation(format!(
                                "parent key {} not found",
                                pid
                            )))
                        })?;
                    let parent_role = KeyRole::from(parent_meta.key_type);
                    if !parent_role.can_wrap(child_role) && !flat_override {
                        return Err(GenerateError(KeystoreError::HierarchyViolation(format!(
                            "{:?} ({:?}) cannot be a child of {:?} ({:?}). \
                             Valid hierarchy: Root → Domain → KeyEncrypting → DataEncrypting/HybridIdentity. \
                             Set CITADEL_ALLOW_FLAT_DEKS=1 with CITADEL_ENV=development to override \
                             for testing only.",
                            key_type, child_role, parent_meta.key_type, parent_role
                        ))));
                    }
                    if !parent_role.can_wrap(child_role) {
                        tracing::warn!(
                            key_type = ?key_type,
                            parent_type = ?parent_meta.key_type,
                            "P211/P214 override: invalid hierarchy relationship allowed by \
                             CITADEL_ALLOW_FLAT_DEKS=1 + CITADEL_ENV=development. \
                             Not for production use."
                        );
                    }
                }
            }
        }

        let id = KeyId::generate();
        let now = Utc::now();

        let (pk, sk) = self.envelope.generate_keypair();
        let sk_bytes = sk.to_bytes();

        // V2: decide wrapping strategy based on parent key type.
        let (material, wrapping_key_id, wrapping_key_version) = self
            .wrap_secret_key_for(&id, 1, parent_id.as_ref(), &sk_bytes)
            .await
            .map_err(|e| GenerateError(KeystoreError::StorageError(e)))?;

        let wrap_nonce_hex = Self::extract_wrap_nonce(&material);

        let version = KeyVersion {
            version: 1,
            created_at: now,
            public_key_hex: hex::encode(pk.to_bytes()),
            secret_key_material: material,
            wrapping_key_id,
            wrapping_key_version,
            wrap_nonce_hex,
            wrapping_mode: None,
        };

        let meta = KeyMetadata {
            id: id.clone(),
            name: name.into(),
            key_type,
            state: KeyState::Pending,
            policy_id,
            parent_id,
            created_at: now,
            updated_at: now,
            activated_at: None,
            rotated_at: None,
            revoked_at: None,
            destroyed_at: None,
            versions: vec![version],
            current_version: 1,
            usage_count: 0,
            tags: HashMap::new(),
        };

        self.storage.put(&meta).map_err(GenerateError)?;
        self.audit.record(AuditEvent::key_event(
            &id,
            key_type,
            KeyState::Pending,
            AuditAction::KeyGenerated,
        ));

        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Key retrieval
    // -----------------------------------------------------------------------

    pub async fn get(&self, id: &KeyId) -> Result<KeyMetadata, KeystoreError> {
        self.storage
            .get(id)?
            .ok_or_else(|| KeystoreError::KeyNotFound(id.clone()))
    }

    pub async fn list_keys(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        self.storage.list()
    }

    pub async fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError> {
        self.storage.list_by_state(state)
    }

    /// P220: Resolve the Domain ancestor for any key.
    ///
    /// Walks the parent chain (DEK → KEK → Domain) to find the Domain key ID.
    /// - For Domain keys: returns self
    /// - For KEK/DEK/HybridIdentity: walks parent chain to find Domain
    /// - For Root: returns error (Root has no Domain ancestor)
    /// - For orphaned keys: returns error
    ///
    /// P282: Rewritten as an iterative loop. The original recursive `async fn`
    /// produced an infinitely-sized Future (E0733). Iterative form is cleaner,
    /// avoids Box::pin indirection, and adds a depth guard (max 10 hops) to
    /// fail-closed on corrupted or cyclical parent chains.
    pub async fn resolve_domain_for_key(&self, key_id: &KeyId) -> Result<KeyId, KeystoreError> {
        const MAX_DEPTH: usize = 10;
        let mut current = key_id.clone();

        for depth in 0..MAX_DEPTH {
            let meta = self.get(&current).await?;

            match meta.key_type {
                KeyType::Domain => return Ok(meta.id.clone()),

                KeyType::Root => {
                    return Err(KeystoreError::HierarchyViolation(
                        "Root key has no Domain ancestor".to_string(),
                    ));
                }

                // KEK, DEK, HybridIdentity — walk up to parent
                _ => {
                    let parent_id = meta.parent_id.ok_or_else(|| {
                        KeystoreError::HierarchyViolation(format!(
                            "Key {} is orphaned (no parent) and not a Domain (depth {})",
                            current, depth
                        ))
                    })?;
                    current = parent_id;
                }
            }
        }

        Err(KeystoreError::HierarchyViolation(format!(
            "resolve_domain_for_key exceeded max depth ({}) starting from {} — possible cycle in parent chain",
            MAX_DEPTH, key_id
        )))
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    pub async fn activate(&self, id: &KeyId) -> Result<(), LifecycleError> {
        let mut meta = self.get(id).await.map_err(LifecycleError)?;
        self.transition(&mut meta, KeyState::Active)?;
        meta.activated_at = Some(Utc::now());
        self.storage.put(&meta).map_err(LifecycleError)?;
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyActivated,
        ));
        Ok(())
    }

    pub async fn rotate(&self, id: &KeyId) -> Result<KeyId, RotateError> {
        let mut meta = self.get(id).await.map_err(RotateError)?;

        if meta.state != KeyState::Active {
            return Err(RotateError(KeystoreError::NotActive(id.clone())));
        }

        // Fail-closed master key check.
        if self.master_key.is_none() {
            let dev_mode = std::env::var("CITADEL_ALLOW_PLAINTEXT_KEYS").as_deref() == Ok("1")
                && std::env::var("CITADEL_ENV").as_deref() == Ok("development");
            if !dev_mode {
                return Err(RotateError(KeystoreError::StorageError(
                    "CITADEL_MASTER_KEY is not set. Set CITADEL_MASTER_KEY or \
                     set CITADEL_ALLOW_PLAINTEXT_KEYS=1 and CITADEL_ENV=development."
                        .into(),
                )));
            }
        }

        let (pk, sk) = self.envelope.generate_keypair();
        let new_sk_bytes = sk.to_bytes();
        let new_version_num = meta.current_version + 1;
        let now = Utc::now();

        // V2: re-use the same parent for rotation (hierarchy is preserved).
        let (new_material, wrapping_key_id, wrapping_key_version) = self
            .wrap_secret_key_for(id, new_version_num, meta.parent_id.as_ref(), &new_sk_bytes)
            .await
            .map_err(|e| RotateError(KeystoreError::StorageError(e)))?;

        let wrap_nonce_hex = Self::extract_wrap_nonce(&new_material);

        let new_version = KeyVersion {
            version: new_version_num,
            created_at: now,
            public_key_hex: hex::encode(pk.to_bytes()),
            secret_key_material: new_material,
            wrapping_key_id,
            wrapping_key_version,
            wrap_nonce_hex,
            wrapping_mode: None,
        };

        // P065 — Atomic rotation: build the final Active state in memory first,
        // then write once. A crash between two puts would leave the key stuck in
        // Rotated state (cannot encrypt). Single put eliminates that window.
        meta.versions.push(new_version);
        meta.current_version = new_version_num;
        meta.state = KeyState::Active; // stays Active — new version is live
        meta.activated_at = Some(now);
        meta.rotated_at = Some(now); // records when the rotation occurred
        meta.updated_at = now;
        self.storage.put(&meta).map_err(RotateError)?; // ← single atomic write

        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyRotated {
                new_version: new_version_num,
            },
        ));

        Ok(id.clone())
    }

    // ── P062: Rewrap ──────────────────────────────────────────────────────────

    /// Re-wrap a key's secret material under a different parent KEK.
    ///
    /// This is the correct operational response to KEK rotation: existing DEKs
    /// wrapped under the old KEK version are re-encrypted under the new KEK version,
    /// so the old version is no longer required for decryption.
    ///
    /// **Important:** Existing ciphertexts encrypted WITH this DEK are unaffected —
    /// rewrap changes only how the DEK's own secret key is stored, not what it encrypts.
    ///
    /// # Errors
    /// - `RewrapError::KeyNotFound` — key or parent not found
    /// - `RewrapError::UnwrapFailed` — cannot unwrap current secret key
    /// - `RewrapError::WrapFailed` — cannot wrap under new parent
    ///
    /// P316: Capability-gated decrypt — requires AuthorizedContext from StateEnforcer.
    pub async fn decrypt_authorized(
        &self,
        authz: &citadel_core::AuthorizedContext,
        blob: &EncryptedBlob,
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, DecryptError> {
        // P378: Validate capability issuance at keystore boundary.
        self.validate_authz(authz).await.map_err(DecryptError)?;
        // Cross-check: the context must authorize THIS specific key for decrypt.
        authz
            .require_decrypt_for(&blob.key_id)
            .map_err(DecryptError)?;
        // P217: keystore-side cross-domain rejection (defense in depth).
        self.enforce_authorized_domain(authz.domain(), &KeyId::new(&blob.key_id))
            .await
            .map_err(DecryptError)?;
        self.decrypt(blob, aad, context).await
    }

    pub async fn rewrap(
        &self,
        id: &KeyId,
        new_parent_id: Option<&KeyId>,
    ) -> Result<(), RewrapError> {
        let mut meta = self
            .get(id)
            .await
            .map_err(|_| RewrapError(KeystoreError::KeyNotFound(id.clone())))?;

        // Get the current version's secret key bytes by walking the unwrap chain.
        let kv = meta
            .current_key_version()
            .ok_or_else(|| RewrapError(KeystoreError::KeyNotFound(id.clone())))?
            .clone();

        let old_parent_id = kv.wrapping_key_id.clone();
        // Use the rewrap-specific unwrap path that bypasses parent state checks.
        // We need the raw SK bytes even if the current parent is revoked —
        // the purpose of rewrap is to move the key under a healthy new parent.
        let sk_bytes = self
            .unwrap_key_version_for_rewrap(id, &kv)
            .await
            .map_err(|e| RewrapError(KeystoreError::StorageError(e)))?;

        // Determine new wrapping (either a parent KEK or the master key).
        // wrap_secret_key_for returns (SecretKeyMaterial, parent_key_id_str, parent_version).
        let (new_material, new_wk_id_str, new_wk_ver) = self
            .wrap_secret_key_for(id, kv.version, new_parent_id, &sk_bytes)
            .await
            .map_err(|e| RewrapError(KeystoreError::StorageError(e)))?;

        let new_wrap_nonce_hex = Self::extract_wrap_nonce(&new_material);

        // Update the current version's material in-place.
        let current_ver = meta.current_version;
        let ver_entry = meta
            .versions
            .iter_mut()
            .find(|v| v.version == current_ver)
            .ok_or_else(|| RewrapError(KeystoreError::KeyNotFound(id.clone())))?;

        ver_entry.secret_key_material = new_material;
        ver_entry.wrapping_key_id = new_wk_id_str;
        ver_entry.wrapping_key_version = new_wk_ver;
        ver_entry.wrap_nonce_hex = new_wrap_nonce_hex;
        ver_entry.wrapping_mode = None; // Reset to force re-derivation from legacy fields.

        meta.updated_at = chrono::Utc::now();
        self.storage.put(&meta).map_err(RewrapError)?;

        // Audit the rewrap event.
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyRewrapped {
                old_parent_id: old_parent_id.clone(),
                new_parent_id: new_parent_id.map(|k| k.as_str().to_string()),
                new_parent_version: new_wk_ver,
            },
        ));

        tracing::info!(
            key_id = %id.as_str(),
            old_parent = ?old_parent_id,
            new_parent = ?new_parent_id.map(|k| k.as_str()),
            "key rewrapped under new parent"
        );

        Ok(())
    }

    pub async fn revoke(
        &self,
        id: &KeyId,
        reason: impl Into<String>,
    ) -> Result<(), LifecycleError> {
        let mut meta = self.get(id).await.map_err(LifecycleError)?;
        let reason = reason.into();

        if meta.state != KeyState::Active {
            return Err(LifecycleError(KeystoreError::InvalidTransition {
                id: id.clone(),
                from: meta.state,
                to: KeyState::Revoked,
            }));
        }

        meta.state = KeyState::Revoked;
        meta.revoked_at = Some(Utc::now());
        meta.updated_at = Utc::now();
        self.storage.put(&meta).map_err(LifecycleError)?;
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyRevoked { reason },
        ));
        Ok(())
    }

    /// Revoke a key and cascade `Suspended` state to all descendants.
    ///
    /// P064 — When a KEK is revoked, its children (and their children) are
    /// immediately marked `Suspended`. Suspended keys cannot encrypt or decrypt;
    /// they are operationally blocked until rewrapped under a healthy parent.
    ///
    /// **Why `Suspended` and not `Revoked`?** The children are not individually
    /// compromised — their parent is. `Suspended` is reversible via `rewrap()`:
    /// once the DEK is re-wrapped under a healthy KEK, it can be re-activated.
    ///
    /// Cascade is depth-first and covers all generations of descendants.
    /// If any individual suspend fails, the error is collected but the cascade
    /// continues so that as many children as possible are protected.
    ///
    /// Returns `(revoked_count, suspended_count, Vec<(KeyId, error)>)`.
    pub async fn revoke_cascade(
        &self,
        id: &KeyId,
        reason: impl Into<String>,
    ) -> Result<(usize, usize, Vec<(KeyId, String)>), CascadeError> {
        // Revoke the target key first.
        let reason = reason.into();
        self.revoke(id, reason.clone())
            .await
            .map_err(|e| CascadeError(e.0))?;

        // Walk descendants breadth-first and suspend each.
        let mut suspended = 0usize;
        let mut errors: Vec<(KeyId, String)> = Vec::new();
        let mut queue: Vec<KeyId> = vec![id.clone()];

        while let Some(parent_id) = queue.pop() {
            let children = self
                .storage
                .list_by_parent(&parent_id)
                .map_err(CascadeError)?;

            for mut child in children {
                // Skip already-terminal states.
                if matches!(
                    child.state,
                    KeyState::Destroyed | KeyState::Revoked | KeyState::Suspended
                ) {
                    continue;
                }
                // Attempt Active/Rotated → Suspended transition.
                if !child.state.can_transition_to(KeyState::Suspended) {
                    errors.push((
                        child.id.clone(),
                        format!("cannot suspend {} key (state: {})", child.name, child.state),
                    ));
                    continue;
                }
                child.state = KeyState::Suspended;
                child.updated_at = Utc::now();
                match self.storage.put(&child) {
                    Ok(_) => {
                        self.audit.record(AuditEvent::key_event(
                            &child.id,
                            child.key_type,
                            child.state,
                            AuditAction::HierarchyViolation {
                                parent_id: parent_id.as_str().to_string(),
                                parent_state: "Revoked".into(),
                                child_id: child.id.as_str().to_string(),
                            },
                        ));
                        suspended += 1;
                        queue.push(child.id.clone()); // cascade to grandchildren
                    }
                    Err(e) => {
                        errors.push((child.id.clone(), e.to_string()));
                    }
                }
            }
        }

        Ok((1, suspended, errors))
    }

    pub async fn expire(&self, id: &KeyId) -> Result<ExpirationSource, ExpireError> {
        let mut meta = self.get(id).await.map_err(ExpireError)?;
        let decision = self.check_expiration(&meta);

        match decision {
            ExpirationDecision::Required { reason, source } => {
                meta.state = KeyState::Expired;
                meta.updated_at = Utc::now();
                self.storage.put(&meta).map_err(ExpireError)?;
                self.audit.record(AuditEvent::key_event(
                    id,
                    meta.key_type,
                    meta.state,
                    AuditAction::KeyExpired { reason },
                ));
                Ok(source)
            }
            _ => Err(ExpireError(KeystoreError::InvalidTransition {
                id: id.clone(),
                from: meta.state,
                to: KeyState::Expired,
            })),
        }
    }

    pub async fn destroy(&self, id: &KeyId) -> Result<(), LifecycleError> {
        let mut meta = self.get(id).await.map_err(LifecycleError)?;

        if !meta.state.can_transition_to(KeyState::Destroyed) {
            return Err(LifecycleError(KeystoreError::InvalidTransition {
                id: id.clone(),
                from: meta.state,
                to: KeyState::Destroyed,
            }));
        }

        for version in &mut meta.versions {
            version.secret_key_material.zeroize_and_destroy();
            version.public_key_hex.zeroize();
            version.public_key_hex = String::from("DESTROYED");
        }

        meta.state = KeyState::Destroyed;
        meta.destroyed_at = Some(Utc::now());
        meta.updated_at = Utc::now();
        self.storage
            .overwrite_key_file(id)
            .map_err(LifecycleError)?;
        self.storage.put(&meta).map_err(LifecycleError)?;
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyDestroyed,
        ));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expiration checks
    // -----------------------------------------------------------------------

    pub async fn should_expire(&self, id: &KeyId) -> Result<ExpirationDecision, KeystoreError> {
        let meta = self.get(id).await?;
        Ok(self.check_expiration(&meta))
    }

    fn check_expiration(&self, meta: &KeyMetadata) -> ExpirationDecision {
        match meta.state {
            KeyState::Rotated => {
                if let Some(rotated_at) = meta.rotated_at {
                    let grace = self.grace_period_for(meta);
                    let elapsed = Utc::now() - rotated_at;
                    let grace_chrono =
                        chrono::Duration::from_std(grace).unwrap_or(chrono::Duration::MAX);

                    if elapsed >= grace_chrono {
                        return ExpirationDecision::Required {
                            reason: format!(
                                "rotated {}s ago, grace period {}s",
                                elapsed.num_seconds(),
                                grace.as_secs()
                            ),
                            source: ExpirationSource::GracePeriodExpired,
                        };
                    }

                    let warn_secs = (grace.as_secs() as f64 * 0.9) as i64;
                    if elapsed.num_seconds() >= warn_secs {
                        let remaining = grace_chrono - elapsed;
                        return ExpirationDecision::Warning {
                            reason: "grace period expiring soon".to_string(),
                            remaining: remaining.to_std().unwrap_or(Duration::ZERO),
                            source: ExpirationSource::GracePeriodExpired,
                        };
                    }
                }
                ExpirationDecision::NotNeeded
            }

            KeyState::Active => {
                if let Some(max_lifetime) = self.max_lifetime_for(meta) {
                    if let Some(activated_at) = meta.activated_at {
                        let elapsed = Utc::now() - activated_at;
                        let max_chrono = chrono::Duration::from_std(max_lifetime)
                            .unwrap_or(chrono::Duration::MAX);

                        if elapsed >= max_chrono {
                            return ExpirationDecision::Required {
                                reason: format!(
                                    "active for {}s, max lifetime {}s",
                                    elapsed.num_seconds(),
                                    max_lifetime.as_secs()
                                ),
                                source: ExpirationSource::MaxLifetimeExceeded,
                            };
                        }

                        let warn_secs = (max_lifetime.as_secs() as f64 * 0.9) as i64;
                        if elapsed.num_seconds() >= warn_secs {
                            let remaining = max_chrono - elapsed;
                            return ExpirationDecision::Warning {
                                reason: "max lifetime expiring soon".to_string(),
                                remaining: remaining.to_std().unwrap_or(Duration::ZERO),
                                source: ExpirationSource::MaxLifetimeExceeded,
                            };
                        }
                    }
                }
                ExpirationDecision::NotNeeded
            }

            _ => ExpirationDecision::NotNeeded,
        }
    }

    pub async fn expire_due_keys(&self) -> Result<ExpirationReport, KeystoreError> {
        let mut report = ExpirationReport::default();

        let rotated = self.storage.list_by_state(KeyState::Rotated)?;
        for meta in &rotated {
            match self.check_expiration(meta) {
                ExpirationDecision::Required { .. } => match self.expire(&meta.id).await {
                    Ok(src) => report.expired.push((meta.id.clone(), src)),
                    Err(e) => report.failed.push((meta.id.clone(), e.to_string())),
                },
                ExpirationDecision::Warning {
                    reason, remaining, ..
                } => {
                    report.warnings.push((meta.id.clone(), reason, remaining));
                }
                ExpirationDecision::NotNeeded => {
                    report.skipped += 1;
                }
            }
        }

        let active = self.storage.list_by_state(KeyState::Active)?;
        for meta in &active {
            match self.check_expiration(meta) {
                ExpirationDecision::Required { .. } => match self.expire(&meta.id).await {
                    Ok(src) => report.expired.push((meta.id.clone(), src)),
                    Err(e) => report.failed.push((meta.id.clone(), e.to_string())),
                },
                ExpirationDecision::Warning {
                    reason, remaining, ..
                } => {
                    report.warnings.push((meta.id.clone(), reason, remaining));
                }
                ExpirationDecision::NotNeeded => {
                    report.skipped += 1;
                }
            }
        }

        self.audit
            .record(AuditEvent::system_event(AuditAction::ExpirationCheckRun {
                expired_count: report.expired.len(),
                warning_count: report.warnings.len(),
            }));

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Policy evaluation
    // -----------------------------------------------------------------------

    pub async fn evaluate_policy(
        &self,
        id: &KeyId,
    ) -> Result<policy::PolicyVerdict, KeystoreError> {
        let meta = self.get(id).await?;
        let policy = match &meta.policy_id {
            Some(pid) => self
                .policies
                .get(pid.as_str())
                .ok_or_else(|| KeystoreError::PolicyNotFound(pid.as_str().to_string()))?,
            None => return Ok(policy::PolicyVerdict::Compliant),
        };

        let verdict = policy::evaluate(policy, &meta);
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::PolicyEvaluated {
                verdict: format!("{:?}", verdict),
            },
        ));
        Ok(verdict)
    }

    pub async fn check_rotation_due(&self) -> Result<Vec<(KeyId, String)>, KeystoreError> {
        let active = self.storage.list_by_state(KeyState::Active)?;
        let mut due = Vec::new();

        for meta in active {
            if let Some(pid) = &meta.policy_id {
                if let Some(policy) = self.policies.get(pid.as_str()) {
                    let verdict = policy::evaluate(policy, &meta);
                    if let policy::PolicyVerdict::RotationNeeded { reason } = verdict {
                        due.push((meta.id.clone(), reason));
                    }
                }
            }
        }
        Ok(due)
    }

    // -----------------------------------------------------------------------
    // Convenience encrypt/decrypt (uses envelope)
    // -----------------------------------------------------------------------

    pub(crate) async fn encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<EncryptedBlob, EncryptError> {
        let mut meta = self
            .get(key_id)
            .await
            .map_err(|e| EncryptError(e.to_string()))?;

        if !meta.state.can_encrypt() {
            return Err(EncryptError(format!(
                "key {} is {}, cannot encrypt",
                key_id, meta.state
            )));
        }

        if meta.key_type != KeyType::DataEncrypting && meta.key_type != KeyType::HybridIdentity {
            return Err(EncryptError(format!(
                "key {} is type {}, only DataEncrypting keys can encrypt user data",
                key_id, meta.key_type
            )));
        }

        // Enforcement gate: evaluate threat-adapted policy.
        if let Some(adapted) = self.effective_policy_for(&meta) {
            let verdict = policy::evaluate(&adapted, &meta);
            match &verdict {
                policy::PolicyVerdict::RotationNeeded { reason } => {
                    self.audit.record(AuditEvent::key_event(
                        key_id,
                        meta.key_type,
                        meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!("BLOCKED: {}", reason),
                        },
                    ));
                    return Err(EncryptError(format!(
                        "policy violation: {}. Rotate key before encrypting.",
                        reason
                    )));
                }
                policy::PolicyVerdict::UsageLimitExceeded { count, limit } => {
                    self.audit.record(AuditEvent::key_event(
                        key_id,
                        meta.key_type,
                        meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!("BLOCKED: usage {}/{}", count, limit),
                        },
                    ));
                    return Err(EncryptError(format!(
                        "policy violation: usage {}/{} exceeded. Rotate key before encrypting.",
                        count, limit
                    )));
                }
                // P015: Handle cryptoperiod expiration (added by P005)
                policy::PolicyVerdict::Expired {
                    age_days,
                    limit_days,
                } => {
                    self.audit.record(AuditEvent::key_event(
                        key_id,
                        meta.key_type,
                        meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!(
                                "BLOCKED: expired age={}d limit={}d",
                                age_days, limit_days
                            ),
                        },
                    ));
                    return Err(EncryptError(format!(
                        "policy violation: key expired after {} days; limit is {} days. Rotate key before encrypting.",
                        age_days, limit_days
                    )));
                }
                policy::PolicyVerdict::Warning { reason } => {
                    self.audit.record(AuditEvent::key_event(
                        key_id,
                        meta.key_type,
                        meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!("WARNING: {}", reason),
                        },
                    ));
                }
                policy::PolicyVerdict::Compliant => {}
            }
        }

        let version = meta
            .current_key_version()
            .ok_or_else(|| EncryptError("no current version".into()))?;

        let pk = PublicKey::from_bytes(
            &hex::decode(&version.public_key_hex)
                .map_err(|e| EncryptError(format!("decode pk: {}", e)))?,
        )
        .map_err(|_| EncryptError("parse public key failed".into()))?;

        // P225: Bind domain_id to AAD for cross-domain protection
        // Prepend domain_id to AAD so blob from Domain A cannot be interpreted under Domain B
        let domain_id = self
            .resolve_domain_for_key(key_id)
            .await
            .map_err(|e| EncryptError(format!("domain resolution failed: {}", e)))?;

        let mut domain_bound_aad = Vec::new();
        domain_bound_aad.extend_from_slice(domain_id.to_string().as_bytes());
        domain_bound_aad.push(b':'); // Separator
        domain_bound_aad.extend_from_slice(aad.as_bytes());
        let bound_aad = Aad::raw(&domain_bound_aad);

        let ciphertext = self
            .envelope
            .seal(&pk, plaintext, &bound_aad, context)
            .map_err(|e| EncryptError(format!("seal: {}", e)))?;

        meta.usage_count += 1;
        meta.updated_at = Utc::now();
        self.storage
            .put(&meta)
            .map_err(|e| EncryptError(e.to_string()))?;

        self.audit.record(AuditEvent::key_event(
            key_id,
            meta.key_type,
            meta.state,
            AuditAction::EncryptionPerformed {
                key_version: meta.current_version,
            },
        ));

        Ok(EncryptedBlob {
            key_id: key_id.as_str().to_string(),
            key_version: meta.current_version,
            ciphertext_hex: hex::encode(&ciphertext),
            encrypted_at: Utc::now(),
        })
    }

    /// P316: Capability-gated encrypt — requires AuthorizedContext from StateEnforcer.
    /// This is the enforced-by-construction path. The raw encrypt() is kept for
    /// internal/test use only and will be deprecated once all callers migrate.
    /// P378/P384 — Validate an AuthorizedContext against the bound StateEnforcer.
    ///
    /// **Fail-closed (P384):** If no enforcer is bound, this returns `Err` — not `Ok`.
    /// The previous `if let Some` pattern silently passed when no enforcer was set,
    /// making enforcement optional. This version makes it mandatory:
    ///
    /// - With enforcer (production): proves the token was issued by the live instance
    /// - Without enforcer: returns `Err` — keystore refuses to operate in unenforced mode
    ///
    /// Call `with_enforcer()` at startup before any authorized operation.
    async fn validate_authz(&self, authz: &citadel_core::AuthorizedContext) -> Result<(), String> {
        match &self.enforcer {
            Some(enforcer) => authz
                .validate(&*enforcer.read().await)
                .map_err(|e| format!("capability validation failed at keystore boundary: {}", e)),
            None => {
                // P384: Fail-closed — "cannot be used incorrectly" not "correct if used properly".
                // This prevents authorized methods from executing without a bound StateEnforcer.
                // If you see this error, call Keystore::with_enforcer() before using the keystore.
                Err(
                    "keystore has no bound StateEnforcer — call with_enforcer() before using \
                     encrypt_authorized, decrypt_authorized, or sign_authorized. \
                     Production keystores must always be bound to a live StateEnforcer."
                        .into(),
                )
            }
        }
    }

    /// P217 — keystore-side cross-domain rejection (defense in depth).
    ///
    /// If the authorization is domain-scoped, independently resolve the target
    /// key's Domain from the hierarchy and reject if it differs from the
    /// authorized domain. The keystore does NOT trust the authorizer's domain
    /// claim: even if the StateEnforcer's domain map were wrong or bypassed, a
    /// cross-domain operation is refused here. A non-domain-scoped authorization
    /// (domain = None) is unaffected (single-tenant deployments).
    async fn enforce_authorized_domain(
        &self,
        authz_domain: Option<&str>,
        key_id: &KeyId,
    ) -> Result<(), String> {
        let dom = match authz_domain {
            Some(d) => d,
            None => return Ok(()),
        };
        let resolved = self
            .resolve_domain_for_key(key_id)
            .await
            .map_err(|e| format!("domain resolution failed for {}: {}", key_id, e))?;
        if resolved.to_string() != dom {
            return Err(format!(
                "P217 cross-domain operation rejected: key {} is in domain {}, \
                 not authorized domain {}",
                key_id, resolved, dom
            ));
        }
        Ok(())
    }

    pub async fn encrypt_authorized(
        &self,
        authz: &citadel_core::AuthorizedContext,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<EncryptedBlob, EncryptError> {
        // P378: Validate capability issuance at keystore boundary.
        self.validate_authz(authz).await.map_err(EncryptError)?;
        let key_id = KeyId::new(authz.key_id());
        // Cross-check: the context must authorize THIS specific key for encrypt.
        authz
            .require_encrypt_for(authz.key_id())
            .map_err(EncryptError)?;
        // P217: keystore-side cross-domain rejection (defense in depth).
        self.enforce_authorized_domain(authz.domain(), &key_id)
            .await
            .map_err(EncryptError)?;
        self.encrypt(&key_id, plaintext, aad, context).await
    }

    pub(crate) async fn decrypt(
        &self,
        blob: &EncryptedBlob,
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, DecryptError> {
        let key_id = KeyId::new(&blob.key_id);

        // P004: All decrypt errors must be uniform to prevent information leakage
        // Log details internally, return opaque error to caller
        let meta = self.get(&key_id).await.map_err(|e| {
            tracing::warn!(key_id = %key_id, error = %e, "decrypt: key lookup failed");
            DecryptError("operation failed".into())
        })?;

        if !meta.state.can_decrypt() {
            tracing::warn!(
                key_id = %key_id,
                state = ?meta.state,
                "decrypt: key state does not permit decryption"
            );
            return Err(DecryptError("operation failed".into()));
        }

        // Enforced cryptoperiods are operation-time security boundaries. The
        // background expiration sweep persists lifecycle state, but decrypt
        // must not remain usable in the interval after max_lifetime elapses and
        // before that sweep runs. Keep the public error opaque, matching every
        // other decrypt rejection path.
        if let Some(adapted) = self.effective_policy_for(&meta) {
            if let policy::PolicyVerdict::Expired {
                age_days,
                limit_days,
            } = policy::evaluate(&adapted, &meta)
            {
                self.audit.record(AuditEvent::key_event(
                    &key_id,
                    meta.key_type,
                    meta.state,
                    AuditAction::PolicyEvaluated {
                        verdict: format!(
                            "BLOCKED DECRYPT: expired age={}d limit={}d",
                            age_days, limit_days
                        ),
                    },
                ));
                tracing::warn!(
                    key_id = %key_id,
                    age_days,
                    limit_days,
                    "decrypt: enforced cryptoperiod expired"
                );
                return Err(DecryptError("operation failed".into()));
            }
        }

        let key_version = meta
            .versions
            .iter()
            .find(|v| v.version == blob.key_version)
            .ok_or_else(|| {
                tracing::warn!(
                    key_id = %key_id,
                    requested_version = blob.key_version,
                    "decrypt: version not found"
                );
                DecryptError("operation failed".into())
            })?
            .clone(); // Clone to avoid holding a reference into `meta` across await.

        let ciphertext = hex::decode(&blob.ciphertext_hex).map_err(|e| {
            tracing::warn!(key_id = %key_id, error = %e, "decrypt: hex decode failed");
            DecryptError("operation failed".into())
        })?;

        // Replay protection — atomic claim before decrypt, release only on failure.
        // P319: ReplayStore::claim() is atomic (check-and-insert in one lock).
        //   claim() returns Ok(true)=slot claimed, Ok(false)=replay detected, Err=fail-closed.
        //   release() called only on decrypt failure — prevents ciphertext poisoning.
        //   Successful decrypt keeps the claim until TTL.
        // P079: replay key includes AEAD tag to prevent ciphertext poisoning.
        //   SHA-256(domain_id || key_id || version[4BE] || nonce[12] || aead_tag[16])
        //   An attacker cannot forge a replay key without knowing the valid AEAD tag.
        // P083: uses derive_replay_key() — canonical format, not hand-rolled concatenation.
        // P084: uses NONCE_OFFSET and AEAD_TAG_BYTES from wire.rs — no hardcoded offsets.
        // P224: Replay scoped by Domain to prevent cross-domain replay interference.
        use citadel_envelope::wire::{envelope_nonce, AEAD_TAG_BYTES};
        if ciphertext.len() < AEAD_TAG_BYTES {
            tracing::warn!(
                key_id = %key_id,
                ciphertext_len = ciphertext.len(),
                "decrypt: ciphertext too short"
            );
            return Err(DecryptError("operation failed".into()));
        }

        // P224: Resolve domain_id for replay scoping
        let domain_id = self
            .resolve_domain_for_key(&KeyId::new(&blob.key_id))
            .await
            .map_err(|e| {
                tracing::warn!(key_id = %key_id, error = %e, "decrypt: domain resolution failed");
                DecryptError("operation failed".into())
            })?;

        let nonce_bytes = envelope_nonce(&ciphertext).map_err(|_| {
            tracing::warn!(key_id = %key_id, "decrypt: invalid envelope framing");
            DecryptError("operation failed".into())
        })?;
        // AEAD tag is the last 16 bytes of the full AEAD ciphertext+tag block.
        let aead_tag = &ciphertext[ciphertext.len() - AEAD_TAG_BYTES..];
        let cache_key = crate::replay_store::derive_replay_key(
            &domain_id.to_string(), // P224: Domain scoping
            &blob.key_id,
            blob.key_version,
            nonce_bytes,
            aead_tag,
        );
        // P319: Atomic claim — check-and-insert in one locked operation.
        // claim() returns Ok(false) if slot already taken (replay), Ok(true) if claimed.
        // We hold the replay key as a local to pass to release() on decrypt failure.
        {
            let cache = self.replay_cache.lock().unwrap();
            match cache.claim(&cache_key, Duration::from_secs(86400)) {
                Ok(true) => {
                    // Slot claimed — proceed with decrypt. release() will be called
                    // if decryption fails (see below).
                }
                Ok(false) => {
                    // Slot already exists — this is a replay.
                    tracing::warn!(
                        key_id = %key_id,
                        version = blob.key_version,
                        "decrypt: replay detected"
                    );
                    self.audit.record(AuditEvent::key_event(
                        &key_id,
                        meta.key_type,
                        meta.state,
                        AuditAction::ReplayDetected {
                            key_version: blob.key_version,
                        },
                    ));
                    return Err(DecryptError("operation failed".into()));
                }
                Err(e) => {
                    // Store failure — fail closed.
                    tracing::error!(
                        err = %e,
                        key_id = %key_id,
                        "decrypt: replay store claim() failed — failing closed"
                    );
                    self.audit.record(AuditEvent::key_event(
                        &key_id,
                        meta.key_type,
                        meta.state,
                        AuditAction::ReplayDetected {
                            key_version: blob.key_version,
                        },
                    ));
                    return Err(DecryptError("operation failed".into()));
                }
            }
        }

        // Unwrap the secret key (recursive through KEK hierarchy if needed).
        let sk_bytes = self
            .unwrap_key_version(&key_id, &key_version, 0)
            .await
            .map_err(|e| {
                // P016: Release replay claim on unwrap failure (after claim succeeded)
                if let Ok(cache) = self.replay_cache.lock() {
                    if let Err(release_err) = cache.release(&cache_key) {
                        tracing::warn!(
                            err = %release_err,
                            key_id = %key_id,
                            "replay store release() failed after key unwrap error"
                        );
                    }
                }
                tracing::warn!(key_id = %key_id, error = %e, "decrypt: key unwrap failed");
                DecryptError("operation failed".into())
            })?;

        let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| {
            // P016: Release replay claim on secret key parse failure (after claim succeeded)
            if let Ok(cache) = self.replay_cache.lock() {
                if let Err(release_err) = cache.release(&cache_key) {
                    tracing::warn!(
                        err = %release_err,
                        key_id = %key_id,
                        "replay store release() failed after secret key parse error"
                    );
                }
            }
            tracing::warn!(key_id = %key_id, error = ?e, "decrypt: secret key parse failed");
            DecryptError("operation failed".into())
        })?;

        // P225: Reconstruct domain-bound AAD (must match encrypt)
        let mut domain_bound_aad = Vec::new();
        domain_bound_aad.extend_from_slice(domain_id.to_string().as_bytes());
        domain_bound_aad.push(b':'); // Separator
        domain_bound_aad.extend_from_slice(aad.as_bytes());
        let bound_aad = Aad::raw(&domain_bound_aad);

        let plaintext = self
            .envelope
            .open(&sk, &ciphertext, &bound_aad, context)
            .map_err(|_| {
                self.record_threat_event(
                    ThreatEvent::new(ThreatEventKind::DecryptionFailure, 3.0).with_detail(format!(
                        "key={}, version={}",
                        blob.key_id, blob.key_version
                    )),
                );
                self.audit.record(AuditEvent::key_event(
                    &key_id,
                    meta.key_type,
                    meta.state,
                    AuditAction::DecryptionFailed {
                        key_version: blob.key_version,
                    },
                ));
                // P319: Release the replay slot on decrypt failure — prevents
                // ciphertext-poisoning attack. A corrupted blob must not block
                // the legitimate ciphertext from being decrypted.
                if let Ok(cache) = self.replay_cache.lock() {
                    if let Err(e) = cache.release(&cache_key) {
                        tracing::warn!(err = %e, key_id = %key_id, "replay store release() failed on decrypt error");
                    }
                }
                // P004: Uniform error message
                DecryptError("operation failed".into())
            })?;

        // P319: Slot was claimed before decrypt. Successful decryption keeps
        // the claim — no release needed. TTL expiry handles slot cleanup.

        self.audit.record(AuditEvent::key_event(
            &key_id,
            meta.key_type,
            meta.state,
            AuditAction::DecryptionPerformed {
                key_version: blob.key_version,
            },
        ));

        Ok(plaintext)
    }

    // -----------------------------------------------------------------------
    // Helper methods
    // -----------------------------------------------------------------------

    fn transition(&self, meta: &mut KeyMetadata, target: KeyState) -> Result<(), LifecycleError> {
        if !meta.state.can_transition_to(target) {
            return Err(LifecycleError(KeystoreError::InvalidTransition {
                id: meta.id.clone(),
                from: meta.state,
                to: target,
            }));
        }
        meta.state = target;
        meta.updated_at = Utc::now();
        Ok(())
    }

    fn current_threat_level(&self) -> ThreatLevel {
        self.threat.lock().unwrap().current_level()
    }

    fn effective_policy_for(&self, meta: &KeyMetadata) -> Option<KeyPolicy> {
        let level = self.current_threat_level();
        meta.policy_id
            .as_ref()
            .and_then(|pid| self.policies.get(pid.as_str()))
            .map(|base| PolicyAdapter::adapt(base, level))
    }

    fn grace_period_for(&self, meta: &KeyMetadata) -> Duration {
        self.effective_policy_for(meta)
            .map(|p| p.rotation_grace_period)
            .unwrap_or(Duration::from_secs(7 * 86400))
    }

    fn max_lifetime_for(&self, meta: &KeyMetadata) -> Option<Duration> {
        self.effective_policy_for(meta).and_then(|p| p.max_lifetime)
    }

    // -----------------------------------------------------------------------
    // Threat assessment API
    // -----------------------------------------------------------------------

    pub fn record_threat_event(&self, event: ThreatEvent) {
        self.threat.lock().unwrap().record_event(event);
    }

    pub fn record_threat_events(&self, events: Vec<ThreatEvent>) {
        self.threat.lock().unwrap().record_events(events);
    }

    /// Explicitly reset threat state to Low, discarding all recorded events
    /// and any manual override. See `ThreatAssessor::reset` for why this is
    /// distinct from injecting a `ManualDeescalation` event.
    pub fn reset_threat_state(&self) {
        self.threat.lock().unwrap().reset();
    }

    /// P158 — Record an audit event directly into the tamper-evident audit chain.
    /// Used by the API layer to write auth failures and other security events
    /// that originate outside the keystore's own operations.
    /// Surface audit persistence failures at service boundaries. This does not
    /// roll back key mutations; callers must not report success after a failed audit.
    pub fn audit_health(&self) -> std::io::Result<()> {
        self.audit.check_health()
    }

    pub fn record_audit_event(&self, action: crate::audit::AuditAction) {
        self.audit
            .record(crate::audit::AuditEvent::system_event(action));
    }

    pub fn threat_level(&self) -> ThreatLevel {
        self.current_threat_level()
    }

    /// P085 — Return the name of the active replay store backend.
    ///
    /// Used by the doctor to verify actual runtime state (not just env hints).
    /// Returns values like `"memory"`, `"file"`, `"redis"`, or `"unknown"`.
    pub fn replay_backend_name(&self) -> &'static str {
        self.replay_cache.lock().unwrap().backend_name()
    }

    pub fn threat_score(&self) -> f64 {
        self.threat.lock().unwrap().raw_score()
    }

    pub async fn security_metrics(&self) -> Result<SecurityMetrics, KeystoreError> {
        let level = self.current_threat_level();
        let all_keys = self.storage.list()?;
        let total = all_keys.len();
        let mut compliant = 0;

        for meta in &all_keys {
            if let Some(pid) = &meta.policy_id {
                if let Some(base_policy) = self.policies.get(pid.as_str()) {
                    let adapted = PolicyAdapter::adapt(base_policy, level);
                    let verdict = policy::evaluate(&adapted, meta);
                    if matches!(
                        verdict,
                        policy::PolicyVerdict::Compliant | policy::PolicyVerdict::Warning { .. }
                    ) {
                        compliant += 1;
                    }
                } else {
                    compliant += 1;
                }
            } else {
                compliant += 1;
            }
        }

        Ok(self
            .threat
            .lock()
            .unwrap()
            .security_metrics(total, compliant))
    }

    pub fn threat_history(&self) -> Vec<(chrono::DateTime<Utc>, ThreatLevel, String)> {
        self.threat.lock().unwrap().level_history().to_vec()
    }

    pub fn policy_adaptation_summary(
        &self,
        policy_id: &PolicyId,
    ) -> Option<crate::threat::AdaptationSummary> {
        let level = self.current_threat_level();
        self.policies
            .get(policy_id.as_str())
            .map(|base| PolicyAdapter::summarize(base, level))
    }

    pub async fn evaluate_adaptive_policy(
        &self,
        id: &KeyId,
    ) -> Result<policy::PolicyVerdict, KeystoreError> {
        let level = self.current_threat_level();
        let meta = self.get(id).await?;
        let adapted_policy = match &meta.policy_id {
            Some(pid) => {
                let base = self
                    .policies
                    .get(pid.as_str())
                    .ok_or_else(|| KeystoreError::PolicyNotFound(pid.as_str().to_string()))?;
                PolicyAdapter::adapt(base, level)
            }
            None => return Ok(policy::PolicyVerdict::Compliant),
        };

        let verdict = policy::evaluate(&adapted_policy, &meta);
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::PolicyEvaluated {
                verdict: format!("{:?} (threat:{})", verdict, level.label()),
            },
        ));
        Ok(verdict)
    }

    pub async fn check_adaptive_rotation_due(&self) -> Result<Vec<(KeyId, String)>, KeystoreError> {
        let level = self.current_threat_level();
        let active = self.storage.list_by_state(KeyState::Active)?;
        let mut due = Vec::new();

        for meta in active {
            if let Some(pid) = &meta.policy_id {
                if let Some(base_policy) = self.policies.get(pid.as_str()) {
                    let adapted = PolicyAdapter::adapt(base_policy, level);
                    let verdict = policy::evaluate(&adapted, &meta);
                    if let policy::PolicyVerdict::RotationNeeded { reason } = verdict {
                        due.push((
                            meta.id.clone(),
                            format!("{} [threat:{}]", reason, level.label()),
                        ));
                    }
                }
            }
        }
        Ok(due)
    }

    // -----------------------------------------------------------------------
    // P364 — ML-DSA-65 Signing Operations
    // -----------------------------------------------------------------------

    /// Generate an ML-DSA-65 signing keypair under the Citadel key hierarchy.
    ///
    /// # What makes this different from generate()
    ///
    /// `generate()` calls `self.envelope.generate_keypair()` which produces an
    /// X25519 + ML-KEM-768 keypair for encryption. Signing keys produce ML-DSA-65
    /// material (NIST FIPS 204). This method is a separate code path.
    ///
    /// # Storage model
    ///
    /// - `public_key_hex`: hex-encoded ML-DSA-65 verifying key (1952 bytes → 3904 hex chars)
    /// - `secret_key_material`: `CitadelWrapped` hex of the 32-byte ML-DSA-65 seed
    ///
    /// The **seed** (32 bytes) is stored, not the expanded signing key (4032 bytes).
    /// This is the preferred serialization per ml-dsa documentation — the full signing
    /// key is reconstructed on demand via `MlDsa65::from_seed()`.
    ///
    /// # Wrapping
    ///
    /// The seed is wrapped by the parent KEK's Citadel public key using the existing
    /// `wrap_with_citadel_key()` path. That method takes `&[u8]` — algorithm-agnostic.
    /// No changes to the wrapping or unwrapping chain.
    ///
    /// # Parent requirement
    ///
    /// Parent MUST be `KeyType::KeyEncrypting`. The hierarchy enforcer rejects any
    /// other parent type.
    ///
    /// # Returns
    ///
    /// `KeyId` of the new signing key in `KeyState::Pending`. Call `activate()` before use.
    pub async fn generate_signing_key(
        &self,
        name: impl Into<String>,
        policy_id: Option<PolicyId>,
        parent_id: KeyId,
    ) -> Result<KeyId, GenerateError> {
        // Fail-closed master key check (same gate as generate())
        if self.master_key.is_none() {
            let dev_mode = std::env::var("CITADEL_ALLOW_PLAINTEXT_KEYS").as_deref() == Ok("1")
                && std::env::var("CITADEL_ENV").as_deref() == Ok("development");
            if !dev_mode {
                return Err(GenerateError(KeystoreError::StorageError(
                    "CITADEL_MASTER_KEY is not set. Set CITADEL_MASTER_KEY or \
                     set CITADEL_ALLOW_PLAINTEXT_KEYS=1 and CITADEL_ENV=development."
                        .into(),
                )));
            }
        }

        // Validate parent is KeyEncrypting (enforces Kek → SigningKey hierarchy)
        {
            use crate::hierarchy::KeyRole;
            let parent_meta = self
                .storage
                .get(&parent_id)
                .map_err(|e| {
                    GenerateError(KeystoreError::StorageError(format!(
                        "load parent for signing key: {}",
                        e
                    )))
                })?
                .ok_or_else(|| {
                    GenerateError(KeystoreError::HierarchyViolation(format!(
                        "parent key {} not found",
                        parent_id
                    )))
                })?;
            let parent_role = KeyRole::from(parent_meta.key_type);
            let flat_override = std::env::var("CITADEL_ALLOW_FLAT_DEKS").as_deref() == Ok("1")
                && std::env::var("CITADEL_ENV").as_deref() == Ok("development");
            if !parent_role.can_wrap(KeyRole::SigningKey) && !flat_override {
                return Err(GenerateError(KeystoreError::HierarchyViolation(format!(
                    "Signing key parent must be KeyEncrypting (Kek). Got {:?} ({:?}).",
                    parent_meta.key_type, parent_role
                ))));
            }
        }

        let id = KeyId::generate();
        let now = Utc::now();

        // P372: Delegate to citadel-signer — single ML-DSA algorithm surface.
        // generate_keypair() returns (vk_bytes: Vec<u8>, seed: Zeroizing<[u8; 32]>)
        let (vk_bytes, seed_zeroizing) = citadel_signer::dsa::generate_keypair().map_err(|e| {
            GenerateError(KeystoreError::StorageError(format!(
                "ML-DSA keypair generation failed: {}",
                e
            )))
        })?;
        let seed_bytes: [u8; 32] = *seed_zeroizing;

        // Wrap the 32-byte seed using the parent KEK's Citadel public key.
        // wrap_with_citadel_key() takes &[u8] — algorithm-agnostic, works unchanged.
        let (material, wrapping_key_id, wrapping_key_version) = self
            .wrap_secret_key_for(&id, 1, Some(&parent_id), &seed_bytes)
            .await
            .map_err(|e| GenerateError(KeystoreError::StorageError(e)))?;

        let wrap_nonce_hex = Self::extract_wrap_nonce(&material);
        // seed_bytes is [u8; 32] on stack — dropped here. seed_zeroizing (Zeroizing) already zeroized.

        let version = KeyVersion {
            version: 1,
            created_at: now,
            public_key_hex: hex::encode(&vk_bytes), // 1952 bytes → 3904 hex chars
            secret_key_material: material,          // CitadelWrapped 32-byte seed
            wrapping_key_id,
            wrapping_key_version,
            wrap_nonce_hex,
            wrapping_mode: None,
        };

        let meta = KeyMetadata {
            id: id.clone(),
            name: name.into(),
            key_type: KeyType::Signing,
            state: KeyState::Pending,
            policy_id,
            parent_id: Some(parent_id),
            created_at: now,
            updated_at: now,
            activated_at: None,
            rotated_at: None,
            revoked_at: None,
            destroyed_at: None,
            versions: vec![version],
            current_version: 1,
            usage_count: 0,
            tags: HashMap::new(),
        };

        self.storage.put(&meta).map_err(GenerateError)?;
        self.audit.record(AuditEvent::key_event(
            &id,
            KeyType::Signing,
            KeyState::Pending,
            AuditAction::KeyGenerated,
        ));

        Ok(id)
    }

    /// Sign a message using an ML-DSA-65 signing key.
    ///
    /// # Replay protection
    ///
    /// NOT applied. Signatures are not one-time-use. The same signing key legitimately
    /// signs many messages. Replay protection (ReplayStore::claim) applies to decryption
    /// blobs, not to signatures. Applications that want one-time assertion semantics
    /// track assertion IDs themselves.
    ///
    /// # StateEnforcer
    ///
    /// The key must be `KeyType::Signing` and `KeyState::Active`.
    /// StateEnforcer (layer 1) denied this key at authorize_sign(); keystore (layer 2)
    // enforces key type and state. Both layers are required.
    ///
    /// # Returns
    ///
    /// `SignedPayload` containing the ML-DSA-65 signature bytes (3309 bytes) plus
    /// key metadata needed for verification.
    /// P369 — Capability-gated sign — requires AuthorizedContext from StateEnforcer.
    ///
    /// This is the enforced-by-construction path for signing. The raw `sign()`
    /// method is `pub(crate)` and should not be called from outside the keystore.
    ///
    /// Mirrors `encrypt_authorized` and `decrypt_authorized` — signing is as
    /// sensitive as decryption: a signing key can mint trust tokens.
    pub async fn sign_authorized(
        &self,
        authz: &citadel_core::AuthorizedContext,
        message: &[u8],
    ) -> Result<SignedPayload, SignError> {
        // P378: Validate capability issuance at keystore boundary.
        self.validate_authz(authz).await.map_err(SignError)?;
        let key_id = KeyId::new(authz.key_id());
        // P017/P022: Cross-check authorization is bound to THIS specific message hash.
        // Prevents authorization reuse across different messages.
        authz
            .require_sign_for_payload(authz.key_id(), message)
            .map_err(SignError)?;
        self.sign(&key_id, message).await
    }

    pub(crate) async fn sign(
        &self,
        key_id: &KeyId,
        message: &[u8],
    ) -> Result<SignedPayload, SignError> {
        let meta = self
            .get(key_id)
            .await
            .map_err(|e| SignError(e.to_string()))?;

        // Keystore gate — key type and state (AuthorizedContext-based check was done
        // in sign_authorized; this guard makes the inner path self-defending)
        if meta.key_type != KeyType::Signing {
            let reason = format!(
                "keystore denied: key {} is type {} — sign() requires KeyType::Signing",
                key_id, meta.key_type
            );
            self.audit.record(AuditEvent::key_event(
                key_id,
                meta.key_type,
                meta.state,
                AuditAction::SigningFailed {
                    key_version: meta.current_version,
                    reason: reason.clone(),
                },
            ));
            return Err(SignError(reason));
        }
        if meta.state != KeyState::Active {
            let reason = format!(
                "keystore denied: key {} is {} — signing requires Active state",
                key_id, meta.state
            );
            self.audit.record(AuditEvent::key_event(
                key_id,
                meta.key_type,
                meta.state,
                AuditAction::SigningFailed {
                    key_version: meta.current_version,
                    reason: reason.clone(),
                },
            ));
            return Err(SignError(reason));
        }

        let kv = meta
            .current_key_version()
            .ok_or_else(|| SignError("no current key version".into()))?
            .clone();

        // Unwrap the 32-byte seed using the existing recursive unwrap chain.
        // unwrap_key_version() takes &[u8] — algorithm-agnostic.
        let seed_bytes = self.unwrap_key_version(key_id, &kv, 0).await.map_err(|e| {
            let reason = format!("unwrap signing key: {}", e);
            self.audit.record(AuditEvent::key_event(
                key_id,
                meta.key_type,
                meta.state,
                AuditAction::SigningFailed {
                    key_version: kv.version,
                    reason: reason.clone(),
                },
            ));
            SignError(reason)
        })?;

        // P372: Delegate to citadel-signer — single ML-DSA algorithm surface.
        let sig_bytes = citadel_signer::dsa::sign_message(&seed_bytes, message)
            .map_err(|e| SignError(format!("ML-DSA sign failed: {}", e)))?;

        self.audit.record(AuditEvent::key_event(
            key_id,
            meta.key_type,
            meta.state,
            AuditAction::SigningPerformed {
                key_version: kv.version,
                payload_bytes: message.len(),
            },
        ));

        Ok(SignedPayload {
            key_id: key_id.as_str().to_string(),
            key_version: kv.version,
            signature_hex: hex::encode(&sig_bytes),
            signed_at: Utc::now(),
        })
    }

    /// Verify an ML-DSA-65 signature against the stored verifying key.
    ///
    /// # Stateless
    ///
    /// Does NOT unwrap or access secret key material. Uses only the
    /// `public_key_hex` field from `KeyVersion` — the ML-DSA-65 verifying key.
    /// A verifier with only the public key bytes can verify offline without Citadel.
    ///
    /// # Version handling
    ///
    /// Verifies against the key version specified in `signed_payload.key_version`.
    /// Allows verification of signatures produced by rotated (superseded) key versions.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid.
    /// `Err(VerifyError)` only for structural problems (key not found, wrong type,
    /// malformed signature bytes, or revoked/destroyed key).
    pub async fn verify_signature(
        &self,
        key_id: &KeyId,
        message: &[u8],
        signed_payload: &SignedPayload,
    ) -> Result<bool, VerifyError> {
        let meta = self
            .get(key_id)
            .await
            .map_err(|e| VerifyError(e.to_string()))?;

        if meta.key_type != KeyType::Signing {
            return Err(VerifyError(format!(
                "key {} is type {} — verify_signature() requires KeyType::Signing",
                key_id, meta.key_type
            )));
        }

        // Allow verification against Active or Rotated keys (historical signatures valid)
        if !matches!(meta.state, KeyState::Active | KeyState::Rotated) {
            return Err(VerifyError(format!(
                "key {} is {} — cannot verify (Revoked/Expired/Destroyed keys are terminal)",
                key_id, meta.state
            )));
        }

        // Find the specific key version that produced the signature
        let kv = meta
            .get_version(signed_payload.key_version)
            .ok_or_else(|| {
                VerifyError(format!(
                    "key {} version {} not found",
                    key_id, signed_payload.key_version
                ))
            })?;

        // Decode verifying key and signature from hex
        let vk_bytes = hex::decode(&kv.public_key_hex)
            .map_err(|e| VerifyError(format!("decode verifying key hex: {}", e)))?;
        let sig_bytes = hex::decode(&signed_payload.signature_hex)
            .map_err(|e| VerifyError(format!("decode signature hex: {}", e)))?;

        // P372: Delegate to citadel-signer — single ML-DSA algorithm surface.
        let valid = citadel_signer::dsa::verify_message(&vk_bytes, message, &sig_bytes)
            .map_err(|e| VerifyError(format!("ML-DSA verify failed: {}", e)))?;

        self.audit.record(AuditEvent::key_event(
            key_id,
            meta.key_type,
            meta.state,
            AuditAction::VerificationPerformed {
                key_version: signed_payload.key_version,
                valid,
            },
        ));

        Ok(valid)
    }
} // impl Keystore

// ---------------------------------------------------------------------------
// P364 — Signing result types
// ---------------------------------------------------------------------------

/// Output of `Keystore::sign()` — ML-DSA-65 signature with key metadata.
///
/// Pass this to `Keystore::verify_signature()` or include it in a
/// Citadel Native Assertion for external verifiers.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedPayload {
    /// The signing key used.
    pub key_id: String,
    /// Which version of the signing key produced this signature.
    pub key_version: u32,
    /// Hex-encoded ML-DSA-65 signature (3309 bytes → 6618 hex chars).
    pub signature_hex: String,
    /// When the signing operation was performed.
    pub signed_at: chrono::DateTime<Utc>,
}

/// Error from `Keystore::sign()`.
#[derive(Debug)]
pub struct SignError(pub String);

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignError: {}", self.0)
    }
}

/// Error from `Keystore::verify_signature()`.
#[derive(Debug)]
pub struct VerifyError(pub String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifyError: {}", self.0)
    }
}
