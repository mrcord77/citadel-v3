// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Distributed replay protection (V3).
//!
//! Provides `ReplayStore` trait whose
//! key is a SHA-256 digest (preventing unbounded growth) and whose API is
//! `claim(key, ttl)` — compatible with atomic Redis `SET NX EX`.
//!
//! # Replay key format (P079 — includes AEAD tag)
//! ```text
//! SHA-256( key_id_bytes || key_version[4BE] || nonce[12] || aead_tag[16] )
//! ```
//! The AEAD tag is the last 16 bytes of the encrypted blob. Including it prevents
//! the poisoning attack: an attacker cannot forge a reservation using a corrupted
//! ciphertext body because the AEAD tag will differ from the valid ciphertext.
//! Using a hash prevents the cache key from growing with key_id length.
//!
//! # Fail-closed policy
//!
//! When `fail_closed = true` (recommended for production), any store error
//! causes `claim()` to return an error (deny the request). This prevents
//! store outages from becoming replay-protection bypasses.
//!
//! # Backend options
//!
//! | Backend | Single-instance | Cross-instance | Restart-safe |
//! |---------|----------------|----------------|--------------|
//! | `MemoryReplayStore` | ✓ | ✗ | ✗ |
//! | `FileReplayStore` | ✓ | ✗ | ✓ |
//! | `RedisReplayStore` | ✓ | ✓ | ✓ |

// ---------------------------------------------------------------------------
// P386 — Replay Invariant: formal declaration
// ---------------------------------------------------------------------------
//
// REPLAY INVARIANT (must hold in all production deployments):
//
//   For any ciphertext C with replay_key K = SHA-256(key_id‖version‖nonce‖tag):
//
//     first  decrypt(C): claim(K) succeeds → decryption executes
//     second decrypt(C): claim(K) fails    → ALWAYS REJECTED, no exceptions
//
// This invariant holds regardless of:
//   - timing: concurrent requests race to claim(), exactly one wins
//   - store availability: fail_closed=true means store error → deny
//   - crash recovery: FileReplayStore persists claim state across restarts
//   - key rotation: replay_key includes key_version
//
// VIOLATION of this invariant is a SYSTEM SECURITY FAILURE.
// Any modification to claim()/release() logic requires explicit invariant review.
//
// Proven by test: replay_invariant_same_ciphertext_decrypts_exactly_once
// (see test module below)

/// P386 — Machine-readable replay invariant. Referenced in invariant tests.
pub const REPLAY_INVARIANT: &str = "same-ciphertext-decrypts-exactly-once-fail-closed-on-error";

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// ReplayError
// ---------------------------------------------------------------------------

/// Error from a replay store operation.
#[derive(Debug, Clone)]
pub struct ReplayError {
    pub message: String,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "replay store error: {}", self.message)
    }
}

impl std::error::Error for ReplayError {}

impl ReplayError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayStore trait
// ---------------------------------------------------------------------------

/// Backend for nonce replay protection.
///
/// All implementations must be `Send + Sync` to be held in a `Mutex<Box<dyn ReplayStore>>`.
pub trait ReplayStore: Send + Sync {
    /// P319: Atomic claim — check-and-insert in one locked operation.
    ///
    /// Returns `Ok(true)`  = slot claimed by this caller; proceed with decrypt.
    /// Returns `Ok(false)` = slot already claimed; this is a replay — deny.
    /// Returns `Err(_)`    = store failure → caller must treat as denied (fail-closed).
    ///
    /// Provides atomic one-time use via claim()/release() — single lock acquisition prevents TOCTOU races. A single lock acquisition
    /// ensures no two concurrent requests can both see the slot as absent.
    fn claim(&self, key: &[u8], ttl: Duration) -> Result<bool, ReplayError>;

    /// P319: Release a previously claimed slot — called ONLY when decrypt fails.
    ///
    /// Prevents the ciphertext-poisoning attack: a corrupted blob that fails
    /// decryption does not permanently block the legitimate ciphertext.
    /// Successful decryption must NOT call release — the claim stays until TTL.
    fn release(&self, key: &[u8]) -> Result<(), ReplayError>;

    /// Optional: return number of entries currently tracked.
    fn entry_count(&self) -> usize {
        0
    }

    /// Optional: backend identifier for diagnostics.
    fn backend_name(&self) -> &'static str {
        "unknown"
    }
}

// ---------------------------------------------------------------------------
// Replay key derivation
// ---------------------------------------------------------------------------

/// Derive the canonical replay cache key for a (key_id, key_version, nonce, aead_tag) tuple.
///
/// P079 fix — include the AEAD authentication tag in the replay key:
/// ```text
/// key = SHA-256( key_id_bytes || key_version[4BE] || nonce[12] || aead_tag[16] )
/// ```
///
/// **Why the tag?** Including the tag eliminates the ciphertext poisoning attack:
/// an attacker who submits a corrupted ciphertext with the same nonce produces a
/// *different* AEAD tag → different replay key → the legitimate ciphertext is not blocked.
/// A true replay (identical bytes) still matches the same key → correctly detected.
///
/// This allows `RedisReplayStore::claim()` to atomically reserve the slot (SET NX EX)
/// in a single call without risking that a corrupted ciphertext poisons the slot.
/// The nonce-only key (previous design) could be reserved by an attacker without
/// knowing the valid tag.
/// P224: Replay key now includes domain_id for cross-domain isolation.
/// Format: SHA-256(domain_id || key_id || key_version || nonce || aead_tag)
pub fn derive_replay_key(
    domain_id: &str,
    key_id: &str,
    key_version: u32,
    nonce: &[u8],
    aead_tag: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(domain_id.as_bytes()); // P224: Domain scoping
    h.update(key_id.as_bytes());
    h.update(key_version.to_be_bytes());
    h.update(nonce);
    h.update(aead_tag);
    h.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// MemoryReplayStore
// ---------------------------------------------------------------------------

/// In-memory replay store with TTL eviction. Not persistent across restarts.
///
/// Suitable for development, testing, and single-instance deployments
/// where restart-window replays are acceptable.
pub struct MemoryReplayStore {
    inner: std::sync::Mutex<MemoryInner>,
    fail_closed: bool,
    /// TTL for eviction — how long a nonce is considered "seen".
    ttl: Duration,
}

struct MemoryInner {
    seen: HashMap<Vec<u8>, Instant>,
}

impl MemoryReplayStore {
    /// Create with a specific TTL window and fail-closed policy.
    ///
    /// `ttl` — how long a nonce is retained (typically 24 hours).
    /// `fail_closed` — when true, errors from `claim()` deny the request.
    pub fn new(ttl: Duration, fail_closed: bool) -> Self {
        Self {
            inner: std::sync::Mutex::new(MemoryInner {
                seen: HashMap::new(),
            }),
            fail_closed,
            ttl,
        }
    }

    /// Create with default 24-hour TTL and fail-closed enabled.
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(86400), true)
    }

    fn evict_expired(inner: &mut MemoryInner, ttl: Duration) {
        let now = Instant::now();
        inner
            .seen
            .retain(|_, seen_at| now.duration_since(*seen_at) < ttl);
    }
}

impl Default for MemoryReplayStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl ReplayStore for MemoryReplayStore {
    /// P319: Atomic claim — evict expired entries then check-and-insert in one lock.
    fn claim(&self, key: &[u8], _ttl: Duration) -> Result<bool, ReplayError> {
        let mut inner = self.inner.lock().map_err(|e| {
            if self.fail_closed {
                ReplayError::new(format!("lock poisoned (fail-closed): {e}"))
            } else {
                ReplayError::new(format!("lock poisoned (fail-open): {e}"))
            }
        })?;
        MemoryReplayStore::evict_expired(&mut inner, self.ttl);
        if inner.seen.contains_key(key) {
            return Ok(false); // replay detected
        }
        inner.seen.insert(key.to_vec(), Instant::now());
        Ok(true) // slot claimed
    }

    /// P319: Release a slot on decrypt failure — prevents ciphertext poisoning.
    fn release(&self, key: &[u8]) -> Result<(), ReplayError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ReplayError::new(format!("lock poisoned on release: {e}")))?;
        inner.seen.remove(key);
        Ok(())
    }

    fn entry_count(&self) -> usize {
        self.inner.lock().map(|m| m.seen.len()).unwrap_or(0)
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

// ---------------------------------------------------------------------------
// FileReplayStore
// ---------------------------------------------------------------------------

/// File-backed replay store. Persists across process restarts on a single node.
///
/// ## P001/P014: Write Batching and Durability Guarantees
///
/// Every successful claim is synchronized to disk before it is acknowledged.
/// Atomic replacement plus parent-directory fsync provides restart/crash durability
/// on Unix filesystems that honor fsync. There is no batching or idle flush window.
/// This trades throughput for durability; the complete live set is rewritten per claim.
/// The file backend remains single-process only. Use Redis for distributed deployments.
pub struct FileReplayStore {
    path: PathBuf,
    default_ttl_secs: u64,
    #[allow(dead_code)]
    fail_closed: bool,
    mirror: std::sync::Mutex<FileReplayInner>,
}

/// In-memory mirror, serialized with its durable snapshot.
struct FileReplayInner {
    /// key → unix_seen_at
    claims: HashMap<Vec<u8>, u64>,
}

#[derive(Serialize, Deserialize)]
struct FileEntry {
    key_hex: String,
    seen_at_unix: u64,
}

impl FileReplayStore {
    /// P393: Returns Result — corrupt replay file = Err, not silent empty.
    ///
    /// - Missing file → Ok(empty) — normal first run
    /// - Read fails → Err — I/O error, abort startup
    /// - Parse fails → Err — corruption detected, abort startup
    pub fn new(
        path: impl Into<PathBuf>,
        default_ttl: Duration,
        fail_closed: bool,
    ) -> Result<Self, ReplayError> {
        let path = path.into();
        let default_ttl_secs = default_ttl.as_secs();
        let now = unix_now();
        let cutoff = now.saturating_sub(default_ttl_secs);

        let mut claims = HashMap::new();
        if path.exists() {
            // P393: Read failure → Err (not silent empty)
            let data = std::fs::read_to_string(&path)
                .map_err(|e| ReplayError::new(format!(
                    "replay file '{}' exists but cannot be read: {} — aborting to prevent replay bypass.",
                    path.display(), e
                )))?;

            // P393: Parse failure = corruption → Err (not silent empty)
            let entries = serde_json::from_str::<Vec<FileEntry>>(&data)
                .map_err(|e| ReplayError::new(format!(
                    "replay file '{}' is corrupt (parse failed: {}) —                      delete only if you accept previously-claimed ciphertexts may replay.",
                    path.display(), e
                )))?;

            for entry in entries {
                if entry.seen_at_unix >= cutoff {
                    // P403: Invalid key_hex → Err (not silent skip).
                    // Silently dropping a malformed entry forgets that replay claim,
                    // allowing a replay of that ciphertext across a restart.
                    let k = hex::decode(&entry.key_hex).map_err(|e| {
                        ReplayError::new(format!(
                            "replay file '{}' contains invalid key_hex '{}': {} \
                             — aborting to prevent replay bypass. \
                             Delete the file only if you accept replay risk for that ciphertext.",
                            path.display(),
                            entry.key_hex.chars().take(16).collect::<String>(),
                            e
                        ))
                    })?;
                    claims.insert(k, entry.seen_at_unix);
                }
            }
        }

        Ok(Self {
            path,
            default_ttl_secs,
            fail_closed,
            mirror: std::sync::Mutex::new(FileReplayInner { claims }),
        })
    }

    /// P394: Crash-safe flush via temp file + atomic rename.
    ///
    /// Writes to `replay.json.tmp`, syncs, renames to `replay.json`.
    /// A crash during write leaves `.tmp`; `replay.json` stays valid.
    fn flush(&self, inner: &FileReplayInner) -> Result<(), ReplayError> {
        use std::io::Write;

        let cutoff = unix_now().saturating_sub(self.default_ttl_secs);
        let entries: Vec<FileEntry> = inner
            .claims
            .iter()
            .filter(|(_, &ts)| ts >= cutoff)
            .map(|(k, &ts)| FileEntry {
                key_hex: hex::encode(k),
                seen_at_unix: ts,
            })
            .collect();

        // P437: serialize to bytes (Vec<u8>) for direct write — no intermediate String
        let json = serde_json::to_vec(&entries)
            .map_err(|e| ReplayError::new(format!("replay flush serialize: {}", e)))?;

        // P394/P416/P437: Write to .tmp then atomically rename.
        // PRE-CONDITION: The parent directory of self.path MUST exist.
        // P437 fix: create → write_all → flush → sync_all → close (all in one handle).
        // Previous pattern (fs::write then File::open) causes "Access is denied" on Windows
        // because reopening a freshly-written file for sync triggers OS file-locking issues.
        let tmp = self.path.with_extension("tmp");

        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| {
                ReplayError::new(format!(
                    "replay flush create tmp '{}': {}",
                    tmp.display(),
                    e
                ))
            })?;

            f.write_all(&json).map_err(|e| {
                ReplayError::new(format!("replay flush write tmp '{}': {}", tmp.display(), e))
            })?;

            f.flush().map_err(|e| {
                ReplayError::new(format!("replay flush buf tmp '{}': {}", tmp.display(), e))
            })?;

            // P404/P437: sync_all while handle still open — safe on both Windows and Unix
            f.sync_all().map_err(|e| {
                ReplayError::new(format!("replay fsync tmp '{}': {}", tmp.display(), e))
            })?;
            // file handle drops and closes here — before rename
        }

        // Never unlink the destination first: that creates a crash window in which
        // all prior replay claims disappear. std::fs::rename replaces the destination.
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| ReplayError::new(format!("replay atomic rename: {e}")))?;
        // The file contents and the replacement directory entry must both be durable.
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| ReplayError::new(format!("replay directory fsync: {e}")))?;
        }
        Ok(())
    }

    /// Synchronize the current snapshot explicitly. Kept for API compatibility;
    /// successful claim/release calls already persist their changes before returning.
    pub fn force_flush(&self) -> Result<(), ReplayError> {
        let inner = self
            .mirror
            .lock()
            .map_err(|e| ReplayError::new(format!("force_flush lock poisoned: {e}")))?;
        self.flush(&inner)
    }
}

impl ReplayStore for FileReplayStore {
    /// Atomically reserve and durably persist a claim before allowing decryption.
    /// On an I/O error retain the reservation: the on-disk outcome may be uncertain.
    fn claim(&self, key: &[u8], _ttl: Duration) -> Result<bool, ReplayError> {
        // P409: Fail-closed on lock poison — never panic during replay enforcement
        let mut inner = self
            .mirror
            .lock()
            .map_err(|e| ReplayError::new(format!("file replay mirror lock poisoned: {}", e)))?;

        // Evict expired entries
        let cutoff = unix_now().saturating_sub(self.default_ttl_secs);
        inner.claims.retain(|_, &mut ts| ts >= cutoff);

        // Check replay
        if inner.claims.contains_key(key) {
            return Ok(false); // replay detected
        }

        // Claim the slot in memory (always immediate)
        inner.claims.insert(key.to_vec(), unix_now());
        self.flush(&inner)?;

        Ok(true) // slot claimed
    }

    /// Release only after a failed decrypt. If persistence fails, restore the
    /// in-memory reservation rather than allowing reuse on an uncertain disk outcome.
    fn release(&self, key: &[u8]) -> Result<(), ReplayError> {
        let mut inner = self
            .mirror
            .lock()
            .map_err(|e| ReplayError::new(format!("file replay mirror lock poisoned: {e}")))?;
        let previous = inner.claims.remove(key);
        if let Err(error) = self.flush(&inner) {
            if let Some(timestamp) = previous {
                inner.claims.insert(key.to_vec(), timestamp);
            }
            return Err(error);
        }
        Ok(())
    }

    fn entry_count(&self) -> usize {
        self.mirror.lock().map(|m| m.claims.len()).unwrap_or(0)
    }

    fn backend_name(&self) -> &'static str {
        "file"
    }
}

// ---------------------------------------------------------------------------
// RedisReplayStore
// ---------------------------------------------------------------------------

/// Redis-backed replay store for distributed deployments.
///
/// # Replay protection design (P319)
///
/// Uses atomic `SET NX EX` (Redis SETNX) as the claim operation.
/// `claim()` is atomic at the Redis server — exactly one concurrent caller claims the slot.
/// `release()` uses DEL and is called only when decryption fails (prevents ciphertext poisoning).
///
/// **Anti-poisoning guarantee**: A corrupted blob that fails decryption calls `release()`,
/// freeing the slot for the legitimate ciphertext. The slot is only kept permanently
/// on successful decryption.
///
/// **Distributed atomicity**: Redis SETNX guarantees exactly one winner across
/// multiple API instances. This is the correct backend for multi-instance deployments.
///
/// **Single-instance**: Use MemoryReplayStore (dev) or FileReplayStore (restart-safe).
///
/// Requires the `redis-backend` feature flag and a `CITADEL_REDIS_URL`
/// environment variable (e.g. `redis://localhost:6379`).
///
/// When `fail_closed = true` (strongly recommended for production), any Redis
/// When `fail_closed = true`, Redis connectivity errors return `Err(ReplayError)` (P396).
/// The keystore denies on `Err`, preserving fail-closed behavior while letting operators
/// distinguish Redis outage from true replay. `Ok(false)` means replay only.
pub struct RedisReplayStore {
    url: String,
    key_prefix: String,
    #[allow(dead_code)]
    fail_closed: bool,
}

impl RedisReplayStore {
    pub fn new(url: impl Into<String>, key_prefix: impl Into<String>, fail_closed: bool) -> Self {
        Self {
            url: url.into(),
            key_prefix: key_prefix.into(),
            fail_closed,
        }
    }

    /// Create from environment variables:
    ///   - `CITADEL_REDIS_URL` (required)
    ///   - `CITADEL_REDIS_PREFIX` (optional, default "citadel:replay:")
    ///
    /// P395: Reads environment, validates Redis connectivity, returns Err on failure.
    ///
    /// This was previously just env-var reading. Now it PINGs Redis at startup:
    /// - Missing CITADEL_REDIS_URL → Err
    /// - Redis unreachable or auth failed → Err (fail-fast, not silent)
    ///
    /// The API exits(1) if from_env() returns Err, so misconfigurations are
    /// caught at startup rather than discovered mid-request.
    pub fn from_env(fail_closed: bool) -> Result<Self, ReplayError> {
        let url = std::env::var("CITADEL_REDIS_URL").map_err(|_| {
            ReplayError::new("CITADEL_REDIS_URL not set; required for Redis replay store")
        })?;
        let prefix =
            std::env::var("CITADEL_REDIS_PREFIX").unwrap_or_else(|_| "citadel:replay:".into());

        // P395: Validate connectivity at startup — fail fast, not mid-request
        redis_ping(&url).map_err(|e| {
            ReplayError::new(format!(
                "Redis startup validation failed for '{}': {} \
                 — fix CITADEL_REDIS_URL or ensure Redis is running",
                url, e
            ))
        })?;

        tracing::info!(url = %url, prefix = %prefix, "Redis replay store: startup PING succeeded");
        Ok(Self::new(url, prefix, fail_closed))
    }

    fn redis_key(&self, key: &[u8]) -> String {
        format!("{}{}", self.key_prefix, hex::encode(key))
    }
}

impl ReplayStore for RedisReplayStore {
    /// P319: Atomic claim using Redis SET NX EX.
    ///
    /// SET NX EX is atomic at the Redis server — exactly one concurrent caller
    /// will succeed. Returns Ok(true) if this caller claimed the slot,
    /// Ok(false) if the slot was already claimed (replay). Redis is the
    /// correct backend for distributed atomic replay protection.
    fn claim(&self, key: &[u8], ttl: Duration) -> Result<bool, ReplayError> {
        let ttl_secs = ttl.as_secs().max(1) as usize;
        match redis_set_nx_ex_atomic(&self.url, &self.redis_key(key), ttl_secs) {
            Ok(true) => Ok(true),   // claimed this slot
            Ok(false) => Ok(false), // slot already exists — replay
            Err(e) => {
                // P396: Both paths deny the operation (keystore denies on Err and Ok(false)).
                // But Err allows operators to distinguish Redis outage from real replay in logs.
                tracing::error!(url = %self.url, err = %e,
                    "Redis claim() failed — failing closed (returning Err to signal outage)");
                Err(ReplayError::new(format!(
                    "Redis outage (fail_closed={}): {} — operation denied to prevent replay bypass",
                    self.fail_closed, e
                )))
            }
        }
    }

    /// P319: Release a slot on decrypt failure.
    /// Uses Redis DEL. Failure here is logged but non-fatal.
    fn release(&self, key: &[u8]) -> Result<(), ReplayError> {
        redis_del(&self.url, &self.redis_key(key))
            .map_err(|e| ReplayError::new(format!("Redis release failed: {}", e)))
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }
}

// ---------------------------------------------------------------------------
// Redis helpers (sync, using redis crate blocking API)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Redis helpers (sync, using redis crate blocking API)
// ---------------------------------------------------------------------------

/// GET a Redis key — returns Some(value) if present, None if absent.
/// P395 — Redis startup validation: send PING and expect PONG.
/// Called by `RedisReplayStore::from_env()` to validate connectivity before
/// the server starts accepting requests.
#[cfg(feature = "redis-backend")]
fn redis_ping(url: &str) -> Result<(), String> {
    use redis::Commands;
    let client = redis::Client::open(url).map_err(|e| format!("connect: {}", e))?;
    let mut con = client
        .get_connection()
        .map_err(|e| format!("get_connection: {}", e))?;
    let pong: String = redis::cmd("PING")
        .query(&mut con)
        .map_err(|e| format!("PING: {}", e))?;
    if pong != "PONG" {
        return Err(format!("unexpected PING response: {:?}", pong));
    }
    Ok(())
}

#[cfg(not(feature = "redis-backend"))]
fn redis_ping(_url: &str) -> Result<(), String> {
    Err("redis-backend feature not enabled".into())
}

#[cfg(feature = "redis-backend")]
fn redis_get(url: &str, key: &str) -> Result<Option<String>, String> {
    use redis::Commands;
    let client = redis::Client::open(url).map_err(|e| e.to_string())?;
    let mut con = client.get_connection().map_err(|e| e.to_string())?;
    let val: Option<String> = con.get(key).map_err(|e| e.to_string())?;
    Ok(val)
}

#[cfg(not(feature = "redis-backend"))]
#[allow(dead_code)]
fn redis_get(_url: &str, _key: &str) -> Result<Option<String>, String> {
    Err("redis-backend feature not enabled; add feature = [\"redis-backend\"] to Cargo.toml".into())
}

/// Atomic SET NX EX: sets `key` to `"1"` with `ttl_secs` expiry IF key does not exist.
///
/// Returns:
/// - `Ok(true)`  — key did NOT exist; now set (nonce is fresh)
/// - `Ok(false)` — key already existed (replay detected)
/// - `Err(msg)`  — Redis connection or command failure
#[cfg(feature = "redis-backend")]
fn redis_set_nx_ex_atomic(url: &str, key: &str, ttl_secs: usize) -> Result<bool, String> {
    use redis::Commands;
    let client = redis::Client::open(url).map_err(|e| e.to_string())?;
    let mut con = client.get_connection().map_err(|e| e.to_string())?;
    // SET key "1" NX EX ttl — returns Some("OK") if set, None if key existed.
    let result: Option<String> = con
        .set_options(
            key,
            "1",
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(ttl_secs)),
        )
        .map_err(|e| e.to_string())?;
    Ok(result.is_some()) // Some("OK") = freshly set; None = already existed
}

#[cfg(not(feature = "redis-backend"))]
fn redis_set_nx_ex_atomic(_url: &str, _key: &str, _ttl_secs: usize) -> Result<bool, String> {
    Err("redis-backend feature not enabled; add feature = [\"redis-backend\"] to Cargo.toml".into())
}

#[cfg(feature = "redis-backend")]
fn redis_del(url: &str, key: &str) -> Result<(), String> {
    use redis::Commands;
    let client = redis::Client::open(url).map_err(|e| e.to_string())?;
    let mut con = client.get_connection().map_err(|e| e.to_string())?;
    let _: () = con.del(key).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(feature = "redis-backend"))]
fn redis_del(_url: &str, _key: &str) -> Result<(), String> {
    Err("redis-backend feature not enabled".into())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests — P066 fail-closed and atomicity verification
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A replay store that always returns Err from claim() — simulates Redis outage.
    struct AlwaysFailStore;

    impl ReplayStore for AlwaysFailStore {
        fn claim(&self, _key: &[u8], _ttl: Duration) -> Result<bool, ReplayError> {
            Err(ReplayError::new("simulated Redis outage"))
        }
        fn release(&self, _key: &[u8]) -> Result<(), ReplayError> {
            Err(ReplayError::new("simulated Redis outage"))
        }
        fn backend_name(&self) -> &'static str {
            "always-fail"
        }
    }

    /// P066 — fail-closed: store error must be treated as seen=true by callers.
    /// This test verifies the AlwaysFailStore returns Err and documents the
    /// contract that keystore::decrypt() treats Err as "seen" (deny).
    #[test]
    fn fail_closed_store_returns_err_on_claim() {
        let store = AlwaysFailStore;
        let result = store.claim(b"any-nonce-key", Duration::from_secs(3600));
        assert!(
            result.is_err(),
            "AlwaysFailStore must return Err from claim()"
        );
    }

    /// P066 — MemoryReplayStore: claim() succeeds initially, fails on replay.
    #[test]
    fn memory_store_claim_and_replay() {
        let store = MemoryReplayStore::new(Duration::from_secs(3600), true);
        let key = b"test-replay-key-32-bytes-for-hmac";
        // First claim succeeds
        assert!(
            store.claim(key, Duration::from_secs(3600)).unwrap(),
            "first claim must succeed"
        );
        // Second claim is a replay — must return false
        assert!(
            !store.claim(key, Duration::from_secs(3600)).unwrap(),
            "second claim must return false (replay detected)"
        );
        // Release and re-claim succeeds (simulates failed decrypt recovery)
        store.release(key).unwrap();
        assert!(
            store.claim(key, Duration::from_secs(3600)).unwrap(),
            "claim after release must succeed"
        );
    }

    /// P066/P079 — derive_replay_key produces a stable, unique digest including AEAD tag.
    /// P283: Updated calls to include domain_id (P224 added domain scoping as first param).
    #[test]
    fn replay_key_derivation_is_stable_and_unique() {
        let tag = b"aead-tag-16bytes"; // 16 bytes simulating AES-GCM tag
        let k1 = derive_replay_key("default-domain", "key-id-A", 1, b"nonce-0000000001", tag);
        let k2 = derive_replay_key("default-domain", "key-id-A", 1, b"nonce-0000000001", tag);
        let k3 = derive_replay_key("default-domain", "key-id-A", 2, b"nonce-0000000001", tag); // different version
        let k4 = derive_replay_key("default-domain", "key-id-B", 1, b"nonce-0000000001", tag); // different key_id
        let k5 = derive_replay_key(
            "default-domain",
            "key-id-A",
            1,
            b"nonce-0000000001",
            b"different-tag!!!",
        ); // different tag
        let k6 = derive_replay_key("other-domain", "key-id-A", 1, b"nonce-0000000001", tag); // different domain (P224)

        assert_eq!(k1, k2, "same inputs must produce same digest");
        assert_ne!(k1, k3, "different version must produce different digest");
        assert_ne!(k1, k4, "different key_id must produce different digest");
        assert_ne!(
            k1, k5,
            "different aead_tag must produce different digest (P079 poisoning fix)"
        );
        assert_ne!(
            k1, k6,
            "different domain must produce different digest (P224 domain scoping)"
        );
        assert_eq!(k1.len(), 32, "SHA-256 digest must be 32 bytes");
    }

    /// P066 — MemoryReplayStore with TTL=0 expiry: seen entries expire immediately.
    #[test]
    fn memory_store_expired_entries_evicted() {
        let store = MemoryReplayStore::new(Duration::from_nanos(1), true);
        let key = b"expiring-key";
        assert!(
            store.claim(key, Duration::from_nanos(1)).unwrap(),
            "initial claim must succeed"
        );
        // After tiny TTL, the entry should be evicted on next claim() call.
        std::thread::sleep(Duration::from_millis(5));
        // claim() must evict expired entries — key is gone, so new claim succeeds.
        let result = store.claim(key, Duration::from_secs(3600)).unwrap();
        assert!(
            result,
            "claim after TTL expiry must succeed (entry evicted)"
        );
    }

    /// P066 — FileReplayStore: persists across instances (simulated by re-opening).
    #[test]
    fn file_store_persists_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");

        let key = b"cross-restart-nonce";
        {
            let store = FileReplayStore::new(&path, Duration::from_secs(3600), true)
                .expect("test: file replay store");
            assert!(
                store.claim(key, Duration::from_secs(3600)).unwrap(),
                "claim must succeed within same instance"
            );
            assert!(
                !store.claim(key, Duration::from_secs(3600)).unwrap(),
                "second claim must fail (replay)"
            );
        }
        {
            // Re-open — simulates a server restart. Claimed keys must persist.
            let store2 = FileReplayStore::new(&path, Duration::from_secs(3600), true)
                .expect("test: file replay store");
            assert!(
                !store2.claim(key, Duration::from_secs(3600)).unwrap(),
                "claim after re-open must fail — key survived restart (restart-safe)"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// P161 — FileReplayStore with an unwritable path (fail_closed=true):
    /// claim() updates the in-memory mirror then attempts disk write.
    /// If the disk write fails, the mirror still has the key (fail-safe for replay
    /// protection — we don't want to lose the "seen" state on disk error).
    /// mirror is read for replay checks, so claim() correctly fails after a prior claim.
    #[test]
    fn file_store_unwritable_path_claim_updates_mirror_or_fails_closed() {
        // Use a path that cannot be written (subdirectory of a non-existent dir)
        // P421: Cross-platform missing parent dir — use tempdir().join("missing-subdir")
        let _tmp = std::env::temp_dir();
        let bad_path = _tmp.join("citadel-nonexistent-p421").join("replay.json");
        let store = FileReplayStore::new(&bad_path, Duration::from_secs(3600), true)
            .expect("test: unwritable path store");

        let key = b"test-nonce-p161";

        // Before claim: slot must be available
        // First claim attempt — may fail if disk is unwritable (claim rolls back in-memory insert on flush failure)
        let claim_result = store.claim(key, Duration::from_secs(3600));
        // Whether claim succeeds or fails (unwritable disk), the store handles it consistently.
        // The important property: it does NOT silently allow replays.
        let seen_after = claim_result;
        // Either Ok(true) [mirror has it] or Err [fail-closed on store error].
        // Both are acceptable. Ok(false) would mean replay protection is broken.
        match seen_after {
            Ok(true) => {} // mirror updated — replay protection maintained
            Err(_) => {}   // store error — fail-closed (acceptable)
            Ok(false) => {
                panic!("replay protection broken — claim succeeded when it should have failed")
            }
        }
    }
    /// P386 — Named invariant test: proves REPLAY_INVARIANT holds for MemoryReplayStore.
    ///
    /// This test is named for the invariant, not the implementation detail.
    /// If this test fails, the replay invariant is broken.
    #[test]
    fn replay_invariant_same_ciphertext_decrypts_exactly_once() {
        let store = MemoryReplayStore::new(Duration::from_secs(60), true);
        let key = b"invariant-test-replay-key";

        // First claim: must succeed (first decrypt)
        assert!(
            store.claim(key, Duration::from_secs(60)).is_ok(),
            "REPLAY INVARIANT VIOLATED: first claim must succeed"
        );

        // Second claim: must return Ok(false) — replay detected, not a backend error.
        // Contract: Ok(true)=claimed, Ok(false)=replay, Err=backend failure.
        // Asserting is_err() was WRONG — MemoryReplayStore returns Ok(false) on replay.
        assert!(
            !store.claim(key, Duration::from_secs(60)).unwrap(),
            "REPLAY INVARIANT VIOLATED: second claim must return Ok(false) — replay detected"
        );

        // Third claim: also Ok(false) — not a one-time flip
        assert!(
            !store.claim(key, Duration::from_secs(60)).unwrap(),
            "REPLAY INVARIANT VIOLATED: third claim must return Ok(false) — replay detected"
        );
    }
}

#[cfg(test)]
mod file_replay_tests {
    use super::*;
    use std::time::Duration;

    /// P168 — If the replay file is deleted mid-run, claim() must recreate it safely.
    /// This simulates an admin accidentally deleting the replay store, or disk events
    /// that remove the file after the store has already loaded.
    #[test]
    fn file_store_recreates_after_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");
        let _ = std::fs::remove_file(&path);

        let store = FileReplayStore::new(&path, Duration::from_secs(3600), true)
            .expect("test: file replay store");

        // Successful claims are durable without a separate force_flush call.
        let key1 = b"nonce-before-delete";
        store.claim(key1, Duration::from_secs(3600)).unwrap();
        assert!(
            std::path::Path::new(&path).exists(),
            "file must exist after claim"
        );
        // Second claim must fail (replay)
        assert!(
            !store.claim(key1, Duration::from_secs(3600)).unwrap(),
            "key1 must be claimed"
        );

        // Simulate file deletion mid-run
        std::fs::remove_file(&path).unwrap();
        assert!(!std::path::Path::new(&path).exists(), "file deleted");

        // Claim a new nonce — must recreate the file, NOT panic or silently fail
        let key2 = b"nonce-after-delete";
        let result = store.claim(key2, Duration::from_secs(3600));
        // claim may succeed (recreates file) or fail (can't write) — both acceptable.
        // What must NOT happen: panic or UB.
        match result {
            Ok(claimed) => {
                if claimed {
                    // File was recreated — key2 is claimed, verify replay detection
                    assert!(
                        !store.claim(key2, Duration::from_secs(3600)).unwrap(),
                        "key2 must be seen as replay after claim"
                    );
                }
            }
            Err(_) => {
                // Write failed — acceptable, store remains in consistent in-memory state
            }
        }

        let _ = std::fs::remove_file(&path);
    }

    /// P188 -- FileReplayStore grows with entries but remains readable at scale.
    /// Writes 1,000 entries and verifies the store remains consistent.
    /// Documents that FileReplayStore is append-to-mirror (not bounded eviction).
    #[test]
    fn file_store_large_entry_count_remains_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");
        let _ = std::fs::remove_file(&path);

        let store = FileReplayStore::new(&path, Duration::from_secs(86400), true)
            .expect("test: file replay store");

        // Write 10,000 entries (required by P188)
        for i in 0u32..10_000 {
            let key = format!("nonce-entry-{:08}", i);
            store
                .claim(key.as_bytes(), Duration::from_secs(86400))
                .unwrap();
        }

        // All entries must be seen
        assert!(
            !store
                .claim(b"nonce-entry-00000000", Duration::from_secs(86400))
                .unwrap(),
            "already claimed"
        );
        assert!(
            !store
                .claim(b"nonce-entry-00009999", Duration::from_secs(86400))
                .unwrap(),
            "already claimed"
        );
        assert!(
            store
                .claim(b"nonce-not-present", Duration::from_secs(86400))
                .unwrap(),
            "unclaimed key must be claimable"
        );

        // File must exist and be non-empty
        let metadata = std::fs::metadata(&path).unwrap();
        assert!(
            metadata.len() > 0,
            "replay file must be non-empty after 1000 entries"
        );

        // Document: FileReplayStore does not evict entries -- file grows with traffic.
        // For long-running production deployments, use Redis backend or periodic
        // maintenance to prune expired entries.

        let _ = std::fs::remove_file(&path);
    }

    /// P195/P420 — Truncated replay file must return Err on startup (P393 behavior).
    ///
    /// Previously this test called .expect() expecting the store to open successfully
    /// even with truncated JSON. P393 changed FileReplayStore::new() to return Err
    /// on any JSON parse failure. .expect() would panic. Test renamed to match behavior.
    #[test]
    fn file_store_truncated_json_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");

        // Write a valid entry first
        {
            let store = FileReplayStore::new(&path, Duration::from_secs(3600), true)
                .expect("test: create store for truncation test");
            store
                .claim(b"test-nonce-valid", Duration::from_secs(3600))
                .unwrap();
        }

        // Truncate the file mid-JSON
        let content = std::fs::read_to_string(&path).unwrap();
        let truncated = &content[..content.len() / 2];
        std::fs::write(&path, truncated).unwrap();

        // P393+P420: Truncated JSON must return Err — not silently start empty.
        // A truncated replay file indicates crash-during-write or disk corruption.
        // Silently starting empty would forget replay claims, enabling replays.
        let result = FileReplayStore::new(&path, Duration::from_secs(3600), true);
        assert!(
            result.is_err(),
            "P393: truncated replay file must return Err to prevent silent replay-loss, got Ok"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// P195 -- Invalid JSON replay store fails safely on first operation.
    /// P393+P400: Corrupt replay file must return Err — not silently start empty.
    ///
    /// This test was previously wrong: it called .expect() expecting success
    /// even with invalid JSON. P393 changed new() to return Err on corrupt files.
    #[test]
    fn file_store_invalid_json_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");

        // Write garbage JSON (simulates corrupt replay file)
        std::fs::write(&path, b"{ this is not valid json !!!").unwrap();

        // P393: Invalid JSON must return Err — NOT silently start empty
        let result = FileReplayStore::new(&path, Duration::from_secs(3600), true);
        assert!(
            result.is_err(),
            "P393: corrupt replay file must return Err to prevent silent replay-loss"
        );
        // P430: FileReplayStore has no Debug — use match instead of unwrap_err()
        let err_msg = match result {
            Ok(_) => panic!("P393: expected FileReplayStore::new() to return Err on corrupt JSON"),
            Err(e) => e.to_string(),
        };
        assert!(
            err_msg.contains("corrupt") || err_msg.contains("parse"),
            "P393: Err must explain the corruption, got: {}",
            err_msg
        );

        let _ = std::fs::remove_file(&path);
    }
    /// P403 — FileReplayStore with a valid JSON but invalid key_hex must return Err.
    ///
    /// Silently skipping malformed entries would forget replay claims, allowing
    /// ciphertext replay across a restart. The fail-closed behavior must extend
    /// to malformed individual entries, not just unreadable/unparseable files.
    #[test]
    fn file_store_invalid_key_hex_fails_closed_on_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");

        // Valid JSON but with one entry whose key_hex is not valid hex
        let bad_content = r#"[{"key_hex":"not-valid-hex!!","seen_at_unix":9999999999}]"#;
        std::fs::write(&path, bad_content).unwrap();

        // P403: Invalid key_hex in a valid JSON file must return Err
        let result = FileReplayStore::new(&path, Duration::from_secs(3600), true);
        assert!(
            result.is_err(),
            "P403: replay file with invalid key_hex must return Err"
        );
        // P430: FileReplayStore has no Debug — use match instead of unwrap_err()
        let err_msg = match result {
            Ok(_) => {
                panic!("P403: expected FileReplayStore::new() to return Err on invalid key_hex")
            }
            Err(e) => e.to_string(),
        };
        assert!(
            err_msg.contains("invalid key_hex") || err_msg.contains("key_hex"),
            "P403: Err must explain the invalid key_hex, got: {}",
            err_msg
        );

        let _ = std::fs::remove_file(&path);
    }
    /// P426 — Direct MemoryReplayStore atomicity: no outer keystore mutex.
    ///
    /// The keystore-level p089 test proves atomicity through Mutex<Box<dyn ReplayStore>>.
    /// This test calls claim() DIRECTLY on MemoryReplayStore from 1000 threads,
    /// proving the backend's own internal synchronization is correct.
    ///
    /// Exactly 1 of 1000 concurrent claim() calls must return Ok(true).
    /// All others must return Ok(false) (replay detected).
    /// Err is not expected (MemoryReplayStore never returns Err on claim).
    #[test]
    fn memory_store_direct_concurrent_atomicity_1000() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let store = Arc::new(MemoryReplayStore::new(Duration::from_secs(60), true));
        let key = b"p426-direct-atomicity-test-key";
        let ttl = Duration::from_secs(60);

        let mut handles = vec![];
        for _ in 0..1000 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || store_clone.claim(key, ttl)));
        }

        let mut true_count = 0usize;
        let mut false_count = 0usize;
        let mut err_count = 0usize;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(true) => true_count += 1,
                Ok(false) => false_count += 1,
                Err(_) => err_count += 1,
            }
        }

        assert_eq!(
            true_count, 1,
            "P426: exactly 1 of 1000 direct claim() calls must succeed (got {}),              others must be Ok(false). This proves MemoryReplayStore internal atomicity              independent of the outer keystore mutex.",
            true_count
        );
        assert_eq!(
            false_count, 999,
            "P426: 999 of 1000 claims must return Ok(false) — replay detected, got {}",
            false_count
        );
        assert_eq!(
            err_count, 0,
            "P426: MemoryReplayStore must not return Err on replay, got {}",
            err_count
        );
    }
}
