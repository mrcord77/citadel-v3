// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Core types: KeyId, KeyType, KeyState, KeyMetadata, KeyVersion.
//!
//! V2 changes:
//! - `SecretKeyMaterial::CitadelWrapped` — new variant for KEK-hierarchy wrapping.
//! - `KeyVersion::wrapping_key_version` — records which version of the parent KEK
//!   was used when wrapping, enabling correct unwrap after KEK rotation.
//!
//! V3 additions (P361 — ML-DSA-65 signing):
//! - `KeyType::Signing` — ML-DSA-65 signing keypair. Wrapped by Kek.
//!   Secret material stored as 32-byte seed hex (CitadelWrapped by parent KEK).
//!   Public key stored as 1952-byte verifying key hex in `public_key_hex`.
//!   Signing keys are NOT used with the replay store (signatures are not one-time-use).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Key identifiers
// ---------------------------------------------------------------------------

/// Unique key identifier (hex-encoded random bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new random KeyId.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Create from a specific string (for testing/deterministic use).
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

use rand_core::RngCore;

/// Policy identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Key classification
// ---------------------------------------------------------------------------

/// Position in the key hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Root key — offline, protects the entire hierarchy.
    Root,
    /// Domain key — per-tenant or per-environment (maps to KeyRole::DomainKek).
    Domain,
    /// Key-encrypting key — wraps DEKs (maps to KeyRole::Kek).
    KeyEncrypting,
    /// Data-encrypting key — directly encrypts user data (maps to KeyRole::Dek).
    DataEncrypting,
    /// Hybrid identity key — V3 addition for authenticated key exchange
    /// (maps to KeyRole::HybridIdentityKey). Wrapped by a Kek.
    HybridIdentity,
    /// Signing key — P361 addition. Holds ML-DSA-65 (NIST FIPS 204) keypair.
    ///
    /// # Storage
    /// - `public_key_hex`: hex-encoded ML-DSA-65 verifying key (1952 bytes → 3904 hex chars)
    /// - `secret_key_material`: CitadelWrapped hex of the 32-byte ML-DSA-65 seed
    ///   (compact representation — full expanded signing key reconstructed on demand
    ///   via `MlDsa65::from_seed()`)
    ///
    /// # Hierarchy
    /// Wrapped by Kek (same as DataEncrypting and HybridIdentity).
    /// Must not be a parent (depth 6 in the hierarchy).
    ///
    /// # Replay protection
    /// NOT subject to the replay store. Signatures are not one-time-use.
    /// Applications that need one-time assertion semantics track assertion IDs themselves.
    Signing,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Root => write!(f, "ROOT"),
            KeyType::Domain => write!(f, "DOMAIN"),
            KeyType::KeyEncrypting => write!(f, "KEK"),
            KeyType::DataEncrypting => write!(f, "DEK"),
            KeyType::HybridIdentity => write!(f, "HYBRID-ID"),
            KeyType::Signing => write!(f, "SIGNING"),
        }
    }
}

// ---------------------------------------------------------------------------
// Key lifecycle state machine
// ---------------------------------------------------------------------------

/// Key lifecycle state.
///
/// ```text
/// PENDING → ACTIVE ↔ ROTATED → EXPIRED → DESTROYED
///             │         │
///             └──→ REVOKED  └──→ SUSPENDED (cascade from parent revoke)
///             │
///             └──→ SUSPENDED
/// ```
///
/// `Suspended` is set by `revoke_cascade()` on descendants of a revoked KEK.
/// It signals "parent is compromised — this key is operationally blocked"
/// without marking the key itself as individually compromised (Revoked).
/// Suspended keys can be restored by `rewrap()` under a healthy parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Generated but not yet activated.
    Pending,
    /// Active — can encrypt and decrypt.
    Active,
    /// Rotated — superseded by a new version. Can still decrypt (grace period).
    Rotated,
    /// Expired — can no longer encrypt or decrypt.
    Expired,
    /// Revoked — emergency deactivation. Cannot be reactivated.
    Revoked,
    /// Suspended — operationally blocked because a parent KEK was revoked.
    ///
    /// Set by `revoke_cascade()`. The key is not individually compromised;
    /// it is blocked because its wrapping chain is broken. Restore by
    /// `rewrap()` under a healthy parent, then re-activate.
    Suspended,
    /// Destroyed — key material has been purged.
    Destroyed,
}

impl KeyState {
    /// Whether this state allows encryption.
    pub fn can_encrypt(&self) -> bool {
        matches!(self, KeyState::Active)
    }

    /// Whether this state allows decryption.
    pub fn can_decrypt(&self) -> bool {
        matches!(self, KeyState::Active | KeyState::Rotated)
    }

    /// Valid transitions from this state.
    pub fn valid_transitions(&self) -> &[KeyState] {
        match self {
            KeyState::Pending => &[KeyState::Active, KeyState::Destroyed],
            KeyState::Active => &[
                KeyState::Rotated,
                KeyState::Revoked,
                KeyState::Expired,
                KeyState::Suspended,
            ],
            KeyState::Rotated => &[KeyState::Expired, KeyState::Suspended],
            KeyState::Suspended => &[KeyState::Active, KeyState::Destroyed],
            KeyState::Expired => &[KeyState::Destroyed],
            KeyState::Revoked => &[KeyState::Destroyed],
            KeyState::Destroyed => &[],
        }
    }

    /// Check if transitioning to `target` is valid.
    pub fn can_transition_to(&self, target: KeyState) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl fmt::Display for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyState::Pending => write!(f, "PENDING"),
            KeyState::Active => write!(f, "ACTIVE"),
            KeyState::Rotated => write!(f, "ROTATED"),
            KeyState::Expired => write!(f, "EXPIRED"),
            KeyState::Revoked => write!(f, "REVOKED"),
            KeyState::Suspended => write!(f, "SUSPENDED"),
            KeyState::Destroyed => write!(f, "DESTROYED"),
        }
    }
}

// ---------------------------------------------------------------------------
// Secret key material (typed, compile-time safe)
// ---------------------------------------------------------------------------

/// Typed representation of a stored secret key's material.
///
/// # Variants
///
/// - `Encrypted(s)` — AES-256-GCM wrapped using `CITADEL_MASTER_KEY`.
///   Format: `"enc:" + hex(nonce[12]) + hex(aes_gcm_ciphertext)`.
///   Used for Root and Domain keys (top of hierarchy, no parent KEK online).
///
/// - `CitadelWrapped(s)` — **V2 new.** Sealed using the parent KEK's Citadel
///   public key (hybrid X25519 + ML-KEM-768 envelope).
///   Format: `"ckw:" + hex(full_citadel_envelope_ciphertext)`.
///   Used for KEK and DEK keys whose parent is online in the keystore.
///   Unwrapping requires loading and decrypting the parent key first.
///
/// - `Plaintext(s)` — Plain hex-encoded secret key bytes.
///   **Development and test use only.** Never acceptable in production.
///
/// - `Destroyed` — Key material purged by `Keystore::destroy()`.
///
/// # Serialization
///
/// Serializes as a plain JSON string (backward compatible with V1):
/// - `Encrypted(s)`      → `s` (starts with `"enc:"`)
/// - `CitadelWrapped(s)` → `s` (starts with `"ckw:"`)
/// - `Plaintext(s)`      → `s` (hex string)
/// - `Destroyed`         → `"DESTROYED"`
#[derive(Clone, PartialEq)]
pub enum SecretKeyMaterial {
    /// AES-256-GCM encrypted at rest using CITADEL_MASTER_KEY.
    /// Format: `"enc:" + hex(nonce[12]) + hex(aes_gcm_ciphertext)`.
    Encrypted(String),
    /// Sealed using parent KEK's Citadel hybrid public key (V2).
    /// Format: `"ckw:" + hex(full_citadel_ciphertext)`.
    /// Unwrap requires online parent key access and recursive decryption.
    CitadelWrapped(String),
    /// Plain hex-encoded secret key bytes.
    /// **Development and test use only.**
    Plaintext(String),
    /// Key material has been purged by `Keystore::destroy()`.
    Destroyed,
}

impl fmt::Debug for SecretKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypted(_) => f.write_str("Encrypted([REDACTED])"),
            Self::CitadelWrapped(_) => f.write_str("CitadelWrapped([REDACTED])"),
            Self::Plaintext(_) => f.write_str("Plaintext([REDACTED])"),
            Self::Destroyed => f.write_str("Destroyed"),
        }
    }
}

impl Drop for SecretKeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Encrypted(s) | Self::CitadelWrapped(s) | Self::Plaintext(s) => s.zeroize(),
            Self::Destroyed => {}
        }
    }
}

impl SecretKeyMaterial {
    /// Returns `true` if the material is AES-GCM encrypted with master key.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }
    /// Returns `true` if the material is wrapped by a Citadel parent key (V2 hierarchy).
    pub fn is_citadel_wrapped(&self) -> bool {
        matches!(self, Self::CitadelWrapped(_))
    }
    /// Returns `true` if the material is wrapped by any method (AES or Citadel).
    pub fn is_wrapped(&self) -> bool {
        self.is_encrypted() || self.is_citadel_wrapped()
    }
    /// Returns `true` if the material is plaintext (dev/test only).
    pub fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext(_))
    }
    /// Returns `true` if the key has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        matches!(self, Self::Destroyed)
    }

    /// Zeroize the inner key bytes (if any) and transition to `Destroyed`.
    pub fn zeroize_and_destroy(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Encrypted(s) | Self::CitadelWrapped(s) | Self::Plaintext(s) => s.zeroize(),
            Self::Destroyed => {}
        }
        *self = Self::Destroyed;
    }
}

impl serde::Serialize for SecretKeyMaterial {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Encrypted(v) | Self::CitadelWrapped(v) | Self::Plaintext(v) => s.serialize_str(v),
            Self::Destroyed => s.serialize_str("DESTROYED"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for SecretKeyMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if raw == "DESTROYED" {
            Ok(Self::Destroyed)
        } else if raw.starts_with("enc:") {
            Ok(Self::Encrypted(raw))
        } else if raw.starts_with("ckw:") {
            Ok(Self::CitadelWrapped(raw))
        } else {
            // Legacy plaintext hex — treat as Plaintext.
            Ok(Self::Plaintext(raw))
        }
    }
}

#[cfg(test)]
mod secret_material_tests {
    use super::SecretKeyMaterial;

    #[test]
    fn debug_never_exposes_key_material() {
        for material in [
            SecretKeyMaterial::Encrypted("enc:super-secret".into()),
            SecretKeyMaterial::CitadelWrapped("ckw:super-secret".into()),
            SecretKeyMaterial::Plaintext("super-secret".into()),
        ] {
            let rendered = format!("{material:?}");
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains("super-secret"));
        }
    }
}

// ---------------------------------------------------------------------------
// Key version (tracks rotation history)
// ---------------------------------------------------------------------------

/// A specific version of a key (created on generation or rotation).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVersion {
    /// Version number (1, 2, 3, ...).
    pub version: u32,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// Serialized public key bytes (hex).
    pub public_key_hex: String,
    /// Secret key material — one of four typed states:
    ///
    /// - `Encrypted(s)` — AES-GCM, uses CITADEL_MASTER_KEY.
    /// - `CitadelWrapped(s)` — Citadel envelope, uses parent KEK (V2 hierarchy).
    /// - `Plaintext(s)` — raw hex. **Dev/test only.**
    /// - `Destroyed` — material has been purged.
    ///
    /// The JSON field name is `"secret_key_hex"` for on-disk backward compatibility.
    #[serde(rename = "secret_key_hex")]
    pub secret_key_material: SecretKeyMaterial,

    /// ID of the key that wrapped this secret key material.
    ///
    /// - `None` = wrapped by CITADEL_MASTER_KEY (AES-256-GCM, external).
    /// - `Some(key_id)` = wrapped by a Citadel KEK in the keystore hierarchy.
    ///   The exact version of the parent key is stored in `wrapping_key_version`.
    #[serde(default)]
    pub wrapping_key_id: Option<String>,

    /// Which version of the wrapping KEK was used (V2 — enables correct unwrap
    /// after the parent KEK is rotated). `None` for AES-wrapped or plaintext keys.
    #[serde(default)]
    pub wrapping_key_version: Option<u32>,

    /// The AES-GCM nonce used when AES-wrapping this key (hex, 24 chars = 12 bytes).
    /// `None` for Citadel-wrapped, plaintext, or destroyed keys.
    #[serde(default)]
    pub wrap_nonce_hex: Option<String>,

    /// V3 formal wrapping mode. When `Some`, this is the authoritative source.
    /// When `None` (V2 key), use `wrapping_mode()` to derive from legacy fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapping_mode: Option<crate::hierarchy::WrappingMode>,
}

impl KeyVersion {
    /// Returns `true` if this version's secret key is wrapped by any method.
    pub fn is_wrapped(&self) -> bool {
        self.secret_key_material.is_wrapped()
    }

    /// Returns `true` if the material is AES-GCM wrapped with CITADEL_MASTER_KEY.
    pub fn is_aes_wrapped(&self) -> bool {
        self.secret_key_material.is_encrypted()
    }

    /// Returns the effective `WrappingMode` for this version (V3).
    ///
    /// If the `wrapping_mode` field is set (V3 key), returns it directly.
    /// Otherwise derives from legacy V2 fields for backward compatibility.
    pub fn effective_wrapping_mode(&self) -> crate::hierarchy::WrappingMode {
        if let Some(ref wm) = self.wrapping_mode {
            return wm.clone();
        }
        crate::hierarchy::WrappingMode::from_legacy(
            &self.wrapping_key_id,
            &self.wrapping_key_version,
            self.secret_key_material.is_citadel_wrapped(),
        )
    }

    /// Returns `true` if the material is Citadel-envelope wrapped by a parent KEK.
    pub fn is_citadel_wrapped(&self) -> bool {
        self.secret_key_material.is_citadel_wrapped()
    }

    /// Returns `true` if the material is plaintext (dev/test only).
    pub fn is_plaintext(&self) -> bool {
        self.secret_key_material.is_plaintext()
    }

    /// Returns `true` if this version's key material has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.secret_key_material.is_destroyed()
    }

    /// Validate internal consistency of this key version.
    pub fn validate(&self) -> Result<(), String> {
        match &self.secret_key_material {
            SecretKeyMaterial::Encrypted(_) => {
                if self.wrap_nonce_hex.is_none() {
                    return Err(format!(
                        "key version {} is AES-wrapped but wrap_nonce_hex is missing",
                        self.version
                    ));
                }
                if self.wrapping_key_id.is_some() {
                    return Err(format!(
                        "key version {} is AES-wrapped but has a wrapping_key_id (should be None)",
                        self.version
                    ));
                }
            }
            SecretKeyMaterial::CitadelWrapped(_) => {
                if self.wrapping_key_id.is_none() {
                    return Err(format!(
                        "key version {} is CitadelWrapped but wrapping_key_id is missing",
                        self.version
                    ));
                }
                if self.wrapping_key_version.is_none() {
                    return Err(format!(
                        "key version {} is CitadelWrapped but wrapping_key_version is missing",
                        self.version
                    ));
                }
                if self.wrap_nonce_hex.is_some() {
                    return Err(format!(
                        "key version {} is CitadelWrapped but wrap_nonce_hex should be None",
                        self.version
                    ));
                }
            }
            SecretKeyMaterial::Plaintext(_) | SecretKeyMaterial::Destroyed => {
                if self.wrap_nonce_hex.is_some() {
                    return Err(format!(
                        "key version {} is not AES-wrapped but wrap_nonce_hex is present",
                        self.version
                    ));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key metadata
// ---------------------------------------------------------------------------

/// Complete metadata for a managed key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier.
    pub id: KeyId,
    /// Human-readable name.
    pub name: String,
    /// Position in hierarchy.
    pub key_type: KeyType,
    /// Current lifecycle state.
    pub state: KeyState,
    /// Associated policy (if any).
    pub policy_id: Option<PolicyId>,
    /// Parent key in the hierarchy (None for root).
    pub parent_id: Option<KeyId>,
    /// When this key was first created.
    pub created_at: DateTime<Utc>,
    /// When the state last changed.
    pub updated_at: DateTime<Utc>,
    /// When the key was activated.
    pub activated_at: Option<DateTime<Utc>>,
    /// When the key was rotated (entered ROTATED state).
    pub rotated_at: Option<DateTime<Utc>>,
    /// When the key was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the key was destroyed.
    pub destroyed_at: Option<DateTime<Utc>>,
    /// All versions (current + historical).
    pub versions: Vec<KeyVersion>,
    /// Current (latest) version number.
    pub current_version: u32,
    /// Number of times this key has been used for encryption.
    pub usage_count: u64,
    /// Arbitrary metadata tags.
    pub tags: std::collections::HashMap<String, String>,
}

impl KeyMetadata {
    /// Get the current (latest) version.
    pub fn current_key_version(&self) -> Option<&KeyVersion> {
        self.versions
            .iter()
            .find(|v| v.version == self.current_version)
    }

    /// Get a specific version by number.
    pub fn get_version(&self, version: u32) -> Option<&KeyVersion> {
        self.versions.iter().find(|v| v.version == version)
    }

    /// Duration since activation (if activated).
    pub fn age(&self) -> Option<chrono::Duration> {
        self.activated_at.map(|a| Utc::now() - a)
    }

    /// The formal V3 role of this key in the hierarchy.
    pub fn role(&self) -> crate::hierarchy::KeyRole {
        crate::hierarchy::KeyRole::from(self.key_type)
    }
}
