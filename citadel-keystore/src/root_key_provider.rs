// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Root-key custody providers and the hardened local-pilot configuration gate.
//!
//! The Linux file provider is deliberately described as *filesystem-backed*:
//! it is exportable and its key is present in process memory while the keystore
//! is running. It is not an HSM, TPM, kernel keyring, or remote KMS.

#[cfg(target_os = "linux")]
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// A custody boundary capable of supplying the 256-bit root wrapping key.
pub trait RootKeyProvider: Send + Sync {
    /// Stable provider identifier for audit/configuration reporting.
    fn name(&self) -> &'static str;

    /// Load the key into zeroizing process memory.
    fn load_root_key(&self) -> Result<Zeroizing<[u8; 32]>, RootKeyError>;

    /// Truthful capability declaration; callers must not infer HSM properties.
    fn capabilities(&self) -> RootKeyCapabilities;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootKeyCapabilities {
    pub provider: &'static str,
    pub hardware_backed: bool,
    pub non_exportable: bool,
    pub owner_only_permissions_enforced: bool,
    pub symlink_rejected: bool,
}

#[derive(Debug)]
pub struct RootKeyError(String);

impl RootKeyError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RootKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RootKeyError {}

/// Owner-only raw 32-byte key file for a single-host Linux pilot.
#[derive(Clone, Debug)]
pub struct LinuxFileRootKeyProvider {
    path: PathBuf,
}

impl LinuxFileRootKeyProvider {
    /// Validate an existing provider file without retaining its key bytes.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RootKeyError> {
        let provider = Self {
            path: path.as_ref().to_path_buf(),
        };
        provider.load_root_key()?;
        Ok(provider)
    }

    /// Create a new provider file atomically; existing paths are never replaced.
    #[cfg(target_os = "linux")]
    pub fn create(path: impl AsRef<Path>) -> Result<Self, RootKeyError> {
        let path = path.as_ref();
        validate_parent(path)?;

        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| RootKeyError::new(format!("create {}: {e}", path.display())))?;
        file.write_all(key.as_ref())
            .and_then(|_| file.sync_all())
            .map_err(|e| RootKeyError::new(format!("write {}: {e}", path.display())))?;
        drop(file);
        Self::open(path)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(_path: impl AsRef<Path>) -> Result<Self, RootKeyError> {
        Err(RootKeyError::new(
            "linux-file-v1 root custody is only supported on Linux",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RootKeyProvider for LinuxFileRootKeyProvider {
    fn name(&self) -> &'static str {
        "linux-file-v1"
    }

    #[cfg(target_os = "linux")]
    fn load_root_key(&self) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
        validate_parent(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|e| RootKeyError::new(format!("open {}: {e}", self.path.display())))?;
        validate_open_file(&file, &self.path)?;

        let mut key = Zeroizing::new([0u8; 32]);
        file.read_exact(key.as_mut())
            .map_err(|e| RootKeyError::new(format!("read {}: {e}", self.path.display())))?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|e| RootKeyError::new(format!("read {}: {e}", self.path.display())))?
            != 0
        {
            return Err(RootKeyError::new(format!(
                "{} must contain exactly 32 raw bytes",
                self.path.display()
            )));
        }
        validate_key_material(key.as_ref())?;
        Ok(key)
    }

    #[cfg(not(target_os = "linux"))]
    fn load_root_key(&self) -> Result<Zeroizing<[u8; 32]>, RootKeyError> {
        Err(RootKeyError::new(
            "linux-file-v1 root custody is only supported on Linux",
        ))
    }

    fn capabilities(&self) -> RootKeyCapabilities {
        RootKeyCapabilities {
            provider: self.name(),
            hardware_backed: false,
            non_exportable: false,
            owner_only_permissions_enforced: true,
            symlink_rejected: true,
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_key_material(key: &[u8]) -> Result<(), RootKeyError> {
    let unique = key
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    if unique.len() < 16 {
        return Err(RootKeyError::new(
            "root-key material has insufficient byte diversity",
        ));
    }
    if key
        .windows(2)
        .map(|pair| pair[1].wrapping_sub(pair[0]))
        .all(|stride| stride == key[1].wrapping_sub(key[0]))
    {
        return Err(RootKeyError::new(
            "root-key material is an arithmetic byte sequence",
        ));
    }
    if (1..=16).any(|period| {
        key.iter()
            .enumerate()
            .all(|(i, byte)| *byte == key[i % period])
    }) {
        return Err(RootKeyError::new(
            "root-key material repeats with a short period",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, RootKeyError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| RootKeyError::new(format!("read /proc/self/status: {e}")))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| RootKeyError::new("effective UID is unavailable"))?;
    line.split_whitespace()
        .nth(2)
        .ok_or_else(|| RootKeyError::new("effective UID is malformed"))?
        .parse()
        .map_err(|e| RootKeyError::new(format!("effective UID is malformed: {e}")))
}

#[cfg(target_os = "linux")]
fn validate_parent(path: &Path) -> Result<(), RootKeyError> {
    let parent = path
        .parent()
        .ok_or_else(|| RootKeyError::new("root-key path has no parent directory"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|e| RootKeyError::new(format!("inspect {}: {e}", parent.display())))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RootKeyError::new(format!(
            "{} must be a real directory, not a symlink",
            parent.display()
        )));
    }
    let mode = metadata.mode() & 0o7777;
    let sticky_world_writable = mode & 0o1000 != 0 && mode & 0o002 != 0;
    if mode & 0o022 != 0 && !sticky_world_writable {
        return Err(RootKeyError::new(format!(
            "{} is group/world writable (mode {:o})",
            parent.display(),
            mode
        )));
    }
    let euid = effective_uid()?;
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(RootKeyError::new(format!(
            "{} owner {} is neither effective uid {} nor root",
            parent.display(),
            metadata.uid(),
            euid
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_open_file(file: &File, path: &Path) -> Result<(), RootKeyError> {
    let metadata = file
        .metadata()
        .map_err(|e| RootKeyError::new(format!("inspect {}: {e}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(RootKeyError::new(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 || mode & 0o400 == 0 {
        return Err(RootKeyError::new(format!(
            "{} must be owner-readable with no group/world permissions, found {:04o}",
            path.display(),
            mode
        )));
    }
    let euid = effective_uid()?;
    if metadata.uid() != euid {
        return Err(RootKeyError::new(format!(
            "{} must be owned by effective uid {}, found {}",
            path.display(),
            euid,
            metadata.uid()
        )));
    }
    if metadata.len() != 32 {
        return Err(RootKeyError::new(format!(
            "{} must contain exactly 32 raw bytes, found {}",
            path.display(),
            metadata.len()
        )));
    }
    if metadata.nlink() != 1 {
        return Err(RootKeyError::new(format!(
            "{} must have exactly one hard link, found {}",
            path.display(),
            metadata.nlink()
        )));
    }
    Ok(())
}

/// Validated startup inputs for the deliberately narrow single-host pilot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPilotConfig {
    pub root_key_file: PathBuf,
    pub replay_store: String,
}

impl LocalPilotConfig {
    pub fn from_env() -> Result<Self, RootKeyError> {
        Self::validate_pairs(std::env::vars())
    }

    pub fn validate_pairs<I, K, V>(pairs: I) -> Result<Self, RootKeyError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let values: HashMap<String, String> = pairs
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        if values.get("CITADEL_PROFILE").map(String::as_str) != Some("local-pilot") {
            return Err(RootKeyError::new(
                "local pilot requires CITADEL_PROFILE=local-pilot",
            ));
        }
        for forbidden in [
            "CITADEL_MASTER_KEY",
            "CITADEL_ALLOW_PLAINTEXT_KEYS",
            "CITADEL_ALLOW_FLAT_DEKS",
            "CITADEL_API_KEY",
        ] {
            if values.contains_key(forbidden) {
                return Err(RootKeyError::new(format!(
                    "{forbidden} is forbidden in local-pilot mode"
                )));
            }
        }
        if values.get("CITADEL_ENV").map(String::as_str) == Some("development") {
            return Err(RootKeyError::new(
                "CITADEL_ENV=development is forbidden in local-pilot mode",
            ));
        }
        let root_key_file = values
            .get("CITADEL_ROOT_KEY_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| RootKeyError::new("CITADEL_ROOT_KEY_FILE is required"))?;
        let replay_store = values
            .get("CITADEL_REPLAY_STORE")
            .filter(|value| matches!(value.as_str(), "file" | "redis"))
            .cloned()
            .ok_or_else(|| {
                RootKeyError::new("local pilot requires CITADEL_REPLAY_STORE=file or redis")
            })?;
        Ok(Self {
            root_key_file,
            replay_store,
        })
    }
}
