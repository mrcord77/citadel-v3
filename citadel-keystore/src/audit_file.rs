// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Strict recovery of a single-writer JSONL audit chain. Existing bytes are never rewritten.

use super::{AuditEvent, ChainState, FileAuditSink, IntegrityChainSink};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, Mutex};

impl IntegrityChainSink {
    /// Validate the existing log, recover its tail, and continue appending.
    ///
    /// Missing/empty files start at genesis. Invalid JSON, missing chain fields,
    /// sequence gaps, bad links, or a partial final line cause an error. Old broken
    /// logs must be preserved and explicitly recovered; they are never reset here.
    /// This constructor is for one process owning the log, not shared writers.
    /// A local hash chain cannot detect replacement of the entire log or tail deletion
    /// without an independently trusted checkpoint.
    pub fn open_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = opts.open(path)?;
        let mut reader = BufReader::new(&file);
        let mut sequence = 0u64;
        let mut prev_hash = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            if !line.ends_with('\n') {
                return Err(invalid(sequence, "incomplete final record"));
            }
            let json = line.strip_suffix('\n').unwrap();
            let event: AuditEvent = serde_json::from_str(json)
                .map_err(|e| invalid(sequence, &format!("invalid event: {e}")))?;
            if event.sequence != Some(sequence) {
                return Err(invalid(sequence, "sequence gap or reset"));
            }
            if event.prev_hash.as_deref() != Some(prev_hash.as_str()) {
                return Err(invalid(sequence, "hash link mismatch"));
            }
            // Hash the exact stored bytes, matching the writer and CLI verifier.
            prev_hash = format!("{:x}", Sha256::digest(json.as_bytes()));
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid(sequence, "sequence exhausted"))?;
        }
        file.sync_all()?;
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            inner: Arc::new(FileAuditSink::new(path)),
            state: Mutex::new(ChainState {
                sequence,
                prev_hash,
                failed: false,
            }),
            witness: None,
            anchor_interval: 1000,
        })
    }
}

fn invalid(sequence: u64, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("audit record {sequence}: {reason}; preserve the log and recover explicitly"),
    )
}
