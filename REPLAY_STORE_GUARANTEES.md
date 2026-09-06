# Citadel V3 — Replay Store Guarantees

A replay claim is atomic: `claim()` checks and reserves a fingerprint under one lock.
`Ok(true)` means the caller may proceed; `Ok(false)` means replay; `Err` means storage
failure and decryption must not proceed. A failed decrypt releases its claim.

## FileReplayStore

The file backend is single-process only. Every successful claim persists the complete
live snapshot to a temporary file, synchronizes it, atomically replaces `replay.json`,
and on Unix synchronizes the parent directory before returning. The destination is
never deleted before replacement. There is no batching or five-second idle window.

Acknowledged claims survive ordinary restart and abrupt process termination while
within the configured TTL, assuming a Unix filesystem/storage stack honoring fsync.
Power-loss durability depends on that storage contract; Windows crash durability has
not been verified by the Linux tests. SIGTERM/SIGINT handling drains active HTTP
requests, but replay durability does not depend on that handler or destructors.

A claim-write error is returned to the caller. Its in-memory reservation is retained
conservatively because a failed sync can leave an uncertain disk outcome. Release
errors restore the in-memory reservation. This favors replay safety over retry
availability. A process can also crash after persisting a claim but before returning
plaintext: that ciphertext remains consumed even if the caller received no response.

`force_flush()` remains available for compatibility; claim/release already persist
before returning. Rewriting the live snapshot and synchronizing each mutation costs
more than batching. Measure expected workload and storage latency before deployment.

### Startup and corruption

| Condition | Behavior |
| --- | --- |
| Missing file | Empty store, as on first startup |
| Invalid/truncated JSON | Startup error |
| Invalid key encoding in a live entry | Startup error |
| Read failure | Startup error |
| Write/sync/rename failure during claim | Error; plaintext not returned |

Missing files cannot be distinguished from a fresh deployment by this format.
Deleting or restoring an old replay file can erase claims; protect it accordingly.
Expired entries are removed from the memory mirror during claims and omitted from
persisted snapshots. The configured default TTL controls file entries.

Two processes must not share this file: the mutex is process-local, not a distributed
lock. Use a suitably configured distributed backend for multiple API instances.

## Memory and Redis

Memory replay protection is for explicit development/testing and disappears on restart.
Redis requires the `redis-backend` build feature and `CITADEL_REPLAY_STORE=redis`.
Its restart and failover guarantees depend on Redis persistence/replication settings.
This patch does not change or independently validate Redis behavior.

## Regression checks

- `cargo test -p citadel-keystore --test restart_durability --locked`
- `python3 scripts/security/restart_durability.py target/debug/citadel-api`

The HTTP check covers idle SIGTERM, immediate SIGKILL, storage errors, exactly-one
concurrent decrypt, and ordinary key/signature/domain behavior. Physical power-loss
and multi-process tests are outside these checks.
