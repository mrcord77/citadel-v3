# Replay Protection Trust Boundaries

## Actual configuration

| Backend | Configuration | Durability boundary |
| --- | --- | --- |
| Memory | Explicit `CITADEL_ENV=development`, replay store unset | Process lifetime only |
| File | `CITADEL_REPLAY_STORE=file` | Every acknowledged claim synced before decryption proceeds |
| Redis | `CITADEL_REPLAY_STORE=redis`, feature enabled and URL configured | Depends on Redis persistence and failover configuration |

`CITADEL_REPLAY_BACKEND` and `CITADEL_REPLAY_FLUSH_MODE` are not configuration knobs
implemented by this API. Previous references to selectable batched/strict file modes
were inaccurate. The repaired file backend always persists claims synchronously.

## File-backed deployment

A claim is reserved under the mirror mutex, written to a temporary snapshot, synced,
renamed over the existing snapshot, and followed by parent-directory fsync on Unix.
Only then may decryption proceed. Replay attempts already present in memory are denied.
There is no need for subsequent traffic, an idle timer, or a destructor to save claims.

Tests cover normal SIGTERM shutdown after an idle interval and immediate SIGKILL after
a successful response. They do not simulate physical power failure or certify storage
hardware. The Unix durability claim assumes that the filesystem and device honor
sync operations. Windows process/crash behavior remains unverified here.

If a write fails, no successful claim is returned; uncertain claims stay reserved in
memory. If a failed-decrypt release cannot be persisted, its reservation is restored.
A crash between durable reservation and delivery of plaintext can consume a message
without the caller receiving it. This is an explicit safety/availability tradeoff.

The complete live set is rewritten per mutation. This increases I/O and serialization
cost versus batching; no throughput figure is promised. A future journal/transactional
backend must preserve durable-before-acknowledgment semantics.

## What this does not protect

- Multiple API processes sharing one replay file: no cross-process locking exists.
- Host compromise, file deletion, rollback to an older snapshot, or malicious editing.
- Loss of data that the underlying filesystem/device claimed was synchronized.
- Replay after expiration of the configured retention period.

A missing replay file initializes an empty store. Protect and back up the deployment's
state consistently; restoring key data with older replay state can allow reuse.

## Audit restart boundary

The API validates existing JSONL sequence/hash links before appending and resumes from
the verified tail. Malformed or incomplete records stop startup without rewriting the
log. Existing logs containing historical sequence resets need explicit recovery.

Audit appends are serialized and synced. Append failure is latched and reported by the
HTTP boundary as 503, including the health endpoint; successful response bodies are
withheld. Correct the storage problem and restart to validate the log before resuming.
A failed response does not guarantee that a key-state mutation has been rolled back:
key metadata and audit storage are not one atomic transaction.

A local hash chain cannot authenticate an entirely replaced log or detect deletion of
its tail without an independent trusted checkpoint. External anchoring and distributed
log ownership are outside this repair.
