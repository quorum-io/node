# DIAGON v0.9.6

**Collective Consciousness Protocol**

*"Consensus, sharing, collective truth"*

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security](#security)
4. [Network Protocol](#network-protocol)
5. [S-Expression Format](#s-expression-format)
6. [Content Sharing](#content-sharing)
7. [Direct Messages](#direct-messages)
8. [DHT Discovery](#dht-discovery)
9. [Governance](#governance)
10. [Witness System](#witness-system)
11. [XP System](#xp-system)
12. [Commands](#commands)
13. [Configuration](#configuration)
14. [Usage](#usage)
15. [Testing](#testing)
16. [Dependencies](#dependencies)

---

## Overview

P2P governance and content sharing. Nodes form authenticated mesh networks within pools (trust domains), propose/vote on expressions via quorum sensing, share E2E encrypted DMs, discover pools via DHT, maintain replicated content-addressed stores with automatic decay.

### Core Principles

- **Homoiconicity**: Code is data, data is code
- **Content-addressing**: Expression IS its identity
- **Quorum sensing**: Accumulate signals, threshold triggers
- **Derived state**: Store expressions, compute results
- **Post-quantum**: Dilithium3 signatures throughout
- **Consent-based**: Human-in-the-loop for connections/DMs
- **Witnessed presence**: Acknowledgment requires attended time

### Features

| Category | Features |
|----------|----------|
| **Identity** | Post-quantum Dilithium3, DID-based |
| **Consensus** | 67% weighted quorum, time-decaying votes |
| **Content** | 262KB chunks, 7-day decay, pin/prune governance |
| **Messaging** | E2E encrypted (X25519 + ChaCha20Poly1305), consent required |
| **Discovery** | DHT via rendezvous network |
| **Threading** | Reply chains with tree display |
| **Engagement** | XP with view tracking and cooldowns |
| **Witnessing** | Acknowledgment (intra-pool), Testimony (inter-pool) |
| **Connection** | Reciprocal elaboration, mutual approval |
| **Security** | Rate limiting, replay protection, self-vote prevention |

---

## Architecture

### Identity

| Component | Description |
|-----------|-------------|
| DID | `did:diagon:<hex(pubkey[0:16])>` |
| Keypair | Dilithium3 (~2KB public key) |
| Verification | DID-pubkey binding at handshake |
| Persistence | CBOR to `<db_path>/state.cbor` |

### Cryptography

| Algorithm | Purpose |
|-----------|---------|
| Dilithium3 | Signatures (post-quantum) |
| SHA-256 | Content addressing |
| Argon2id | Pool passphrase (64MB, 3 iter, 4 threads) |
| X25519 | DM key exchange |
| ChaCha20Poly1305 | DM encryption |

### Expression Store

- **CID**: `SHA256(data || 256-bit random || timestamp)`
- **Deduplication**: Content-identical expressions share CIDs
- **Merkle root**: Commitment over expression log
- **Capacity**: 100,000 expressions max
- **Decay**: 7-day inactivity triggers candidacy
- **Threading**: Reply index maps parent→child CIDs

### Quorum Sensing

| Parameter | Value |
|-----------|-------|
| Threshold | `max(ceil((peer_count + 1) * 0.67 * 1000), 1000)` |
| Decay | Exponential, 5-min half-life |
| Weight | `max(trust * 1000, 100)` |
| Constraints | One vote/DID, no self-voting, signature required |

### Epigenetic Marks (Trust)

| Parameter | Value |
|-----------|-------|
| Default | 0.5 |
| Update | `score = score * 0.7 + quality * 0.3` |
| Unverified cap | 0.6 |
| Min weight | 100 |
| Propose threshold | 0.4 |

Trust updated by: elaboration quality, valid acknowledgments (0.7), valid testimonies (0.8), voting participation.

### Pools

Trust domains defined by shared passphrases:

| Aspect | Description |
|--------|-------------|
| Commitment | `Argon2id(passphrase, "diagon-pool-v1-salt-2024")` |
| Genesis | 3 hardcoded bootstrap pools |
| Rendezvous | Public DHT discovery pool |
| Isolation | Peers connect only within same pool |

### Geometry of Presence
```
                    ┌─────────────────────────────────────┐
                    │         MONAD (CID space)           │
                    │  SHA-256 content addressing         │
                    └─────────────────────────────────────┘
                                     ▲
                                     │ Testimony (inter-pool)
                    ┌────────────────┼────────────────┐
                    │                │                │
              ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐
              │  Pool A   │◄──►│  Pool B   │◄──►│  Pool C   │
              └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
                    │ Reciprocal Elaboration          │
              ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐
              │  Node 1   │    │  Node 3   │    │  Node 5   │
              │  Node 2   │    │  Node 4   │    │  Node 6   │
              └───────────┘    └───────────┘    └───────────┘
                    │                │                │
                    ▼                ▼                ▼
              Acknowledgment   Acknowledgment   Acknowledgment
```

---

## Security

### Protections

| Threat | Mitigation |
|--------|------------|
| Message flooding | Per-peer rate limiting (100/60s) |
| Replay attacks | Nonce tracking, time-bounded windows |
| Sybil voting | Human elaboration + approval required |
| Self-voting | Returns `SelfVoteProhibited` |
| Unsigned injection | Signatures required on critical messages |
| Memory exhaustion | Store limits (100K expr, 10K proposals) |
| DID spoofing | DID-pubkey binding verification |
| Expression forgery | Signature verification before storage |
| Brute-force pools | Argon2id (64MB memory-hard) |
| DM interception | E2E encryption, forward secrecy |
| DHT spam | 5 registrations/hour/DID |
| Fake acks | Min dwell time + signature verification |
| Fake testimonies | Cross-pool signature verification |

### Signed Messages

| Message | Signed Data |
|---------|-------------|
| Approve | `"approve:" + timestamp + peer_did` |
| Reject | `"reject:" + reason` |
| Heartbeat | `"heartbeat:" + timestamp` |
| Disconnect | `"disconnect:" + timestamp` |
| Elaborate | elaboration text |
| MutualApprove | `"mutual-approve:" + timestamp + peer_did + elaboration_hash` |
| MutualReject | `"mutual-reject:" + reason` |
| DmRequest | `"dm-request:" + did + ephemeral_pubkey` |
| DmAccept | `"dm-accept:" + did + ephemeral_pubkey` |
| DmReject | `"dm-reject:" + did + reason` |
| PinRequest | `"pin:" + cid + reason` |
| PruneRequest | `"prune:" + cid + reason` |
| DhtRegister | `"dht-register:" + topic_hash + pool_commitment + pool_name + description` |
| DhtPoolAnnounce | `"dht-announce:" + pool_commitment + pool_name + peer_count + topics` |
| Acknowledge | `"ack:" + target_cid + view_started + acknowledged_at + reflection` |
| TestimonyRequest | `"testimony-request:" + cid + requester_pool + requester + timestamp` |
| TestimonyAnnounce | `"testimony:" + cid + origin_pool + witness_pool + attestation + timestamp` |

### Error Types
```rust
DiagonError::Io                  // I/O errors
DiagonError::Serialization       // Encoding/decoding failures
DiagonError::Crypto              // Cryptographic failures
DiagonError::Validation          // Invalid data/state
DiagonError::InsufficientTrust   // Trust below threshold
DiagonError::RateLimited         // Too many messages
DiagonError::ConnectionLost      // Peer disconnected
DiagonError::MessageTooLarge     // Exceeds 1MB limit
DiagonError::PoolFull            // Connection pool at capacity
DiagonError::StoreFull           // Expression store at capacity
DiagonError::ReplayAttack        // Nonce reuse detected
DiagonError::SelfVoteProhibited  // Proposer cannot vote
DiagonError::SignatureRequired   // Missing required signature
DiagonError::DmNotEstablished    // DM channel not ready
DiagonError::DmPendingConsent    // Awaiting peer consent
DiagonError::DecryptionFailed    // DM decryption error
DiagonError::DhtRateLimited      // DHT rate limit exceeded
```

---

## Network Protocol

### Connection Lifecycle
```
Initiator                           Receiver
    |-- Hello { did, pubkey, pool } --->|
    |<-- Hello { did, pubkey, pool } ---|
    |       [DID-pubkey verification]   |
    |       [Pool matching]             |
    |<-- Challenge(nonce) --------------|
    |-- Response(nonce, sig) ---------->|
    |<-- ElaborateRequest --------------|
    |-- Elaborate { text, sig } ------->|
    |<-- Elaborate { text, sig } -------|
    |       [Human review both sides]   |
    |-- MutualApprove { hash, sig } --->|
    |<-- MutualApprove { hash, sig } ---|
    |       [CONNECTED]                 |
    |-- SyncRequest ------------------->|
    |<-- SyncReply { expressions } -----|
```

### Connection States

| State | Description |
|-------|-------------|
| Connecting | TCP initiated |
| Authenticating | Hello/Challenge/Response |
| AwaitingOurElaboration | They connected, we must elaborate |
| AwaitingTheirElaboration | We elaborated, awaiting theirs |
| MutualPending | Both elaborated, decision pending |
| AwaitingTheirApproval | We approved, awaiting theirs |
| AwaitingOurApproval | They approved, awaiting ours |
| Connected | Fully authenticated |
| Closing | Graceful disconnect |
| Closed | Terminated |

### Message Types

| Message | Auth | Purpose |
|---------|------|---------|
| Hello | No | Identity/pool announcement |
| Challenge | No | 32-byte nonce |
| Response | No | Signed nonce proof |
| ElaborateRequest | No | Request elaboration |
| Elaborate | No | Signed elaboration |
| MutualApprove/Reject | No | Connection decision |
| Discover | No | Query peers/pools |
| DiscoverResponse | No | Return network info |
| Expression | Yes | Broadcast S-expression |
| Signal | Yes | Quorum vote |
| SyncRequest | Yes | Request missing expressions |
| SyncReply | Yes | Batch expressions + pinned CIDs |
| Heartbeat | Yes | Keep-alive (30s) |
| Disconnect | Yes | Graceful shutdown |
| ContentStart/Data/Ack | Yes | Chunked transfer |
| ContentRetransmit | Yes | Request missing chunks |
| ContentComplete/Error | Yes | Transfer status |
| DmRequest/Accept/Reject | Yes | DM channel setup |
| DmMessage | Yes | Encrypted message |
| PinRequest/Signal | Yes | Pin governance |
| PruneRequest/Signal | Yes | Prune governance |
| DhtRegister | Yes | Register pool under topic |
| DhtDirectoryRequest/Response | Yes | Full DHT directory |
| DhtSearchRequest/Response | Yes | Topic search |
| DhtPoolAnnounce | Yes | Pool status broadcast |
| Acknowledge | Yes | Witnessed attention |
| TestimonyRequest/Announce | Yes | Inter-pool testimony |

### Framing

- 4-byte big-endian length prefix
- Max message: 1 MB
- Size verified before allocation

### Timeouts & Intervals

| Parameter | Value |
|-----------|-------|
| Connection pool | 100 max |
| Reconnect | 10 × 5s |
| Peer timeout | 150s |
| Challenge timeout | 10s |
| Heartbeat | 30s |
| Sync | 60s |
| Decay check | 1 hour |
| Transfer timeout | 300s |
| DHT sync | 300s |
| DHT stale | 24 hours |

---

## S-Expression Format

### Node Types

| Type | Syntax | Example |
|------|--------|---------|
| Nil | `()` | `()` |
| Atom | `symbol` | `propose` |
| Int | 64-bit signed | `42` |
| Bytes | `#x<hex>` | `#xdeadbeef` |
| Cons | `(car . cdr)` | `(a b c)` |

### Arena Operations
```rust
arena.atom("symbol")       // Create atom
arena.int(42)              // Create integer
arena.bytes(&[0xDE, 0xAD]) // Create bytes
arena.cons(car, cdr)       // Create cons cell
arena.list(&[a, b, c])     // Create proper list
arena.car(expr)            // First element
arena.cdr(expr)            // Rest of list
arena.nth(list, n)         // Nth element (0-indexed)
arena.serialize(expr)      // To bytes
arena.deserialize(&data)   // From bytes
arena.parse("(a b c)")     // From string
arena.display(expr)        // To string
arena.hash(expr)           // Content hash (cached)
arena.intern(expr)         // Returns (CID, canonical_ref)
arena.lookup(&cid)         // Find by CID
```

### Expression Formats
```lisp
;; Signed envelope
(signed #x<pubkey> #x<signature> <inner-expression>)

;; Proposal
(signed #x<pubkey> #x<sig> (propose "text" "elaboration"))

;; Vote
(signed #x<pubkey> #x<sig> (vote #x<target-cid> yes|no "elaboration"))

;; Reply
(signed #x<pubkey> #x<sig> (reply-to #x<parent-cid> "text"))
```

---

## Content Sharing

### Chunked Transfer

| Parameter | Value |
|-----------|-------|
| Chunk size | 262,144 bytes |
| Max pending | 5 transfers |
| Timeout | 300s |
| Max size | 100 MB |

### Content Types

| Type | Keywords | Formats |
|------|----------|---------|
| Image | `image`, `img`, `photo` | JPEG, PNG, GIF, WebP |
| Video | `video`, `vid`, `movie` | MP4, WebM, MPEG |
| Text | `text`, `txt`, `doc` | Plain text |

### Transfer Flow
```
Sender                              Receiver
   |-- ContentStart(metadata) --------->|
   |-- ContentData(chunk 0) ----------->|
   |<-- ContentAck(chunk 0) ------------|
   |       ...                          |
   |-- ContentData(chunk N) ----------->|
   |<-- ContentComplete ----------------|
```

### Content Metadata
```rust
ContentMetadata {
    content_id: [u8; 32],
    content_type: ContentType,
    total_size: u64,
    total_chunks: u32,
    content_hash: [u8; 32],
    filename: Option<String>,
    mime_type: Option<String>,
    sender: Did,
    timestamp: u64,
    signature: Vec<u8>,
}
```

### Content Decay

- Check: hourly
- Threshold: 7 days since last engagement
- Engagement: viewing, voting, acknowledging
- Pinned: exempt from decay
- Witnessed: higher engagement weight

---

## Direct Messages

### E2E Encryption

| Component | Algorithm |
|-----------|-----------|
| Key exchange | X25519 (ephemeral) |
| Encryption | ChaCha20Poly1305 |
| Key derivation | SHA-256("diagon-dm-key-v1" + shared_secret) |
| Nonce | Random 12 bytes/message |

### Channel States

| State | Description |
|-------|-------------|
| PendingOutbound | Request sent, awaiting consent |
| PendingInbound | Request received, needs consent |
| Established | Both consented, encryption active |
| Rejected | Declined |

### DM Flow
```
Alice                               Bob
  |-- DmRequest(ephemeral_pk) ------>|
  |<-- DmAccept(ephemeral_pk) -------|
  |       [Both derive shared key]   |
  |-- DmMessage(encrypted) --------->|
  |<-- DmMessage(encrypted) ---------|
```

### Channel ID
```rust
fn dm_channel_id(a: &Did, b: &Did) -> [u8; 32] {
    SHA256(min(a, b) + max(a, b))
}
```

---

## DHT Discovery

### Rendezvous Network

| Parameter | Value |
|-----------|-------|
| Passphrase | `"diagon-rendezvous-v1-public-directory"` |
| Purpose | Pool advertisement and discovery |

### DHT Entry
```rust
DhtEntry {
    topic_hash: [u8; 32],      // SHA256("diagon-topic-v1:" + lowercase(topic))
    pool_commitment: [u8; 32],
    pool_name: String,
    description: String,
    peer_count: usize,
    registered_by: Did,
    registered_at: u64,
    last_seen: u64,
}
```

### DHT Operations

| Operation | Rate Limit | Description |
|-----------|------------|-------------|
| Register | 5/hour/DID | Register pool under topic |
| Search | None | Query by topic |
| Directory | None | Get all entries |
| Announce | Per sync interval | Broadcast pool status |

### DHT Lifecycle

- Registration broadcasts to rendezvous peers
- Peers forward registrations
- Duplicates update existing entries
- Entries >24h removed
- Announcements every 5 minutes

---

## Governance

### Proposals

Create with `propose <text>` (trust >= 0.4):
```rust
ProposalState {
    cid: Cid,
    expr_data: Vec<u8>,
    proposer: Did,
    elaboration: String,
    quorum: QuorumState,
    created: u64,
}
```

### Voting

`vote <cid> <y/n> <elaboration>`:
- Min 20-char elaboration
- No self-voting
- One vote/DID/proposal
- Weight based on trust

### Threading

`reply <cid> <text>`:
- Creates signed reply-to expression
- Indexed by parent CID
- View with `thread <cid>`

### Pinning

1. `pin <cid> <reason>` - propose
2. `vote-pin <cid> <y/n> <text>` - vote
3. Quorum reached → pinned
4. Pinned content exempt from decay

### Pruning

1. `prune <cid> <reason>` - propose
2. `vote-prune <cid> <y/n> <text>` - vote
3. Quorum reached → removed

### Decay Governance

1. `propose-decay enable <days> <engage> <reason>`
2. `propose-decay disable <reason>`
3. `vote-decay <id> <y/n> <text>`
4. Quorum reached → config applied pool-wide

### Quorum Signal
```rust
QuorumSignal {
    source: Did,
    pubkey: Vec<u8>,
    target: Cid,
    weight: u64,
    support: bool,
    elaboration: String,
    timestamp: u64,
    signature: Vec<u8>,
}
```

---

## Witness System

### Acknowledgment (Intra-Pool)

Receipt ≠ Attention. Proves attended presence.

| Parameter | Value |
|-----------|-------|
| Min dwell | 5s |
| Base weight | 100 |
| Reflection weight | 300 |
| Reflection min | 10 chars |
| Witnessed threshold | 2 witnesses |

```rust
Acknowledgment {
    target: Cid,
    witness: Did,
    pubkey: Vec<u8>,
    view_started: u64,
    acknowledged_at: u64,
    reflection: Option<String>,
    signature: Vec<u8>,
}
```

### Reciprocal Elaboration

Both parties elaborate before either can approve:

```
Alice                               Bob
  |-- connect -----------------------|
  |<-- ElaborateRequest -------------|
  |-- Elaborate { text } ----------->|
  |<-- Elaborate { text } -----------|
  |       [Both review]              |
  |-- MutualApprove { hash } ------->|
  |<-- MutualApprove { hash } -------|
  |       [CONNECTED]                |
```

### Testimony (Inter-Pool)

Pools witness each other's expressions without merging.

| Parameter | Value |
|-----------|-------|
| Weight/pool | 500 |
| Attestation min | 10 chars |

```rust
Testimony {
    cid: Cid,
    origin_pool: [u8; 32],
    witness_pool: [u8; 32],
    testifier: Did,
    pubkey: Vec<u8>,
    attestation: String,
    testified_at: u64,
    signature: Vec<u8>,
}
```

Constraints: cannot testify own pool, one testimony/testifier/expression, broadcasts via rendezvous.

### Expression Metadata
```rust
ExpressionMeta {
    created_at: u64,
    last_engaged: u64,
    engagement_count: u32,
    acknowledgments: AcknowledgmentState,
    testimonies: TestimonyState,
    origin_pool: Option<[u8; 32]>,
}
```

---

## XP System

| Parameter | Value |
|-----------|-------|
| View threshold | 30s min |
| XP/view | 1 |
| Cooldown | 5 min/content |

```rust
XpState {
    total_xp: u64,
    last_view: HashMap<Cid, u64>,
    view_start: HashMap<Cid, u64>,
    viewing: HashMap<Cid, u64>,
}
```

---

## Commands

### Pool & Connection
```
auth <passphrase> [name]       Join/create pool, optionally set name
auth <passphrase> --name "X"   Join/create pool with name
connect <addr|did>             Connect via IP:port or DID prefix
elaborate <text>               Explain why joining (min 20 chars)
```

### Reciprocal Approval
```
review <did>                   Review peer's elaboration
mutual-approve <did>           Approve after mutual elaboration
mutual-reject <did> <reason>   Reject with reason
```

### Discovery (Rendezvous)
```
join-rendezvous                Join public discovery network
discover                       Get directory of pools
sync-dht                       Force refresh directory
dht-register <topic> [desc]    Register pool under topic
dht-search <topic>             Search pools by topic
dht-status                     Show DHT state
```

### Content Sharing
```
message <type> <path>          Share content (image/video/text)
view-start <cid>               Start viewing (for XP)
view-stop <cid>                Stop viewing (awards XP if >=30s)
```

### Acknowledgment
```
witness <cid>                  Begin attending to expression
ack <cid> [reflection]         Acknowledge with optional reflection
witnesses <cid>                Show who witnessed expression
```

### Testimony
```
testify <cid> <pool> <text>    Testify about another pool's expression
testimonies <cid>              Show testimonies for expression
request-testimony <cid>        Request others to testify
my-testimonies                 Show testimonies given
```

### Direct Messages
```
dm-request <did>               Request E2E channel
dm-accept <did>                Accept DM request
dm-reject <did> <reason>       Reject DM request
dm-send <did> <message>        Send encrypted message
dm-list                        List DM channels
dm-history <did>               View message history
```

### Governance
```
propose <text>                 Create proposal (trust >= 0.4)
vote <cid> <y/n> <text>        Vote on proposal
reply <cid> <text>             Reply to expression
thread <cid>                   Show thread tree
pin <cid> <reason>             Propose pinning
vote-pin <cid> <y/n> <text>    Vote on pin
prune <cid> <reason>           Propose removal
vote-prune <cid> <y/n> <text>  Vote on prune
```

### Decay Governance
```
propose-decay enable <days> <engage> <reason>
propose-decay disable <reason>
vote-decay <id> <y/n> <text>
decay-proposals
```

### Status
```
status                         Show node status
list-pinned                    Show pins
list-decayed                   Show decayed content
xp                             Show XP status
help                           Show commands
quit                           Shutdown
```

---

## Configuration

### Constants

| Constant | Value |
|----------|-------|
| `EIGEN_THRESHOLD` | 0.67 |
| `SIGNAL_HALF_LIFE` | 300s |
| `HEARTBEAT_INTERVAL` | 30s |
| `SYNC_INTERVAL` | 60s |
| `DECAY_CHECK_INTERVAL` | 3600s |
| `PEER_TIMEOUT_SECS` | 150s |
| `CHALLENGE_TIMEOUT_SECS` | 10s |
| `MIN_ELABORATION_LEN` | 20 |
| `MAX_MESSAGE_SIZE` | 1 MB |
| `MAX_CONNECTIONS` | 100 |
| `CONTENT_CHUNK_SIZE` | 262,144 |
| `CONTENT_DECAY_DAYS` | 7 |
| `XP_VIEW_THRESHOLD_SECS` | 30 |
| `XP_PER_VIEW` | 1 |
| `XP_COOLDOWN_SECS` | 300 |
| `TRUST_DEFAULT` | 0.5 |
| `TRUST_MIN_FOR_PROPOSE` | 0.4 |
| `TRUST_HISTORY_WEIGHT` | 0.7 |
| `TRUST_NEW_WEIGHT` | 0.3 |
| `MAX_EXPRESSIONS` | 100,000 |
| `MAX_PROPOSALS` | 10,000 |
| `MAX_PINNED` | 1,000 |
| `MAX_DM_CHANNELS` | 100 |
| `RATE_LIMIT_MAX_MESSAGES` | 100 |
| `RATE_LIMIT_WINDOW_SECS` | 60 |
| `DHT_REGISTER_LIMIT_PER_HOUR` | 5 |
| `DHT_SYNC_INTERVAL` | 300s |
| `DHT_STALE_SECS` | 86400 |
| `ARGON2_MEM_COST` | 65,536 |
| `ARGON2_TIME_COST` | 3 |
| `ARGON2_PARALLELISM` | 4 |
| `ACK_MIN_DWELL_SECS` | 5 |
| `ACK_ELABORATION_MIN_LEN` | 10 |
| `ACK_WEIGHT_BASE` | 100 |
| `ACK_WEIGHT_WITH_REFLECTION` | 300 |
| `TESTIMONY_MIN_ATTESTATION_LEN` | 10 |
| `TESTIMONY_WEIGHT_PER_POOL` | 500 |

---

## Usage

### Starting a Node
```bash
cargo run                              # Default: 127.0.0.1:9070
cargo run -- 192.168.1.10:9070 /var/lib/diagon
```

### Joining a Network
```bash
> auth quantum leap beyond horizon
Pool set: 801e100b...

> auth quantum leap beyond horizon --name "My Pool"
Pool set: 801e100b...
Pool name: My Pool

> connect 192.168.1.20:9070
[->] Connecting to 192.168.1.20:9070

> elaborate I am joining this network to participate in distributed governance.
[ELABORATE] Sent, awaiting their elaboration...

# Peer elaborates
[ELAB] from abc123...
   "I've been running this pool for collective decision-making."

> review abc1
=== ELABORATION FROM abc123... ===
I've been running this pool for collective decision-making.

Use 'mutual-approve abc1' to accept

> mutual-approve abc1
[APPROVE] Sent approval, awaiting theirs...
[OK] Mutually connected with abc123...
```

### Connecting via DID
```bash
# Connect to known peer by DID prefix
> connect abc1
[->] Resolved abc123... to 192.168.1.20:9070
[->] Connecting...

# If DID unknown
> connect xyz9
[ERR] Unknown DID xyz9... - use 'discover' or provide IP:port
```

### Witnessing Content
```bash
> witness 7f3a
[WITNESS] Began attending to 7f3a2b1c...

> ack 7f3a This resonates with my experience.
[ACK] Witnessed 7f3a2b1c... (12s dwell) with reflection
[XP] +1 XP earned

> witnesses 7f3a
=== WITNESSES FOR 7f3a2b1c... ===
Total: 3 witnesses, weight: 700
  [2m ago] abc123... (8s dwell, weight: 100)
  [1m ago] def456... (15s dwell, weight: 300)
       "This resonates with my experience..."
```

### Pool Discovery
```bash
> join-rendezvous
[RENDEZVOUS] Joining public discovery network...

> auth my-pool-secret --name "Rust Developers Pool"
Pool set: a1b2c3d4...
Pool name: Rust Developers Pool

> dht-register rust "Rust programming discussions"
[DHT] Registered under topic 'rust'

> dht-search python
=== DHT Search: 'python' ===
Found 2 pool(s):
  Python Pool (a1b2c3d4...) - 5 peers

> discover
[DISCOVER] Requesting directory...
```

### Creating Threads
```bash
> propose This is the root message.
[PROPOSE] 7f3a2b1c...

> reply 7f3a I agree with this proposal.
[REPLY] 8b4c3d2e -> 7f3a2b1c

> thread 7f3a
=== THREAD 7f3a2b1c ===
[ROOT] "This is the root message..." (2m ago)
  └─ 8b4c3d2e "I agree with this..." (1m ago)
```

### Status
```bash
> status
=== DIAGON v0.9.6 STATUS ===
[MY ID] abc123...
[POOL] Rust Developers Pool
[EXPR] 42/100000
[PROP] 3
[PIN] 1 active
[LINK] 5 auth, 1 pending
[DM] 2 channels
[XP] 15
[DHT] 12 entries
[WITNESS] 8 acknowledged, 3 testified
```

---

## Testing
```bash
cargo test -- --nocapture --test-threads=1
```

| Category | Tests |
|----------|-------|
| Arena/S-Expression | 4 |
| Content Transfer | 5 |
| Quorum/Consensus | 5 |
| Trust/Epigenetic | 2 |
| DM/Encryption | 3 |
| Acknowledgment | 3 |
| Testimony | 2 |
| Reciprocal | 1 |
| Error Handling | 8 |
| DHT Discovery | 10 |
| Threading | 3 |
| Integration | 5 |

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `pqcrypto-dilithium` | Dilithium3 signatures |
| `sha2` | SHA-256 |
| `argon2` | Pool passphrase hashing |
| `x25519-dalek` | DM key exchange |
| `chacha20poly1305` | DM encryption |
| `serde`, `bincode`, `serde_cbor` | Serialization |
| `rand` | Cryptographic randomness |
| `hex` | Hex encoding |

---

## Genesis Pools
```
#1 801e100b... [genesis]
#2 93a780b1... [genesis]
#3 c78dec83... [genesis]
```
Genesis pools use legacy SHA256. New pools use Argon2id.

---

## Persistence

State persisted to `<db_path>/state.cbor`:
- Identity (keypair, DID)
- Expressions, metadata, reply index
- Proposals, quorum progress
- Pins, prune proposals
- Epigenetic marks
- XP state
- DHT entries
- Pool name, registered topics
- Decay config, proposals
- Testimony registry

```
<db_path>/
├── state.cbor
└── received/
    └── <files>
```