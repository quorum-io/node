# DIAGON v0.9.5

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
10. [XP System](#xp-system)
11. [Commands](#commands)
12. [Configuration](#configuration)
13. [Usage](#usage)
14. [Testing](#testing)
15. [Dependencies](#dependencies)

---

## Overview

DIAGON is a peer-to-peer governance and content sharing system. Nodes form authenticated mesh networks within pools (trust domains), propose and vote on expressions using quorum sensing, share encrypted direct messages, discover pools via DHT, and maintain replicated content-addressed stores with automatic decay.

### Core Principles

- **Homoiconicity**: Code is data, data is code
- **Content-addressing**: The expression IS its identity
- **Quorum sensing**: Accumulate signals, threshold triggers
- **Derived state**: Store expressions, compute results
- **Post-quantum**: Dilithium3 signatures throughout
- **Consent-based**: Human-in-the-loop for connections and DMs

### Features

| Category | Features |
|----------|----------|
| **Identity** | Post-quantum Dilithium3 signatures, DID-based identity |
| **Consensus** | 67% weighted quorum with time-decaying vote weights |
| **Content** | Chunked transfers (262KB), 7-day decay, pin/prune governance |
| **Messaging** | E2E encrypted DMs (X25519 + ChaCha20Poly1305), consent required |
| **Discovery** | DHT-based pool discovery via rendezvous network |
| **Threading** | Reply chains with tree display |
| **Engagement** | XP system with view tracking and cooldowns |
| **Security** | Rate limiting, replay protection, self-vote prevention |
| **Network** | Pool-based authentication, discovery, automatic sync |

---

## Architecture

### Identity

| Component | Description |
|-----------|-------------|
| DID | `did:diagon:<hex(pubkey[0:16])>` |
| Keypair | Dilithium3 (post-quantum, ~2KB public key) |
| Verification | DID-pubkey binding checked during handshake |
| Persistence | CBOR-serialized to `<db_path>/state.cbor` |

### Cryptography

| Algorithm | Purpose |
|-----------|---------|
| Dilithium3 | Signatures (post-quantum secure) |
| SHA-256 | Content addressing, hashing |
| Argon2id | Pool passphrase hashing (64MB, 3 iterations, 4 threads) |
| X25519 | DM ephemeral key exchange |
| ChaCha20Poly1305 | DM message encryption |

### Expression Store

- **CID**: `SHA256(data || 256-bit random || timestamp)`
- **Deduplication**: Content-identical expressions share CIDs
- **Merkle root**: Commitment over expression log
- **Capacity**: 100,000 expressions maximum
- **Verification**: Signed expressions verified before storage
- **Decay**: 7-day inactivity triggers decay candidacy
- **Threading**: Reply index maps parent CID to child CIDs

### Quorum Sensing

| Parameter | Value | Description |
|-----------|-------|-------------|
| Threshold | `max(ceil((peer_count + 1) * 0.67 * 1000), 1000)` | Minimum 1000 |
| Decay | Exponential | 5-minute half-life |
| Weight | Trust-based | `max(trust * 1000, 100)` |
| Constraints | One vote per DID | No self-voting, signature required |

### Epigenetic Marks (Trust)

| Parameter | Value |
|-----------|-------|
| Default | 0.5 |
| Update formula | `score = score * 0.7 + quality * 0.3` |
| Unverified cap | 0.6 |
| Minimum weight | 100 |
| Propose threshold | 0.4 |

### Pools

Pools are trust domains defined by shared passphrases:

| Aspect | Description |
|--------|-------------|
| Commitment | `Argon2id(passphrase, "diagon-pool-v1-salt-2024")` |
| Genesis pools | 3 hardcoded pools bootstrap the network |
| Rendezvous | Special pool for public DHT discovery |
| Isolation | Nodes only connect to peers in the same pool |

---

## Security

### Protections

| Threat | Mitigation |
|--------|------------|
| Message flooding | Per-peer rate limiting (100/60s) |
| Replay attacks | Nonce tracking with time-bounded windows |
| Sybil voting | Human elaboration + approval required |
| Self-voting | Explicit prohibition, returns `SelfVoteProhibited` |
| Unsigned injection | Signatures required on critical messages |
| Memory exhaustion | Store size limits (100K expressions, 10K proposals) |
| DID spoofing | DID-pubkey binding verification |
| Expression forgery | Signature verification before storage |
| Brute-force pools | Argon2id (memory-hard, 64MB) |
| DM interception | E2E encryption with forward secrecy |
| DHT spam | Rate limiting (5 registrations/hour/DID) |

### Signed Messages

| Message | Signed Data |
|---------|-------------|
| Approve | `"approve:" + timestamp + peer_did` |
| Reject | `"reject:" + reason` |
| Heartbeat | `"heartbeat:" + timestamp` |
| Disconnect | `"disconnect:" + timestamp` |
| Elaborate | elaboration text |
| DmRequest | `"dm-request:" + did + ephemeral_pubkey` |
| DmAccept | `"dm-accept:" + did + ephemeral_pubkey` |
| DmReject | `"dm-reject:" + did + reason` |
| PinRequest | `"pin:" + cid + reason` |
| PruneRequest | `"prune:" + cid + reason` |
| DhtRegister | `"dht-register:" + topic_hash + pool_commitment + pool_name + description` |
| DhtPoolAnnounce | `"dht-announce:" + pool_commitment + pool_name + peer_count + topics` |

### Error Types
```rust
DiagonError::Io              // I/O errors
DiagonError::Serialization   // Encoding/decoding failures
DiagonError::Crypto          // Cryptographic failures
DiagonError::Validation      // Invalid data/state
DiagonError::InsufficientTrust(f64)  // Trust below threshold
DiagonError::RateLimited     // Too many messages
DiagonError::ConnectionLost  // Peer disconnected
DiagonError::MessageTooLarge // Exceeds 1MB limit
DiagonError::PoolFull        // Connection pool at capacity
DiagonError::StoreFull       // Expression store at capacity
DiagonError::ReplayAttack    // Nonce reuse detected
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
    |                                   |
    |-- Hello { did, pubkey, pool } --->|
    |<-- Hello { did, pubkey, pool } ---|
    |       [DID-pubkey verification]   |
    |       [Pool matching]             |
    |<-- Challenge(nonce) --------------|
    |-- Response(nonce, sig) ---------->|
    |       [10s timeout]               |
    |<-- ElaborateRequest --------------|
    |-- Elaborate { text, sig } ------->|
    |       [Human review]              |
    |<-- Approve/Reject ----------------|
    |       [If approved: AUTHENTICATED]|
    |                                   |
    |-- SyncRequest ------------------->|
    |<-- SyncReply { expressions } -----|
```

### Message Types

| Message | Auth Required | Purpose |
|---------|---------------|---------|
| Hello | No | Identity and pool announcement |
| Challenge | No | 32-byte nonce for signature |
| Response | No | Signed nonce proof |
| ElaborateRequest | No | Request human elaboration |
| Elaborate | No | Signed elaboration text |
| Approve/Reject | No | Connection decision |
| Discover | No | Query peers/pools |
| DiscoverResponse | No | Return network info |
| Expression | Yes | Broadcast S-expression |
| Signal | Yes | Quorum vote signal |
| SyncRequest | Yes | Request missing expressions |
| SyncReply | Yes | Batch of expressions + pinned CIDs |
| Heartbeat | Yes | Keep-alive (30s interval) |
| Disconnect | Yes | Graceful shutdown |
| ContentStart | Yes | Begin chunked transfer |
| ContentData | Yes | Transfer chunk |
| ContentAck | Yes | Acknowledge chunk |
| ContentRetransmit | Yes | Request missing chunks |
| ContentComplete | Yes | Confirm transfer complete |
| ContentError | Yes | Report transfer failure |
| DmRequest | Yes | Request E2E channel |
| DmAccept | Yes | Accept DM channel |
| DmReject | Yes | Decline DM channel |
| DmMessage | Yes | Encrypted message |
| PinRequest | Yes | Propose pinning content |
| PinSignal | Yes | Vote on pin proposal |
| PruneRequest | Yes | Propose removing content |
| PruneSignal | Yes | Vote on prune proposal |
| DhtRegister | Yes | Register pool under topic |
| DhtDirectoryRequest | Yes | Request full DHT directory |
| DhtDirectoryResponse | Yes | Return DHT entries |
| DhtSearchRequest | Yes | Search by topic hash |
| DhtSearchResponse | Yes | Return search results |
| DhtPoolAnnounce | Yes | Announce pool status/topics |

### Framing

- 4-byte big-endian length prefix
- Maximum message size: 1 MB
- Size verified before allocation

### Timeouts & Intervals

| Parameter | Value |
|-----------|-------|
| Connection pool | 100 max |
| Reconnect attempts | 10 x 5s |
| Peer timeout | 150s |
| Challenge timeout | 10s |
| Heartbeat interval | 30s |
| Sync interval | 60s |
| Decay check interval | 1 hour |
| Transfer timeout | 300s |
| DHT sync interval | 300s |
| DHT stale threshold | 24 hours |

---

## S-Expression Format

### Node Types

| Type | Syntax | Example |
|------|--------|---------|
| Nil | `()` | `()` |
| Atom | `symbol` | `propose` |
| Int | 64-bit signed | `42`, `-123` |
| Bytes | `#x<hex>` | `#xdeadbeef` |
| Cons | `(car . cdr)` | `(a b c)` |

### Arena Operations
```rust
// Construction
arena.atom("symbol")      // Create atom
arena.int(42)             // Create integer
arena.bytes(&[0xDE, 0xAD]) // Create bytes
arena.cons(car, cdr)      // Create cons cell
arena.list(&[a, b, c])    // Create proper list

// Access
arena.car(expr)           // First element
arena.cdr(expr)           // Rest of list
arena.nth(list, n)        // Nth element (0-indexed)

// Serialization
arena.serialize(expr)     // To bytes
arena.deserialize(&data)  // From bytes
arena.parse("(a b c)")    // From string
arena.display(expr)       // To string

// Interning
arena.hash(expr)          // Content hash (cached)
arena.intern(expr)        // Returns (CID, canonical_ref)
arena.lookup(&cid)        // Find by CID
```

### Signed Envelope
```lisp
(signed #x<pubkey> #x<signature> <inner-expression>)
```

### Proposal Format
```lisp
(signed #x<pubkey> #x<sig>
  (propose "proposal text" "elaboration"))
```

### Vote Format
```lisp
(signed #x<pubkey> #x<sig>
  (vote #x<target-cid> yes|no "elaboration"))
```

### Reply Format
```lisp
(signed #x<pubkey> #x<sig>
  (reply-to #x<parent-cid> "reply text"))
```

---

## Content Sharing

### Chunked Transfer

Large content transferred in 262KB chunks with hash verification:

| Parameter | Value |
|-----------|-------|
| Chunk size | 262,144 bytes (256KB) |
| Max pending transfers | 5 |
| Transfer timeout | 300 seconds |
| Max content size | 100 MB |

### Content Types

| Type | Keywords | Auto-detected formats |
|------|----------|----------------------|
| Image | `image`, `img`, `photo` | JPEG, PNG, GIF, WebP |
| Video | `video`, `vid`, `movie` | MP4, WebM, MPEG |
| Text | `text`, `txt`, `doc` | Plain text |

### Transfer Flow
```
Sender                              Receiver
   |                                    |
   |-- ContentStart(metadata) --------->|
   |       [Verify signature]           |
   |                                    |
   |-- ContentData(chunk 0) ----------->|
   |<-- ContentAck(chunk 0) ------------|
   |-- ContentData(chunk 1) ----------->|
   |<-- ContentAck(chunk 1) ------------|
   |       ...                          |
   |-- ContentData(chunk N) ----------->|
   |       [Reassemble & verify hash]   |
   |<-- ContentComplete ----------------|
```

### Content Metadata
```rust
ContentMetadata {
    content_id: [u8; 32],      // Random identifier
    content_type: ContentType,  // Image/Video/Text
    total_size: u64,           // Bytes
    total_chunks: u32,         // Number of chunks
    content_hash: [u8; 32],    // SHA-256 of full content
    filename: Option<String>,  // Original filename
    mime_type: Option<String>, // Detected MIME type
    sender: Did,               // Sender's DID
    timestamp: u64,            // Creation time
    signature: Vec<u8>,        // Dilithium3 signature
}
```

### Content Decay

Content without engagement decays after 7 days:

- **Decay check**: Every hour
- **Decay threshold**: 7 days since last engagement
- **Engagement**: Viewing, voting, or interacting
- **Pinned content**: Exempt from decay
- **Decayed content**: Candidates for pruning

---

## Direct Messages

### E2E Encryption

| Component | Algorithm |
|-----------|-----------|
| Key exchange | X25519 (ephemeral keys) |
| Encryption | ChaCha20Poly1305 (AEAD) |
| Key derivation | SHA-256("diagon-dm-key-v1" + shared_secret) |
| Nonce | Random 12 bytes per message |

### Channel States

| State | Description |
|-------|-------------|
| PendingOutbound | Request sent, awaiting consent |
| PendingInbound | Request received, needs your consent |
| Established | Both parties consented, encryption active |
| Rejected | Request declined |

### DM Flow
```
Alice                               Bob
  |                                  |
  |-- DmRequest(ephemeral_pk) ------>|
  |       [Bob sees request]         |
  |       [Bob consents]             |
  |<-- DmAccept(ephemeral_pk) -------|
  |       [Both derive shared key]   |
  |                                  |
  |-- DmMessage(encrypted) --------->|
  |<-- DmMessage(encrypted) ---------|
```

### Channel ID

Symmetric (Alice->Bob = Bob->Alice):
```rust
fn dm_channel_id(did_a: &Did, did_b: &Did) -> [u8; 32] {
    SHA256(min(did_a, did_b) + max(did_a, did_b))
}
```

---

## DHT Discovery

### Rendezvous Network

Public discovery network for finding pools by topic:

| Parameter | Value |
|-----------|-------|
| Passphrase | `"diagon-rendezvous-v1-public-directory"` |
| Commitment | Argon2id hash of passphrase |
| Purpose | Pool advertisement and discovery |

### DHT Entry
```rust
DhtEntry {
    topic_hash: [u8; 32],      // SHA256("diagon-topic-v1:" + lowercase(topic))
    pool_commitment: [u8; 32], // Pool's Argon2id commitment
    pool_name: String,         // Human-readable name
    description: String,       // Pool description
    peer_count: usize,         // Current peer count
    registered_by: Did,        // Registrar's DID
    registered_at: u64,        // Registration timestamp
    last_seen: u64,            // Last activity timestamp
}
```

### DHT Operations

| Operation | Rate Limit | Description |
|-----------|------------|-------------|
| Register | 5/hour/DID | Register pool under topic |
| Search | None | Query by topic string |
| Directory | None | Get all entries |
| Announce | Per sync interval | Broadcast pool status |

### Topic Hashing
```rust
fn topic_hash(topic: &str) -> [u8; 32] {
    SHA256("diagon-topic-v1:" + topic.to_lowercase())
}
```

### DHT Lifecycle

- **Registration**: Broadcast to rendezvous peers
- **Propagation**: Peers forward new registrations
- **Updates**: Duplicate registrations update existing entries
- **Cleanup**: Entries older than 24 hours removed
- **Sync**: Periodic announcements every 5 minutes

---

## Governance

### Proposals

Create with `propose <text>` (requires trust >= 0.4):
```rust
ProposalState {
    cid: Cid,              // Content ID
    expr_data: Vec<u8>,    // Serialized expression
    proposer: Did,         // Creator's DID
    elaboration: String,   // Proposal text
    quorum: QuorumState,   // Vote tracking
    created: u64,          // Timestamp
}
```

### Voting

Vote with `vote <cid> <y/n> <elaboration>`:

- Minimum 20-character elaboration required
- Cannot vote on own proposals
- One vote per DID per proposal
- Vote weight based on trust score

### Threading

Reply to expressions with `reply <cid> <text>`:

- Creates signed reply-to expression
- Indexed by parent CID
- View threads with `thread <cid>`
- Nested replies supported

### Pinning

Pin important content to prevent decay:

1. `pin <cid> <reason>` - Propose pinning
2. `vote-pin <cid> <y/n> <text>` - Vote on pin
3. When quorum reached, content pinned
4. Pinned content exempt from decay

### Pruning

Remove content through consensus:

1. `prune <cid> <reason>` - Propose removal
2. `vote-prune <cid> <y/n> <text>` - Vote on prune
3. When quorum reached, content removed
4. Also removes from proposals and pins

### Quorum Signal
```rust
QuorumSignal {
    source: Did,           // Voter's DID
    pubkey: Vec<u8>,       // Voter's public key
    target: Cid,           // Target proposal/pin/prune
    weight: u64,           // Based on trust
    support: bool,         // For or against
    elaboration: String,   // Vote rationale
    timestamp: u64,        // When cast
    signature: Vec<u8>,    // Dilithium3 signature
}
```

---

## XP System

### View Tracking

| Parameter | Value |
|-----------|-------|
| View threshold | 30 seconds minimum |
| XP per view | 1 |
| Cooldown | 5 minutes per content |

### XP Flow
```
User                                System
  |                                   |
  |-- view-start <cid> -------------->|
  |       [Timer starts]              |
  |       [Content engagement logged] |
  |                                   |
  |-- view-stop <cid> --------------->|
  |       [Check duration >= 30s]     |
  |       [Check cooldown elapsed]    |
  |<-- XP awarded (if eligible) ------|
```

### XP State
```rust
XpState {
    total_xp: u64,                    // Accumulated XP
    last_view: HashMap<Cid, u64>,     // Last view timestamp per content
    view_start: HashMap<Cid, u64>,    // Active viewing sessions
}
```

---

## Commands

### Pool & Connection
```
auth <passphrase>              Join/create pool
connect <addr>                 Connect to peer (requires auth)
elaborate <text>               Explain why joining (min 20 chars)
approve <id>                   Approve pending peer
reject <id> <reason>           Reject pending peer
```

### Discovery (Rendezvous)
```
join-rendezvous                Join public discovery network
discover                       Get directory of pools
sync-dht                       Force refresh directory
dht-register <topic> [desc]    Register pool under topic
dht-search <topic>             Search pools by topic
dht-status                     Show DHT state
set-pool-name <name>           Set human-readable pool name
```

### Content Sharing
```
message <type> <path>          Share content (image/video/text)
view-start <cid>               Start viewing (for XP)
view-stop <cid>                Stop viewing (awards XP if >=30s)
```

### Direct Messages
```
dm-request <did>               Request E2E channel (needs consent)
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

| Constant | Value | Description |
|----------|-------|-------------|
| `EIGEN_THRESHOLD` | 0.67 | Quorum threshold (67%) |
| `SIGNAL_HALF_LIFE` | 300s | Vote decay half-life |
| `HEARTBEAT_INTERVAL` | 30s | Keep-alive frequency |
| `SYNC_INTERVAL` | 60s | Expression sync frequency |
| `DECAY_CHECK_INTERVAL` | 3600s | Content decay check |
| `PEER_TIMEOUT_SECS` | 150s | Inactivity disconnect |
| `CHALLENGE_TIMEOUT_SECS` | 10s | Auth challenge expiry |
| `MIN_ELABORATION_LEN` | 20 | Minimum elaboration chars |
| `MAX_MESSAGE_SIZE` | 1 MB | Maximum network message |
| `MAX_CONNECTIONS` | 100 | Connection pool limit |
| `CONTENT_CHUNK_SIZE` | 262,144 | Bytes per chunk |
| `CONTENT_DECAY_DAYS` | 7 | Days until decay |
| `XP_VIEW_THRESHOLD_SECS` | 30 | Minimum view time for XP |
| `XP_PER_VIEW` | 1 | XP per valid view |
| `XP_COOLDOWN_SECS` | 300 | Cooldown between XP awards |
| `TRUST_DEFAULT` | 0.5 | Initial trust score |
| `TRUST_MIN_FOR_PROPOSE` | 0.4 | Minimum trust to propose |
| `TRUST_HISTORY_WEIGHT` | 0.7 | Weight of existing trust |
| `TRUST_NEW_WEIGHT` | 0.3 | Weight of new interaction |
| `MAX_EXPRESSIONS` | 100,000 | Expression store limit |
| `MAX_PROPOSALS` | 10,000 | Proposal limit |
| `MAX_PINNED` | 1,000 | Pin limit |
| `MAX_DM_CHANNELS` | 100 | DM channel limit |
| `RATE_LIMIT_MAX_MESSAGES` | 100 | Messages per window |
| `RATE_LIMIT_WINDOW_SECS` | 60 | Rate limit window |
| `DHT_REGISTER_LIMIT_PER_HOUR` | 5 | DHT registrations/hour/DID |
| `DHT_SYNC_INTERVAL` | 300s | DHT announcement interval |
| `DHT_STALE_SECS` | 86400 | DHT entry TTL (24h) |
| `ARGON2_MEM_COST` | 65,536 | 64 MB memory |
| `ARGON2_TIME_COST` | 3 | Iterations |
| `ARGON2_PARALLELISM` | 4 | Threads |

---

## Usage

### Starting a Node
```bash
# Default: 127.0.0.1:9070, database in ./diagon_db
cargo run

# Custom address and database
cargo run -- 192.168.1.10:9070 /var/lib/diagon
```

### Joining a Network
```bash
> auth quantum leap beyond horizon
Pool set: 801e100b...

> connect 192.168.1.20:9070
[->] Connecting to 192.168.1.20:9070

> elaborate I am joining this network to participate in distributed governance.

# Wait for approval...
[OK] Authenticated with 192.168.1.20:9070
```

### Pool Discovery
```bash
# Join rendezvous network
> join-rendezvous
[RENDEZVOUS] Joining public discovery network...
Pool set: <rendezvous-commitment>

# Connect to rendezvous peer
> connect 192.168.1.100:9070

# Set pool name for registration
> set-pool-name "Rust Developers Pool"

# Register under topics
> dht-register rust "Rust programming discussions"
[DHT] Registered under topic 'rust'

> dht-register webdev "Web development with Rust"
[DHT] Registered under topic 'webdev'

# Search for pools
> dht-search python
=== DHT Search: 'python' ===
Found 2 pool(s):
  Python Pool (a1b2c3d4...)
     Python programming - 5 peers

# Get full directory
> discover
[DISCOVER] Requesting directory...
```

### Creating Threads
```bash
> propose This is the root message for discussion.
[PROPOSE] 7f3a2b1c...

> reply 7f3a I agree with this proposal.
[REPLY] 8b4c3d2e -> 7f3a2b1c

> reply 8b4c Let me add more context.
[REPLY] 9c5d4e3f -> 8b4c3d2e

> thread 7f3a
=== THREAD 7f3a2b1c ===
[ROOT] "This is the root message..." (2m ago)
  +- 8b4c3d2e "I agree with this..." (1m ago)
       +- 9c5d4e3f "Let me add more..." (30s ago)
```

### Status Check
```bash
> status

=== DIAGON v0.9.5 STATUS ===
[MY ID] abc123...
[POOL] Rendezvous (public discovery)
[EXPR] 42/100000
[PROP] 3
[PIN] 1 active
[LINK] 5 auth, 1 pending, 0 awaiting
[DM] 2 channels
[XP] 15
[DHT] 12 entries

Proposals:
  [OK] 7f3a2b1c - "Implement privacy-pres..." (1500/1000)
  [ ] 9e8d7c6b - "Add multi-signature su..." (400/1000)

Pinned content:
  PIN 7f3a2b1c - Important governance document

Connections:
  def456... @ 192.168.1.20:9070 (auth)
  ghi789... @ 192.168.1.30:9070 (auth)
```

---

## Testing
```bash
cargo test -- --nocapture --test-threads=1
```

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| Arena/S-Expression | 4 | Parse, serialize, hash, intern, list ops |
| Content Transfer | 5 | Chunking, verification, reassembly |
| Quorum/Consensus | 5 | Self-vote rejection, accumulation, decay |
| Trust/Epigenetic | 2 | Trust evolution, elaboration scoring |
| DM/Encryption | 3 | Key exchange, encrypt/decrypt, channel state |
| Error Handling | 8 | Rate limiting, replay, store limits |
| DHT Discovery | 10 | Topic hashing, registration, search, sync |
| Threading | 3 | Reply indexing, nested replies, display |
| Integration | 4 | Ephemeral pools, two-node, content transfer, DHT sync |

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `pqcrypto-dilithium` | Dilithium3 post-quantum signatures |
| `sha2` | SHA-256 hashing |
| `argon2` | Password hashing for pools |
| `x25519-dalek` | DM key exchange |
| `chacha20poly1305` | DM encryption |
| `serde`, `bincode`, `serde_cbor` | Serialization |
| `rand` | Cryptographic randomness |
| `hex` | Hex encoding/decoding |

---

## Genesis Pools

Three pools active at genesis:
```
#1 801e100b... [genesis]
#2 93a780b1... [genesis]
#3 c78dec83... [genesis]
```

Genesis pools use legacy SHA256 for backward compatibility. New pools use Argon2id.

---

## Persistence

State persisted to `<db_path>/state.cbor`:

- Identity (keypair, DID)
- Expressions with CIDs, metadata, reply index
- Proposal states and quorum progress
- Pinned content and prune proposals
- Epigenetic marks
- XP state
- DHT entries
- Pool name and registered topics

Received content saved to `<db_path>/received/`.

---

## File Structure
```
<db_path>/
+-- state.cbor           # Persisted node state
+-- received/            # Downloaded content
    +-- photo.jpg
    +-- video.mp4
    +-- document.txt
```