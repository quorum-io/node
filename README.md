# DIAGON v0.9.1 Alpha

**Security Hardened P2P Governance System for Decentralized Knowledge Transmission**

*"In the struggle between truth and deception, let mathematics be the arbiter."*

Core principles:
- Homoiconicity: Code is data, data is code
- Content-addressing: The expression IS its identity
- Quorum sensing: Accumulate signals, threshold triggers
- Derived state: Store expressions, compute results
- Post-quantum: Dilithium3 signatures
- Robust networking: Connection pooling, message framing, reconnection
- **Security hardening: Rate limiting, replay protection, self-vote prevention**

---

## Overview

DIAGON is a peer-to-peer governance system built on biological consensus metaphors. Nodes form authenticated mesh networks within "pools" (trust domains), propose and vote on expressions using quorum sensing, and maintain replicated expression stores with content-addressed identities.

The system uses S-expressions as its fundamental data structure, enabling homoiconic representation where proposals, votes, and all protocol messages share a unified format.

### What's New in v0.9.1 (Security Hardened)

- **Argon2 pool authentication**: Pool passphrases now hashed with Argon2id instead of SHA256
- **Rate limiting**: Per-peer message rate limits prevent DoS attacks
- **Anti-replay protection**: Nonce tracking prevents challenge replay attacks
- **Self-voting prevention**: Proposers cannot vote on their own proposals
- **Signed protocol messages**: Heartbeat, Disconnect, and Approve messages now require signatures
- **Expression signature verification**: Signed expressions are cryptographically verified before storage
- **DID-pubkey binding verification**: DIDs are verified to match their claimed public keys
- **Store limits**: Configurable limits prevent memory exhaustion attacks
- **Reduced challenge timeout**: Narrower replay window (10s vs 30s)
- **Verified vs unverified trust updates**: Unverified interactions have capped influence

---

## Architecture

### Identity

- **DID (Decentralized Identifier)**: Derived from Dilithium3 public key (`did:diagon:<hex>`)
- **DID-pubkey binding**: DIDs are verified to match their public keys during Hello exchange
- **Post-quantum signatures**: All authentication and message signing uses Dilithium3
- **Key persistence**: Identity survives restarts via CBOR-serialized state

### Cryptographic Choices

- **Dilithium3 (post-quantum)**: Used for all signatures — authentication, 
  votes, protocol messages. Protects against "harvest now, break later" attacks.
  
- **SHA-256**: Used for content addressing (CIDs, Merkle roots, expression hashing). 
  This is standard practice (used by Bitcoin, IPFS, Git). Content addressing requires 
  collision resistance, where SHA-256 retains ~128-bit security even against quantum 
  computers. CIDs additionally include 256 bits of cryptographic randomness, preventing 
  collision crafting.

- **Argon2id**: Used for pool passphrase hashing. Memory-hard to resist brute-force.

### Expression Store

- **Content-addressed**: Every expression has a unique CID (SHA256 hash including cryptographic randomness and timestamp)
- **Arena allocator**: Efficient S-expression memory management with interning
- **Merkle root**: Log of all expressions produces a verifiable state commitment
- **Automatic deduplication**: Content-identical expressions resolve to same CID
- **Size limits**: Maximum 100,000 expressions to prevent memory exhaustion
- **Signature verification**: Signed expressions are verified before storage

### Quorum Sensing

Inspired by bacterial quorum sensing, consensus emerges from accumulated signals:

- **Threshold**: `⌈(peer_count + 1) × 0.67 × 1000⌉` (minimum 1000)
- **Signal decay**: Exponential with 5-minute half-life
- **Weight**: Based on sender's epigenetic mark (trust score)
- **One vote per source**: Duplicate signals from same DID are rejected
- **Self-voting prohibited**: Proposers cannot vote on their own proposals
- **Signature required**: All signals must include valid cryptographic signatures

### Epigenetic Marks (Trust)

Trust scores evolve based on participation quality:

- **Default**: 0.5
- **Update formula**: `score = score × 0.7 + effective_quality × 0.3`
- **Verified vs unverified**: Unverified interactions capped at 0.6 quality
- **Decay**: Score decays toward baseline when inactive
- **Signal weight**: `max(score × 1000, 100)`
- **Proposal threshold**: Trust ≥ 0.4 required to propose

### Pools

Pools are trust domains defined by shared passphrases:

- **Commitment**: `Argon2id(passphrase, salt)` identifies the pool (upgraded from SHA256)
- **Salt**: Fixed pool salt `diagon-pool-v1-salt-2024`
- **Argon2 parameters**: Memory 64MB, Time cost 3, Parallelism 4
- **Genesis pools**: Three hardcoded pools bootstrap the network
- **Dynamic pools**: New pools can be proposed and voted into existence
- **Isolation**: Nodes only connect to peers in the same pool

---

## Security Features

### Rate Limiting

Per-peer rate limiting prevents denial-of-service attacks:

- **Window**: 60 seconds
- **Limit**: 100 messages per window per peer
- **Enforcement**: Connections exceeding limit are terminated
- **Cleanup**: Expired rate limit entries are garbage collected

### Anti-Replay Protection

Nonce tracking prevents replay of authentication challenges:

- **Nonce size**: 32 bytes (cryptographic random)
- **Tracking window**: 2× challenge timeout (20 seconds)
- **Verification**: Replayed nonces are rejected with `ReplayAttack` error

### Self-Voting Prevention

Prevents proposers from inflating their own proposal support:

- **Tracking**: QuorumState records the proposer's DID
- **Enforcement**: Votes from proposer DID are rejected with `SelfVoteProhibited` error
- **Applies to**: Both expression proposals and pool proposals

### Signed Protocol Messages

Critical protocol messages now require cryptographic signatures:

| Message | Signed Data |
|---------|-------------|
| `Approve` | `"approve:" + timestamp + peer_did` |
| `Reject` | `"reject:" + reason` |
| `Heartbeat` | `"heartbeat:" + timestamp` |
| `Disconnect` | `"disconnect:" + timestamp` |
| `Elaborate` | elaboration text |

### Expression Signature Verification

Signed expressions are verified before storage:

1. Parse expression to extract `(signed pubkey signature inner)`
2. Serialize inner expression
3. Verify signature against pubkey using Dilithium3
4. Only store if verification succeeds

### DID-Pubkey Binding

During Hello exchange, DIDs are verified to match public keys:

1. Compute expected DID: `did:diagon:<hex(pubkey[0:16])>`
2. Compare against claimed DID
3. Reject connection if mismatch detected

---

## Network Protocol

### Connection Lifecycle

1. **TCP Connect**: Initiator connects to receiver
2. **Hello Exchange**: Both sides send `Hello { did, pubkey, pool, expr_root }`
3. **DID Verification**: Verify DID matches pubkey
4. **Challenge-Response**: Cryptographic verification via signed nonces (10s timeout)
5. **Elaboration (HITL)**: Initiator must provide signed human-written elaboration (≥20 chars)
6. **Approval/Rejection**: Receiver manually approves (with signed timestamp) or rejects
7. **Authenticated**: Connection enters full mesh participation

### Message Types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `Hello` | Bidirectional | Identity and pool announcement |
| `Challenge` | Receiver → Initiator | 32-byte nonce for signature |
| `Response` | Initiator → Receiver | Signed nonce proof |
| `ElaborateRequest` | Receiver → Initiator | Request human elaboration |
| `Elaborate` | Initiator → Receiver | Signed elaboration text |
| `Approve` | Receiver → Initiator | Signed acceptance with timestamp and peer DID |
| `Reject` | Receiver → Initiator | Signed denial with reason |
| `Expression` | Broadcast | New S-expression to replicate (verified) |
| `Signal` | Broadcast | Signed quorum vote signal |
| `SyncRequest` | Any → Any | Request missing expressions |
| `SyncReply` | Any → Any | Batch of expressions (verified) |
| `Heartbeat` | Broadcast | Signed keep-alive with timestamp (30s interval) |
| `Disconnect` | Any → Any | Signed graceful shutdown with timestamp |

### Framing

All messages are length-prefixed:
- 4-byte big-endian length header
- Maximum message size: 1 MB (verified BEFORE allocation)
- Async I/O with connection pooling

### Reliability

- **Connection pool**: Maximum 100 concurrent connections
- **Automatic reconnection**: Up to 10 attempts with 5s intervals
- **Peer timeout**: 150 seconds of inactivity triggers disconnect
- **Challenge timeout**: 10 seconds to complete authentication (reduced from 30s)
- **Heartbeat**: 30-second interval keeps connections alive (now signed)
- **Sync**: 60-second interval reconciles expression stores (limited to 100 expressions per reply)

---

## S-Expression Format

### Node Types
```
Nil     → ()
Atom    → symbol
Int     → 64-bit signed integer
Bytes   → #x<hex>
Cons    → (car . cdr)
```

### Signed Expressions

All proposals and votes are wrapped in signed envelopes:
```lisp
(signed
  #x<pubkey>
  #x<signature>
  <inner-expression>)
```

The signature covers the serialized inner expression and is verified using Dilithium3.

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

---

## Commands

### Pool Management
```
auth <passphrase>              Authenticate to a pool (Argon2 hashed)
list-pools                     Show active and pending pools
propose-pool <phrase> - <rationale>   Propose new pool
vote-pool <id> <y/n> <elaboration>    Vote on pool proposal (cannot self-vote)
```

### Peer Management
```
connect <host:port>            Initiate connection to peer
elaborate <text>               Send signed elaboration (min 20 chars)
approve <id>                   Approve pending peer (by DID prefix or address)
reject <id> <reason>           Reject pending peer
```

### Governance
```
propose <text>                 Create new proposal (requires trust ≥ 0.4)
vote <cid> <y/n> <elaboration> Vote on proposal (cannot self-vote, min 20 char elaboration)
status                         Show node status, proposals, connections
```

### Development
```
eval <sexp>                    Parse and store S-expression
help                           Show command list
quit                           Graceful shutdown (sends signed disconnect)
```

---

## Configuration Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `EIGEN_THRESHOLD` | 0.67 | Quorum threshold (67%) |
| `SIGNAL_HALF_LIFE` | 300s | Vote decay half-life |
| `HEARTBEAT_INTERVAL` | 30s | Keep-alive frequency |
| `SYNC_INTERVAL` | 60s | Expression sync frequency |
| `PEER_TIMEOUT_SECS` | 150s | Inactivity disconnect |
| `CHALLENGE_TIMEOUT_SECS` | **10s** | Auth challenge expiry (reduced) |
| `MIN_ELABORATION_LEN` | 20 | Minimum elaboration characters |
| `MAX_MESSAGE_SIZE` | 1 MB | Maximum network message |
| `MAX_CONNECTIONS` | 100 | Connection pool limit |
| `TRUST_DEFAULT` | 0.5 | Initial trust score |
| `TRUST_MIN_FOR_PROPOSE` | 0.4 | Minimum trust to propose |
| `MAX_EXPRESSIONS` | 100,000 | Expression store limit |
| `MAX_PROPOSALS` | 10,000 | Active proposal limit |
| `MAX_PENDING_CHALLENGES` | 1,000 | Pending challenge limit |
| `RATE_LIMIT_WINDOW_SECS` | 60s | Rate limit window |
| `RATE_LIMIT_MAX_MESSAGES` | 100 | Messages per window per peer |
| `ARGON2_MEM_COST` | 65536 | Argon2 memory (64 MB) |
| `ARGON2_TIME_COST` | 3 | Argon2 iterations |
| `ARGON2_PARALLELISM` | 4 | Argon2 threads |

---

## Error Types

| Error | Description |
|-------|-------------|
| `Io` | I/O operation failed |
| `Serialization` | Message serialization/deserialization failed |
| `Crypto` | Cryptographic operation failed (invalid key, signature verification) |
| `Validation` | Protocol validation failed |
| `InsufficientTrust` | Trust score too low for operation |
| `RateLimited` | Peer exceeded message rate limit |
| `ConnectionLost` | Connection to peer was lost |
| `MessageTooLarge` | Message exceeds 1 MB limit |
| `PoolFull` | Connection pool at capacity |
| `ChannelClosed` | Internal communication channel closed |
| `StoreFull` | Expression store at capacity (100,000) |
| `ReplayAttack` | Replayed nonce detected |
| `SelfVoteProhibited` | Cannot vote on own proposal |
| `SignatureRequired` | Valid signature required but missing/invalid |

---

## Persistence

State is persisted to `<db_path>/state.cbor` using atomic writes:

- Identity (keypair, DID)
- All expressions with CIDs
- Proposal states and quorum progress
- Pool proposals and active pools
- Epigenetic marks for all known DIDs

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
> auth quantum leap beyond horizon    # Authenticate to genesis pool (Argon2 hashed)
> connect 192.168.1.20:9070           # Connect to peer
# Wait for elaboration request...
> elaborate I am joining this network to participate in distributed governance experiments.
# Wait for signed approval from peer...
```

### Accepting Peers
```bash
# When a peer connects and elaborates, you'll see:
# 🔔 ELABORATION from abc123...
#    "Their elaboration text here"

> approve abc123                      # Approve by DID prefix (sends signed approval)
# or
> reject abc123 Insufficient elaboration
```

### Creating Proposals
```bash
> propose Implement zero-knowledge proof verification for private voting.
# [PROPOSE] 7f3a2b1c
```

### Voting
```bash
> vote 7f3a y This is essential for privacy-preserving governance systems.
# [VOTE] YES on 7f3a2b1c
# Note: You cannot vote on your own proposals
```

---

## Testing
```bash
# Run all tests (single-threaded for network tests)
cargo test -- --nocapture --test-threads=1

# Key security tests
cargo test test_self_voting_prevention
cargo test test_rate_limiter
cargo test test_nonce_tracker
cargo test test_pool_hash_argon2
cargo test test_did_generation           # Includes DID-pubkey matching
cargo test test_elaboration_scoring
cargo test test_expression_store_limits
cargo test test_derived_state_limits
cargo test test_message_signable_bytes
cargo test test_quorum_signal_signable_bytes

# Integration tests
cargo test test_three_node_mesh_async
cargo test test_two_node_connection
cargo test test_persistence
```

---

## Dependencies

- `sha2`: SHA-256 hashing
- `pqcrypto-dilithium`: Post-quantum Dilithium3 signatures
- `serde`, `bincode`, `serde_cbor`: Serialization
- `rand`: Cryptographic randomness
- `argon2`: Argon2id password hashing for pool authentication
- `smol`: Async runtime
- `async-channel`, `async-lock`: Async primitives
- `futures-lite`: Async utilities
- `hex`: Hex encoding/decoding

---

## Genesis Pools

Three pools are active at genesis (commitments shown):
```
#1 801e100b... [genesis]
#2 93a780b1... [genesis]
#3 c78dec83... [genesis]
```

**Note**: Genesis pool commitments are based on the legacy SHA256 hashing. New pools use Argon2id. Contact existing network participants to obtain genesis passphrases.

---

## Security Considerations

### Threat Model

DIAGON v0.9.1 addresses the following threats:

1. **DoS via message flooding**: Mitigated by per-peer rate limiting
2. **Replay attacks**: Mitigated by nonce tracking with time-bounded windows
3. **Sybil voting**: Mitigated by human-in-the-loop elaboration and approval
4. **Self-voting inflation**: Mitigated by explicit self-vote prohibition
5. **Unsigned message injection**: Mitigated by requiring signatures on critical messages
6. **Memory exhaustion**: Mitigated by store size limits
7. **DID spoofing**: Mitigated by DID-pubkey binding verification
8. **Expression forgery**: Mitigated by signature verification before storage
9. **Brute-force pool discovery**: Mitigated by Argon2 (memory-hard hashing)

### Remaining Considerations

- **Eclipse attacks**: Nodes should connect to multiple diverse peers
- **Long-range attacks**: Trust decay helps but doesn't fully prevent
- **Collusion**: Quorum threshold (67%) requires significant coordination
- **Key compromise**: No key rotation mechanism yet

---