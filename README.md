# DIAGON v0.9.2 Alpha

**Security Hardened P2P Governance System with Network Discovery**

*"In the struggle between truth and deception, let mathematics be the arbiter."*

---

## Table of Contents

1. [Overview](#overview)
   - [Core Principles](#core-principles)
   - [What's New in v0.9.2](#whats-new-in-v092)
   - [What's New in v0.9.1](#whats-new-in-v091-security-hardened)
2. [Architecture](#architecture)
   - [Identity](#identity)
   - [Cryptographic Choices](#cryptographic-choices)
   - [Expression Store](#expression-store)
   - [Quorum Sensing](#quorum-sensing)
   - [Epigenetic Marks (Trust)](#epigenetic-marks-trust)
   - [Pools](#pools)
3. [Network Discovery](#network-discovery)
   - [Discovery Overview](#discovery-overview)
   - [Discovery Messages](#discovery-messages)
   - [Pool Hints](#pool-hints)
   - [Discovery Flow](#discovery-flow)
4. [Security Features](#security-features)
   - [Rate Limiting](#rate-limiting)
   - [Anti-Replay Protection](#anti-replay-protection)
   - [Self-Voting Prevention](#self-voting-prevention)
   - [Signed Protocol Messages](#signed-protocol-messages)
   - [Expression Signature Verification](#expression-signature-verification)
   - [DID-Pubkey Binding](#did-pubkey-binding)
5. [Network Protocol](#network-protocol)
   - [Connection Lifecycle](#connection-lifecycle)
   - [Message Types](#message-types)
   - [Framing](#framing)
   - [Reliability](#reliability)
6. [S-Expression Format](#s-expression-format)
   - [Node Types](#node-types)
   - [Signed Expressions](#signed-expressions)
   - [Proposal Format](#proposal-format)
   - [Vote Format](#vote-format)
7. [Commands](#commands)
   - [Discovery Commands](#discovery-commands)
   - [Pool Management](#pool-management)
   - [Peer Management](#peer-management)
   - [Governance](#governance)
   - [Development](#development)
8. [Configuration Constants](#configuration-constants)
9. [Error Types](#error-types)
10. [Persistence](#persistence)
11. [Usage](#usage)
    - [Starting a Node](#starting-a-node)
    - [Discovering the Network](#discovering-the-network)
    - [Joining a Network](#joining-a-network)
    - [Accepting Peers](#accepting-peers)
    - [Creating Proposals](#creating-proposals)
    - [Voting](#voting)
12. [Testing](#testing)
13. [Dependencies](#dependencies)
14. [Genesis Pools](#genesis-pools)
15. [Security Considerations](#security-considerations)

---

## Overview

### Core Principles

- **Homoiconicity**: Code is data, data is code
- **Content-addressing**: The expression IS its identity
- **Quorum sensing**: Accumulate signals, threshold triggers
- **Derived state**: Store expressions, compute results
- **Post-quantum**: Dilithium3 signatures
- **Robust networking**: Connection pooling, message framing, reconnection
- **Security hardening**: Rate limiting, replay protection, self-vote prevention
- **Open discovery**: Find pools and peers without prior authentication

DIAGON is a peer-to-peer governance system built on biological consensus metaphors. Nodes form authenticated mesh networks within "pools" (trust domains), propose and vote on expressions using quorum sensing, and maintain replicated expression stores with content-addressed identities.

The system uses S-expressions as its fundamental data structure, enabling homoiconic representation where proposals, votes, and all protocol messages share a unified format.

### What's New in v0.9.2

**Network Discovery** - New users can now find their way into the network:

- **`probe` command**: Query any node for available pools and known peers without authentication
- **`crawl` command**: Recursively explore the network from a starting node
- **`discover` command**: Ask connected peers for network topology information
- **Pool hints**: Partial passphrase hints help users identify pools without revealing secrets
- **Unauthenticated discovery**: Discovery protocol works before pool authentication
- **DiscoveredPeer info**: Includes address, pool, expression count, and uptime
- **Genesis pool identification**: Pool hints indicate which pools are genesis vs dynamic

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

| Algorithm | Purpose | Rationale |
|-----------|---------|-----------|
| **Dilithium3** | Signatures | Post-quantum secure, protects against "harvest now, break later" |
| **SHA-256** | Content addressing | Standard (Bitcoin, IPFS, Git), ~128-bit quantum security |
| **Argon2id** | Pool passphrases | Memory-hard, resists brute-force and GPU attacks |

CIDs additionally include 256 bits of cryptographic randomness, preventing collision crafting.

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

| Parameter | Value | Description |
|-----------|-------|-------------|
| Default | 0.5 | Initial trust score |
| History weight | 0.7 | Weight of existing score |
| New weight | 0.3 | Weight of new interaction |
| Unverified cap | 0.6 | Maximum quality for unverified interactions |
| Minimum weight | 100 | Floor for signal weight |
| Propose threshold | 0.4 | Minimum trust to create proposals |

**Update formula**: `score = score × 0.7 + effective_quality × 0.3`

### Pools

Pools are trust domains defined by shared passphrases:

- **Commitment**: `Argon2id(passphrase, salt)` identifies the pool
- **Salt**: Fixed pool salt `diagon-pool-v1-salt-2024`
- **Argon2 parameters**: Memory 64MB, Time cost 3, Parallelism 4
- **Genesis pools**: Three hardcoded pools bootstrap the network
- **Dynamic pools**: New pools can be proposed and voted into existence
- **Isolation**: Nodes only connect to peers in the same pool
- **Discoverable**: Pool hints reveal partial information for discovery

---

## Network Discovery

### Discovery Overview

Discovery allows new users to find pools and peers without prior knowledge of the network. Unlike other protocol messages, discovery works **without authentication**, enabling bootstrapping from a single known address.

```
┌─────────────────────────────────────────────────────────────────┐
│                    DISCOVERY FLOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   New User                    Known Node                        │
│      │                            │                             │
│      │──── probe ────────────────>│                             │
│      │     (no auth needed)       │                             │
│      │                            │                             │
│      │<─── pool hints ────────────│                             │
│      │<─── peer addresses ────────│                             │
│      │                            │                             │
│      │                                                          │
│      │  [User obtains passphrase out-of-band]                   │
│      │                                                          │
│      │──── auth ─────────────────>│                             │
│      │──── connect ──────────────>│                             │
│      │──── elaborate ────────────>│                             │
│      │<─── approve ──────────────│                             │
│      │                            │                             │
│      │  [Now authenticated]       │                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Discovery Messages

#### Discover Request

Sent to query a node for network information:

```rust
NetMessage::Discover {
    pools: Vec<[u8; 32]>,  // Pool commitments to filter by (empty = all)
    want_hints: bool,       // Request pool hints for browsing
}
```

#### Discover Response

Returns known peers and pool information:

```rust
NetMessage::DiscoverResponse {
    peers: Vec<DiscoveredPeer>,
    pool_hints: Vec<PoolHint>,
}
```

#### DiscoveredPeer Structure

```rust
struct DiscoveredPeer {
    addr: SocketAddr,      // Network address
    pool: [u8; 32],        // Pool commitment
    expr_count: usize,     // Number of expressions stored
    uptime_secs: u64,      // How long the node has been running
}
```

#### PoolHint Structure

```rust
struct PoolHint {
    commitment: [u8; 32],  // Pool identifier
    hint: String,          // Partial passphrase (e.g., "quan...zon")
    peer_count: usize,     // Known peers in this pool
    is_genesis: bool,      // Whether this is a genesis pool
}
```

### Pool Hints

Pool hints provide partial information about passphrases to help users identify pools:

- **Format**: First 4 and last 4 characters: `"quantum leap beyond horizon"` → `"quan...zon"`
- **Auto-generated**: If no hint provided, uses commitment hex: `"801e100b..."`
- **Genesis marking**: Genesis pools are clearly identified
- **Privacy**: Hints don't reveal enough to brute-force passphrases

### Discovery Flow

#### Probe Sequence

```
┌──────────┐                              ┌──────────┐
│  Prober  │                              │  Target  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  TCP Connect                            │
     │────────────────────────────────────────>│
     │                                         │
     │  Discover { pools: [], want_hints: true }
     │────────────────────────────────────────>│
     │                                         │
     │  DiscoverResponse { peers, pool_hints } │
     │<────────────────────────────────────────│
     │                                         │
     │  TCP Close                              │
     │────────────────────────────────────────>│
     │                                         │
```

#### Crawl Sequence

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Crawler │     │  Node A  │     │  Node B  │     │  Node C  │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │  probe         │                │                │
     │───────────────>│                │                │
     │  peers: [B, C] │                │                │
     │<───────────────│                │                │
     │                │                │                │
     │  probe                          │                │
     │────────────────────────────────>│                │
     │  peers: [A, C, D]               │                │
     │<────────────────────────────────│                │
     │                │                │                │
     │  probe                                           │
     │─────────────────────────────────────────────────>│
     │  peers: [A, B]                                   │
     │<─────────────────────────────────────────────────│
     │                │                │                │
     │  [Continue until max_hops or all visited]       │
     │                │                │                │
```

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

```
┌─────────────────────────────────────────────────────────────────┐
│              EXPRESSION VERIFICATION FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. Receive expression data                                    │
│                    │                                            │
│                    ▼                                            │
│   2. Parse: (signed #x<pubkey> #x<signature> <inner>)          │
│                    │                                            │
│                    ▼                                            │
│   3. Serialize inner expression                                 │
│                    │                                            │
│                    ▼                                            │
│   4. Verify: Dilithium3.verify(signature, inner, pubkey)       │
│                    │                                            │
│           ┌───────┴───────┐                                     │
│           ▼               ▼                                     │
│       [Valid]         [Invalid]                                 │
│           │               │                                     │
│           ▼               ▼                                     │
│     Store expr       Reject with                                │
│                      Crypto error                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### DID-Pubkey Binding

During Hello exchange, DIDs are verified to match public keys:

1. Compute expected DID: `did:diagon:<hex(pubkey[0:16])>`
2. Compare against claimed DID
3. Reject connection if mismatch detected

---

## Network Protocol

### Connection Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│              AUTHENTICATED CONNECTION SEQUENCE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Initiator                              Receiver               │
│       │                                      │                  │
│       │──── TCP Connect ────────────────────>│                  │
│       │                                      │                  │
│       │──── Hello { did, pubkey, pool } ────>│                  │
│       │                                      │                  │
│       │<─── Hello { did, pubkey, pool } ─────│                  │
│       │                                      │                  │
│       │     [DID-Pubkey verification]        │                  │
│       │     [Pool matching]                  │                  │
│       │                                      │                  │
│       │<─── Challenge(nonce) ────────────────│                  │
│       │                                      │                  │
│       │──── Response(nonce, sig) ───────────>│                  │
│       │                                      │                  │
│       │     [Signature verification]         │                  │
│       │     [10 second timeout]              │                  │
│       │                                      │                  │
│       │<─── ElaborateRequest ────────────────│                  │
│       │                                      │                  │
│       │──── Elaborate { text, sig } ────────>│                  │
│       │                                      │                  │
│       │     [Human reviews elaboration]      │                  │
│       │                                      │                  │
│       │<─── Approve { ts, did, sig } ────────│                  │
│       │         or                           │                  │
│       │<─── Reject { reason, sig } ──────────│                  │
│       │                                      │                  │
│       │     [If approved: AUTHENTICATED]     │                  │
│       │                                      │                  │
│       │<─── SyncRequest ─────────────────────│                  │
│       │──── SyncReply ──────────────────────>│                  │
│       │                                      │                  │
│       │     [Full mesh participation]        │                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Message Types

| Message | Direction | Auth Required | Purpose |
|---------|-----------|---------------|---------|
| `Discover` | Any → Any | **No** | Query for peers and pool hints |
| `DiscoverResponse` | Any → Any | **No** | Return network information |
| `Hello` | Bidirectional | No | Identity and pool announcement |
| `Challenge` | Receiver → Initiator | No | 32-byte nonce for signature |
| `Response` | Initiator → Receiver | No | Signed nonce proof |
| `ElaborateRequest` | Receiver → Initiator | No | Request human elaboration |
| `Elaborate` | Initiator → Receiver | No | Signed elaboration text |
| `Approve` | Receiver → Initiator | No | Signed acceptance |
| `Reject` | Receiver → Initiator | No | Signed denial |
| `Expression` | Broadcast | **Yes** | New S-expression (verified) |
| `Signal` | Broadcast | **Yes** | Signed quorum vote |
| `SyncRequest` | Any → Any | **Yes** | Request missing expressions |
| `SyncReply` | Any → Any | **Yes** | Batch of expressions |
| `Heartbeat` | Broadcast | **Yes** | Signed keep-alive |
| `Disconnect` | Any → Any | **Yes** | Signed graceful shutdown |

### Framing

All messages are length-prefixed:
- 4-byte big-endian length header
- Maximum message size: 1 MB (verified BEFORE allocation)
- Async I/O with connection pooling

### Reliability

| Feature | Value | Description |
|---------|-------|-------------|
| Connection pool | 100 | Maximum concurrent connections |
| Reconnect attempts | 10 | With 5s intervals |
| Peer timeout | 150s | Inactivity triggers disconnect |
| Challenge timeout | 10s | Auth challenge expiry |
| Heartbeat interval | 30s | Keep-alive frequency |
| Sync interval | 60s | Expression reconciliation |
| Sync batch limit | 100 | Expressions per SyncReply |

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

### Discovery Commands

```
probe <addr>                   Query any node for peers/pools (no auth needed)
crawl <addr> <hops>            Recursively explore network (default 5 hops)
discover                       Ask connected peers for network info
```

### Pool Management

```
auth <passphrase>              Authenticate to a pool (Argon2 hashed)
list-pools                     Show active and pending pools
propose-pool <phrase> - <rationale>   Propose new pool
vote-pool <id> <y/n> <elaboration>    Vote on pool proposal
```

### Peer Management

```
connect <host:port>            Initiate connection to peer
elaborate <text>               Send signed elaboration (min 20 chars)
approve <id>                   Approve pending peer
reject <id> <reason>           Reject pending peer
```

### Governance

```
propose <text>                 Create new proposal (requires trust ≥ 0.4)
vote <cid> <y/n> <elaboration> Vote on proposal (min 20 char elaboration)
status                         Show node status, proposals, connections
```

### Development

```
eval <sexp>                    Parse and store S-expression
help                           Show command list
quit                           Graceful shutdown
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
| `CHALLENGE_TIMEOUT_SECS` | 10s | Auth challenge expiry |
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
| `Crypto` | Cryptographic operation failed |
| `Validation` | Protocol validation failed |
| `InsufficientTrust` | Trust score too low for operation |
| `RateLimited` | Peer exceeded message rate limit |
| `ConnectionLost` | Connection to peer was lost |
| `MessageTooLarge` | Message exceeds 1 MB limit |
| `PoolFull` | Connection pool at capacity |
| `ChannelClosed` | Internal communication channel closed |
| `StoreFull` | Expression store at capacity |
| `ReplayAttack` | Replayed nonce detected |
| `SelfVoteProhibited` | Cannot vote on own proposal |
| `SignatureRequired` | Valid signature required but missing |

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

### Discovering the Network

New users can discover the network knowing only a single address:

```bash
$ cargo run

> probe 192.168.1.10:9070
[PROBE] Connecting to 192.168.1.10:9070 for discovery...
[PROBE] Available pools:
  801e... "quan...zon" 5 peers [genesis]
  93a7... "shar...ret" 3 peers [genesis]
  c78d... "deep...ink" 2 peers [genesis]
[PROBE] Known peers:
  192.168.1.10:9070 in pool 801e... (1523 expr)
  192.168.1.20:9070 in pool 801e... (892 expr)
  192.168.1.30:9070 in pool 801e... (445 expr)
```

Crawl the network to find all reachable nodes:

```bash
> crawl 192.168.1.10:9070 10
[CRAWL] Starting network crawl from 192.168.1.10:9070...
[CRAWL] Probing 192.168.1.10:9070 (hop 1)... found 3 peers, 3 pools
[CRAWL] Probing 192.168.1.20:9070 (hop 2)... found 4 peers, 3 pools
[CRAWL] Probing 192.168.1.30:9070 (hop 3)... found 2 peers, 3 pools

[CRAWL] === Summary ===
[CRAWL] Visited 3 nodes
[CRAWL] Found 5 unique peers
[CRAWL] Found 3 pools

[CRAWL] Pools:
  801e... "quan...zon" [genesis]
  93a7... "shar...ret" [genesis]
  c78d... "deep...ink" [genesis]
```

### Joining a Network

Once you have the passphrase (obtained out-of-band from existing participants):

```bash
> auth quantum leap beyond horizon
[OK] Pool authenticated: 801e100b...

> connect 192.168.1.10:9070
[->] Connecting to 192.168.1.10:9070

# Wait for elaboration request...
> elaborate I discovered this network through probing and want to participate in governance.
[->] Elaboration sent

# Wait for approval from peer...
[OK] Authenticated with 192.168.1.10:9070

# Ask authenticated peers for more network info
> discover
[DISCOVER] Asking 1 peer(s) for network info...
[DISCOVER] Received 2 peer(s) from 192.168.1.10:9070:
  192.168.1.20:9070 (pool: 801e..., 892 expr) [same-pool]
  192.168.1.30:9070 (pool: 801e..., 445 expr) [same-pool]
```

### Accepting Peers

```bash
# When a peer connects and elaborates:
# 🔔 ELABORATION from abc123...
#    "Their elaboration text here"

> approve abc123                      # Approve by DID prefix
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

# Discovery tests (v0.9.2)
cargo test test_pool_hints
cargo test test_discovery_messages
cargo test test_two_node_discovery
cargo test test_discovery_without_auth

# Security tests (v0.9.1)
cargo test test_self_voting_prevention
cargo test test_rate_limiter
cargo test test_nonce_tracker
cargo test test_pool_hash_argon2
cargo test test_did_generation
cargo test test_elaboration_scoring
cargo test test_expression_store_limits

# Integration tests
cargo test test_three_node_mesh_async
cargo test test_two_node_connection
cargo test test_persistence
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `sha2` | SHA-256 hashing |
| `pqcrypto-dilithium` | Post-quantum Dilithium3 signatures |
| `serde`, `bincode`, `serde_cbor` | Serialization |
| `rand` | Cryptographic randomness |
| `argon2` | Argon2id password hashing |
| `smol` | Async runtime |
| `async-channel`, `async-lock` | Async primitives |
| `futures-lite` | Async utilities |
| `hex` | Hex encoding/decoding |

---

## Genesis Pools

Three pools are active at genesis (commitments shown):

```
#1 801e100b... [genesis]
#2 93a780b1... [genesis]
#3 c78dec83... [genesis]
```

**Note**: Genesis pool commitments are based on legacy SHA256 hashing. New pools use Argon2id. Use `probe` to discover pools and contact existing participants to obtain passphrases.

---

## Security Considerations

### Threat Model

DIAGON v0.9.2 addresses the following threats:

| Threat | Mitigation |
|--------|------------|
| DoS via message flooding | Per-peer rate limiting |
| Replay attacks | Nonce tracking with time-bounded windows |
| Sybil voting | Human-in-the-loop elaboration and approval |
| Self-voting inflation | Explicit self-vote prohibition |
| Unsigned message injection | Signatures required on critical messages |
| Memory exhaustion | Store size limits |
| DID spoofing | DID-pubkey binding verification |
| Expression forgery | Signature verification before storage |
| Brute-force pool discovery | Argon2 (memory-hard hashing) |
| Network enumeration | Intentionally allowed for bootstrapping |

### Discovery Security Notes

1. **Discovery reveals pool commitments** - By design, so users can find pools
2. **Pool hints are partial** - `"quan...zon"` doesn't reveal full passphrase
3. **No consensus state leaked** - Only peer addresses and existence
4. **Rate limiting applies** - Probe connections are short-lived
5. **No auth bypass** - Discovery shows addresses only; still need passphrase + elaboration + approval

### Remaining Considerations

- **Eclipse attacks**: Nodes should connect to multiple diverse peers
- **Long-range attacks**: Trust decay helps but doesn't fully prevent
- **Collusion**: Quorum threshold (67%) requires significant coordination
- **Key compromise**: No key rotation mechanism yet
- **Network topology leakage**: Crawling reveals network structure (intentional for bootstrapping)