# DIAGON v0.9.2 Alpha

**P2P Governance System with Post-Quantum Signatures and Network Discovery**

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Network Discovery](#network-discovery)
4. [Security](#security)
5. [Network Protocol](#network-protocol)
6. [S-Expression Format](#s-expression-format)
7. [Commands](#commands)
8. [Configuration](#configuration)
9. [Usage](#usage)
10. [Testing](#testing)
11. [Dependencies](#dependencies)

---

## Overview

DIAGON is a peer-to-peer governance system. Nodes form authenticated mesh networks within pools (trust domains), propose and vote on expressions using weighted quorum, and maintain replicated content-addressed stores.

### Features

- **Post-quantum signatures**: Dilithium3 for all authentication and signing
- **Content-addressed storage**: SHA-256 CIDs with cryptographic randomness
- **Weighted quorum**: 67% threshold with time-decaying vote weights
- **S-expression protocol**: Homoiconic format for proposals, votes, and messages
- **Pool-based authentication**: Argon2id-hashed passphrases define trust domains
- **Network discovery**: Probe, crawl, and discover commands for bootstrapping
- **Human-in-the-loop**: Elaboration and approval required for peer connections
- **Rate limiting**: Per-peer message limits prevent flooding
- **Anti-replay protection**: Nonce tracking with time-bounded windows
- **Self-vote prevention**: Proposers cannot vote on their own proposals
- **Signed protocol messages**: Critical messages require cryptographic signatures
- **Expression verification**: Signatures verified before storage

---

## Architecture

### Identity

| Component | Description |
|-----------|-------------|
| DID | `did:diagon:<hex(pubkey[0:16])>` |
| Keypair | Dilithium3 (post-quantum) |
| Verification | DID-pubkey binding checked during handshake |
| Persistence | CBOR-serialized to disk |

### Cryptography

| Algorithm | Purpose |
|-----------|---------|
| Dilithium3 | Signatures (post-quantum) |
| SHA-256 | Content addressing |
| Argon2id | Pool passphrase hashing (64MB, 3 iterations, 4 threads) |

### Expression Store

- **CID**: `SHA256(data || 256-bit random || timestamp)`
- **Deduplication**: Content-identical expressions share CIDs
- **Merkle root**: Commitment over expression log
- **Limits**: 100,000 expressions maximum
- **Verification**: Signed expressions verified before storage

### Quorum

- **Threshold**: `⌈(peer_count + 1) × 0.67 × 1000⌉` (minimum 1000)
- **Decay**: Exponential with 5-minute half-life
- **Weight**: Based on sender's trust score
- **Constraints**: One vote per DID, no self-voting, signature required

### Trust Scores

| Parameter | Value |
|-----------|-------|
| Default | 0.5 |
| Update formula | `score = score × 0.7 + quality × 0.3` |
| Unverified cap | 0.6 |
| Minimum weight | 100 |
| Propose threshold | 0.4 |

### Pools

- **Commitment**: `Argon2id(passphrase, "diagon-pool-v1-salt-2024")`
- **Genesis pools**: 3 hardcoded pools bootstrap the network
- **Dynamic pools**: New pools proposed and voted into existence
- **Isolation**: Peers only connect within the same pool

---

## Network Discovery

Discovery enables bootstrapping without prior network knowledge. Unlike other messages, discovery works **without authentication**.

### Commands

| Command | Description |
|---------|-------------|
| `probe <addr>` | Query node for peers/pools (no auth) |
| `crawl <addr> <hops>` | Recursive network exploration |
| `discover` | Ask authenticated peers for topology |

### Messages

```rust
// Request
Discover { pools: Vec<[u8; 32]>, want_hints: bool }

// Response
DiscoverResponse { peers: Vec<DiscoveredPeer>, pool_hints: Vec<PoolHint> }

// Peer info
DiscoveredPeer { addr, pool, expr_count, uptime_secs }

// Pool info
PoolHint { commitment, hint, peer_count, is_genesis }
```

### Pool Hints

Format: First 4 + last 3 characters of passphrase (`"quantum leap beyond horizon"` → `"quan...zon"`).

Hints allow pool identification without revealing enough to brute-force.

---

## Security

### Protections

| Threat | Mitigation |
|--------|------------|
| Message flooding | Per-peer rate limiting (100/60s) |
| Replay attacks | Nonce tracking (20s window) |
| Sybil voting | Human elaboration + approval |
| Self-voting | Explicit prohibition |
| Unsigned injection | Signatures on critical messages |
| Memory exhaustion | Store size limits |
| DID spoofing | DID-pubkey binding verification |
| Expression forgery | Signature verification |
| Brute-force pools | Argon2id (memory-hard) |

### Signed Messages

| Message | Signed Data |
|---------|-------------|
| Approve | `"approve:" + timestamp + peer_did` |
| Reject | `"reject:" + reason` |
| Heartbeat | `"heartbeat:" + timestamp` |
| Disconnect | `"disconnect:" + timestamp` |
| Elaborate | elaboration text |

### Verification Flow

1. Parse `(signed #x<pubkey> #x<signature> <inner>)`
2. Serialize inner expression
3. Verify with Dilithium3
4. Store if valid, reject otherwise

---

## Network Protocol

### Connection Sequence

```
Initiator                           Receiver
    │                                   │
    │── Hello { did, pubkey, pool } ───>│
    │<── Hello { did, pubkey, pool } ───│
    │       [DID-pubkey verification]   │
    │       [Pool matching]             │
    │<── Challenge(nonce) ──────────────│
    │── Response(nonce, sig) ──────────>│
    │       [10s timeout]               │
    │<── ElaborateRequest ──────────────│
    │── Elaborate { text, sig } ───────>│
    │       [Human review]              │
    │<── Approve/Reject ────────────────│
    │       [If approved: AUTHENTICATED]│
```

### Message Types

| Message | Auth Required | Purpose |
|---------|---------------|---------|
| Discover | No | Query peers/pools |
| DiscoverResponse | No | Return network info |
| Hello | No | Identity exchange |
| Challenge | No | Auth nonce |
| Response | No | Signed nonce |
| ElaborateRequest | No | Request elaboration |
| Elaborate | No | Signed elaboration |
| Approve/Reject | No | Connection decision |
| Expression | Yes | Broadcast S-expression |
| Signal | Yes | Quorum vote |
| SyncRequest/Reply | Yes | Expression sync |
| Heartbeat | Yes | Keep-alive |
| Disconnect | Yes | Graceful shutdown |

### Framing

- 4-byte big-endian length prefix
- Maximum 1 MB per message
- Size verified before allocation

### Timeouts

| Parameter | Value |
|-----------|-------|
| Connection pool | 100 |
| Reconnect attempts | 10 × 5s |
| Peer timeout | 150s |
| Challenge timeout | 10s |
| Heartbeat interval | 30s |
| Sync interval | 60s |
| Sync batch | 100 expressions |

---

## S-Expression Format

### Node Types

| Type | Syntax |
|------|--------|
| Nil | `()` |
| Atom | `symbol` |
| Int | 64-bit signed |
| Bytes | `#x<hex>` |
| Cons | `(car . cdr)` |

### Signed Envelope

```lisp
(signed #x<pubkey> #x<signature> <inner>)
```

### Proposal

```lisp
(signed #x<pubkey> #x<sig>
  (propose "proposal text" "elaboration"))
```

### Vote

```lisp
(signed #x<pubkey> #x<sig>
  (vote #x<target-cid> yes|no "elaboration"))
```

---

## Commands

### Discovery

```
probe <addr>                    Query node for peers/pools
crawl <addr> <hops>             Recursive exploration (default 5)
discover                        Ask peers for network info
```

### Pool Management

```
auth <passphrase>               Authenticate to pool
list-pools                      Show pools
propose-pool <phrase> - <text>  Propose new pool
vote-pool <id> <y/n> <text>     Vote on pool
```

### Peer Management

```
connect <host:port>             Connect to peer
elaborate <text>                Send elaboration (min 20 chars)
approve <id>                    Approve peer
reject <id> <reason>            Reject peer
```

### Governance

```
propose <text>                  Create proposal (trust ≥ 0.4)
vote <cid> <y/n> <text>         Vote (min 20 char elaboration)
status                          Show status
```

### Development

```
eval <sexp>                     Parse and store expression
help                            Show commands
quit                            Shutdown
```

---

## Configuration

| Constant | Value |
|----------|-------|
| Quorum threshold | 67% |
| Signal half-life | 300s |
| Heartbeat interval | 30s |
| Sync interval | 60s |
| Peer timeout | 150s |
| Challenge timeout | 10s |
| Min elaboration | 20 chars |
| Max message | 1 MB |
| Max connections | 100 |
| Default trust | 0.5 |
| Propose threshold | 0.4 |
| Max expressions | 100,000 |
| Max proposals | 10,000 |
| Rate limit | 100 msg/60s/peer |
| Argon2 memory | 64 MB |
| Argon2 iterations | 3 |
| Argon2 parallelism | 4 |

---

## Usage

### Start Node

```bash
cargo run                              # localhost:9070
cargo run -- 192.168.1.10:9070 /data   # custom addr/path
```

### Discover Network

```bash
> probe 192.168.1.10:9070
[PROBE] Available pools:
  801e... "quan...zon" 5 peers [genesis]
[PROBE] Known peers:
  192.168.1.10:9070 (1523 expr)
  192.168.1.20:9070 (892 expr)

> crawl 192.168.1.10:9070 10
[CRAWL] Visited 8 nodes, found 12 peers, 3 pools
```

### Join Network

```bash
> auth quantum leap beyond horizon
[OK] Pool: 801e100b...

> connect 192.168.1.10:9070
> elaborate I want to participate in governance decisions.
# Wait for approval...
[OK] Authenticated
```

### Governance

```bash
> propose Implement zero-knowledge voting
[PROPOSE] 7f3a2b1c

> vote 7f3a y Essential for privacy.
[VOTE] YES on 7f3a2b1c
```

---

## Testing

```bash
cargo test -- --test-threads=1

# Discovery
cargo test test_pool_hints
cargo test test_discovery_messages
cargo test test_two_node_discovery

# Security
cargo test test_self_voting_prevention
cargo test test_rate_limiter
cargo test test_nonce_tracker
cargo test test_pool_hash_argon2

# Integration
cargo test test_three_node_mesh_async
cargo test test_persistence
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| pqcrypto-dilithium | Dilithium3 signatures |
| sha2 | SHA-256 |
| argon2 | Password hashing |
| serde, bincode, serde_cbor | Serialization |
| smol | Async runtime |
| rand | Cryptographic randomness |

---

## Genesis Pools

```
#1 801e100b... [genesis]
#2 93a780b1... [genesis]
#3 c78dec83... [genesis]
```

Genesis pools use legacy SHA256. New pools use Argon2id. Use `probe` to discover pools; obtain passphrases out-of-band.