# DIAGON v0.9.0

**Headless P2P Governance System for Decentralized Knowledge Transmission**

*"In the struggle between truth and deception, let mathematics be the arbiter."*

Core principles:
- Homoiconicity: Code is data, data is code
- Content-addressing: The expression IS its identity
- Quorum sensing: Accumulate signals, threshold triggers
- Derived state: Store expressions, compute results
- Post-quantum: Dilithium3 signatures
- Robust networking: Connection pooling, message framing, reconnection

---

## Overview

DIAGON is a peer-to-peer governance system built on biological consensus metaphors. Nodes form authenticated mesh networks within "pools" (trust domains), propose and vote on expressions using quorum sensing, and maintain replicated expression stores with content-addressed identities.

The system uses S-expressions as its fundamental data structure, enabling homoiconic representation where proposals, votes, and all protocol messages share a unified format.

## Architecture

### Identity

- **DID (Decentralized Identifier)**: Derived from Dilithium3 public key (`did:diagon:<hex>`)
- **Post-quantum signatures**: All authentication and message signing uses Dilithium3
- **Key persistence**: Identity survives restarts via CBOR-serialized state

### Expression Store

- **Content-addressed**: Every expression has a unique CID (SHA256 hash including nonce and timestamp)
- **Arena allocator**: Efficient S-expression memory management with interning
- **Merkle root**: Log of all expressions produces a verifiable state commitment
- **Automatic deduplication**: Identical expressions resolve to same CID

### Quorum Sensing

Inspired by bacterial quorum sensing, consensus emerges from accumulated signals:

- **Threshold**: `⌈(peer_count + 1) × 0.67 × 1000⌉` (minimum 1000)
- **Signal decay**: Exponential with 5-minute half-life
- **Weight**: Based on sender's epigenetic mark (trust score)
- **One vote per source**: Duplicate signals from same DID are rejected

### Epigenetic Marks (Trust)

Trust scores evolve based on participation quality:

- **Default**: 0.5
- **Update formula**: `score = score × 0.7 + quality × 0.3`
- **Decay**: Score decays toward baseline when inactive
- **Signal weight**: `max(score × 1000, 100)`
- **Proposal threshold**: Trust ≥ 0.4 required to propose

### Pools

Pools are trust domains defined by shared passphrases:

- **Commitment**: `SHA256(passphrase)` identifies the pool
- **Genesis pools**: Three hardcoded pools bootstrap the network
- **Dynamic pools**: New pools can be proposed and voted into existence
- **Isolation**: Nodes only connect to peers in the same pool

## Network Protocol

### Connection Lifecycle

1. **TCP Connect**: Initiator connects to receiver
2. **Hello Exchange**: Both sides send `Hello { did, pubkey, pool, expr_root }`
3. **Challenge-Response**: Cryptographic verification via signed nonces
4. **Elaboration (HITL)**: Initiator must provide human-written elaboration (≥20 chars)
5. **Approval/Rejection**: Receiver manually approves or rejects with reason
6. **Authenticated**: Connection enters full mesh participation

### Message Types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `Hello` | Bidirectional | Identity and pool announcement |
| `Challenge` | Receiver → Initiator | 32-byte nonce for signature |
| `Response` | Initiator → Receiver | Signed nonce proof |
| `ElaborateRequest` | Receiver → Initiator | Request human elaboration |
| `Elaborate` | Initiator → Receiver | Signed elaboration text |
| `Approve` | Receiver → Initiator | Accept peer into mesh |
| `Reject` | Receiver → Initiator | Deny with reason |
| `Expression` | Broadcast | New S-expression to replicate |
| `Signal` | Broadcast | Quorum vote signal |
| `SyncRequest` | Any → Any | Request missing expressions |
| `SyncReply` | Any → Any | Batch of expressions |
| `Heartbeat` | Broadcast | Keep-alive (30s interval) |
| `Disconnect` | Any → Any | Graceful shutdown |

### Framing

All messages are length-prefixed:
- 4-byte big-endian length header
- Maximum message size: 1 MB
- Non-blocking I/O with 100ms read timeout

### Reliability

- **Connection pool**: Maximum 100 concurrent connections
- **Automatic reconnection**: Up to 10 attempts with 5s intervals
- **Peer timeout**: 150 seconds of inactivity triggers disconnect
- **Challenge timeout**: 30 seconds to complete authentication
- **Heartbeat**: 30-second interval keeps connections alive
- **Sync**: 60-second interval reconciles expression stores

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

## Commands

### Pool Management
```
auth <passphrase>              Authenticate to a pool
list-pools                     Show active and pending pools
propose-pool <phrase> - <rationale>   Propose new pool
vote-pool <id> <y/n> <elaboration>    Vote on pool proposal
```

### Peer Management
```
connect <host:port>            Initiate connection to peer
elaborate <text>               Send elaboration (min 20 chars)
approve <id>                   Approve pending peer (by DID prefix or address)
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
> auth quantum leap beyond horizon    # Authenticate to genesis pool
> connect 192.168.1.20:9070           # Connect to peer
# Wait for elaboration request...
> elaborate I am joining this network to participate in distributed governance experiments.
# Wait for approval from peer...
```

### Accepting Peers
```bash
# When a peer connects and elaborates, you'll see:
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
```

## Configuration Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `EIGEN_THRESHOLD` | 0.67 | Quorum threshold (67%) |
| `SIGNAL_HALF_LIFE` | 300s | Vote decay half-life |
| `HEARTBEAT_INTERVAL` | 30s | Keep-alive frequency |
| `SYNC_INTERVAL` | 60s | Expression sync frequency |
| `PEER_TIMEOUT_SECS` | 150s | Inactivity disconnect |
| `CHALLENGE_TIMEOUT_SECS` | 30s | Auth challenge expiry |
| `MIN_ELABORATION_LEN` | 20 | Minimum elaboration characters |
| `MAX_MESSAGE_SIZE` | 1 MB | Maximum network message |
| `MAX_CONNECTIONS` | 100 | Connection pool limit |
| `TRUST_DEFAULT` | 0.5 | Initial trust score |
| `TRUST_MIN_FOR_PROPOSE` | 0.4 | Minimum trust to propose |

## Persistence

State is persisted to `<db_path>/state.cbor` using atomic writes:

- Identity (keypair, DID)
- All expressions with CIDs
- Proposal states and quorum progress
- Pool proposals and active pools
- Epigenetic marks for all known DIDs
- Nonce counter for CID generation

## Testing
```bash
# Run all tests (single-threaded for network tests)
cargo test -- --nocapture --test-threads=1

# Individual tests
cargo test test_node_creation
cargo test test_pool_authentication
cargo test test_sexp_arena
cargo test test_expression_store
cargo test test_quorum_sensing
cargo test test_three_node_mesh
```

## Dependencies

- `sha2`: SHA-256 hashing
- `pqcrypto-dilithium`: Post-quantum Dilithium3 signatures
- `serde`, `bincode`, `serde_cbor`: Serialization
- `rand`: Cryptographic randomness

## Genesis Pools

Three pools are active at genesis (commitments shown):
```
#1 801e100b... [genesis]
#2 93a780b1... [genesis]
#3 c78dec83... [genesis]
```

Contact existing network participants to obtain genesis passphrases.