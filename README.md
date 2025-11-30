# Quorum IO - Node

`QUORUM IO: NODE: DIAGON`

**Headless P2P Governance System for Decentralized Knowledge Transmission**

Byzantine fault-tolerant peer-to-peer network enabling democratic governance of shared knowledge through cryptographically-verified consensus. Post-quantum cryptography, trust scoring, elaboration-based decision-making, and democratic content moderation over TCP mesh.

## Abstract

Quorum Node (DIAGON) is a decentralized trust network implementing semantic authentication through a novel challenge-response protocol that combines cryptographic verification with human-in-the-loop elaboration and **democratic genesis governance**. The protocol uses:

- **Pool commitments** for genesis phrase verification (SHA-256)
- **Dilithium3** post-quantum signatures for all network actions
- **Mandatory natural language elaboration** to establish trust relationships
- **Trust scoring** based on elaboration quality (vocabulary diversity + substance)
- **Democratic pruning** for collective content moderation
- **DIDs & CIDs** similar to Bluesky for identity and content addressing
- **Byzantine fault-tolerant voting** (67% threshold) for network governance

## Philosophy

> "Organization through democracy, Trust through mathematics, Meaning through elaboration"

**The Quorum Node Thesis**: True decentralized trust emerges not from eliminating human judgment but from structuring it through democratic processes, cryptographic verification, and semantic elaboration. The network becomes a living system where trust domains can grow, merge, and evolve based on collective human wisdom rather than algorithmic decree.

*Knowledge wants freedom. Trust requires verifiable proof.*

## Features

- **Post-Quantum Security**: Dilithium3 lattice-based signatures resistant to quantum attacks
- **Content Addressing**: Deterministic CIDs derived from content + timestamp + creator
- **Decentralized Identity**: DIDs derived from public keys (`did:diagon:<hash>`)
- **Trust Scoring**: Elaboration quality measured by vocabulary diversity and substance
- **Trust-Gated Proposals**: Participation rights earned through quality contributions
- **Democratic Pruning**: Community-voted content removal with re-addition prevention
- **Pool Isolation**: Networks isolated by shared passphrase commitment
- **State Sync**: Automatic synchronization of entries on peer connection
- **Validated Persistence**: Signature verification on state reload (corrupted entries rejected)
- **Atomic Persistence**: Crash-safe identity and governance state storage
- **Cross-Platform**: Windows and Unix support with graceful shutdown handling

## What's New in 0.5.1

| Feature | Description |
|---------|-------------|
| **Trust Scoring** | `score_elaboration()` measures vocabulary diversity + length; scores range 0.0-1.0 |
| **Trust-Gated Proposals** | Must have trust ≥ 0.4 to create proposals or prune requests |
| **Democratic Pruning** | `EntryType::Prune` allows community to vote on content removal |
| **Entry Type Tracking** | Proposals store their `entry_type` for proper execution logic |
| **Validated Persistence** | Entries verified (CID + signature) on reload; invalid entries rejected |
| **Pruned CID Tracking** | Removed content cannot be re-added to the network |

## Architecture

```
+------------------------------------------------------------------+
|                         Quorum Node                              |
+------------------------------------------------------------------+
|  +-------------+  +-------------+  +-------------------------+   |
|  |  Identity   |  |  Governance |  |      Peer Manager       |   |
|  |  (Dilithium)|  |    Actor    |  |                         |   |
|  +-------------+  +-------------+  +-------------------------+   |
|  | - DID       |  | - Entries   |  | - PeerHandle (light)    |   |
|  | - Keypair   |  | - Proposals |  | - ConnectionActor       |   |
|  | - Pool Hash |  | - Trust     |  | - Message Routing       |   |
|  |             |  | - Pruned    |  | - Heartbeat/Timeout     |   |
|  +-------------+  +-------------+  +-------------------------+   |
+------------------------------------------------------------------+
|                      TCP Mesh Network                            |
|              (Mutual Challenge-Response Authentication)          |
+------------------------------------------------------------------+
```

### Trust System

```
                    ┌─────────────────────────────────────┐
                    │         Trust Evolution             │
                    └─────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
         ▼                          ▼                          ▼
   ┌───────────┐            ┌───────────┐            ┌───────────┐
   │  Initial  │            │  Quality  │            │   Poor    │
   │   0.50    │            │  Content  │            │  Content  │
   └───────────┘            └───────────┘            └───────────┘
         │                        │                        │
         │                        ▼                        ▼
         │                  Trust Rises              Trust Falls
         │                   (→ 1.0)                  (→ 0.0)
         │                        │                        │
         ▼                        ▼                        ▼
   ┌───────────────────────────────────────────────────────────┐
   │              Proposal Rights (trust ≥ 0.4)                │
   │                                                           │
   │  ✓ Create proposals    ✓ Propose pruning                  │
   │  ✓ Vote on proposals   ✓ Participate in governance        │
   └───────────────────────────────────────────────────────────┘
```

### Protocol Flow

```
Client                              Server
  |                                    |
  |--- Connect(DID, PubKey, Pool) ---->|
  |                                    | Verify pool commitment
  |<-- Challenge(Nonce, ServerSig) ----|
  |     Verify server signature        |
  |--- Response(Signature, Elab) ----->|
  |                                    | Verify client signature
  |                                    | Update trust from elaboration
  |<-- Authenticated(ServerDID) -------|
  |                                    |
  |--- SyncRequest(KnownCIDs) -------->|
  |<-- SyncReply(MissingEntries) ------|
  |                                    |
```

### Prune Lifecycle

```
  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
  │   Content   │────▶│   Prune     │────▶│   Voting    │
  │   Exists    │     │  Proposed   │     │  (67%+)     │
  └─────────────┘     └─────────────┘     └─────────────┘
                                                 │
                                                 ▼
  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
  │  Re-add     │◀───X│   CID in    │◀────│   Content   │
  │  Blocked    │     │ pruned_cids │     │   Removed   │
  └─────────────┘     └─────────────┘     └─────────────┘
```

## Building

### Prerequisites

- Rust 1.70+ (stable)
- Cargo

### Compile

```bash
# Debug build
cargo build

# Release build (recommended)
cargo build --release
```

### Test

```bash
# Run all tests (single-threaded for network tests)
cargo test -- --test-threads=1

# With output
cargo test -- --test-threads=1 --nocapture
```

### Test Coverage

| Test | Validates |
|------|-----------|
| `test_trust_scoring` | Elaboration quality measurement |
| `test_trust_gated_proposals` | Trust decay with poor participation |
| `test_prune_lifecycle` | Full prune→vote→execute→block-readd cycle |
| `test_entry_type_tracking` | Proposal stores its entry type |
| `test_persistence_with_validation` | State survives restart with validation |
| `test_invalid_entry_rejected_on_load` | Corrupted signatures rejected |
| `test_two_node_with_trust` | Trust updates propagate between nodes |
| `test_mesh_with_prune` | 3-node network with democratic pruning |
| `test_identity_persistence` | DID survives restart |
| `test_signature_verification` | Tampered entries rejected |
| `test_pool_mismatch_rejected` | Different pools cannot connect |

## Usage

### Starting a Node

```bash
# Start on default port 9090 with default pool
./target/release/diagon

# Start on specific port with custom pool
./target/release/diagon 127.0.0.1:9091 my_secret_pool

# Start and connect to existing peer
./target/release/diagon 127.0.0.1:9092 my_secret_pool 127.0.0.1:9091
```

### Command Line Interface

Once running, the node accepts these commands:

```
Commands:
  propose <text...>                 - Create votable proposal (requires trust >= 0.4)
  prune <cid> <reason>              - Propose democratic removal (requires trust >= 0.4)
  knowledge <cat> <concept> <content> <elaboration>
  vote <cid> <yes|no> <elaboration>
  connect <addr>
  status
  quit
```

### Examples

```bash
# Create a proposal (text must be >= 20 chars, trust must be >= 0.4)
propose This is a governance proposal that needs community approval

# Add knowledge entry (no trust requirement)
knowledge Protocol Security "Post-quantum signatures" This elaboration explains the entry

# Vote on a proposal (use CID prefix from status)
vote a1b2c3d4 yes I support this proposal because it improves security

# Propose removal of harmful content
prune a1b2c3d4 This content violates our community guidelines and should be removed

# Check node status (shows trust level)
status

# Connect to another peer
connect 127.0.0.1:9092
```

### Status Output

```
=== NODE STATUS ===
DID: did:diagon:8425a...16eefb
Pool: f8797dea588a628f
Trust: 0.65 (can propose: true)
Entries: 12 (verified)
Proposals: 2
Known pubkeys: 5
Pruned CIDs: 1
Peers: 3
  - did:diagon:f941a..3ba16d (trust: 0.72, seen 5.2s ago)
  - did:diagon:dbd18..28ed20 (trust: 0.58, seen 2.1s ago)
  - did:diagon:141c6..5a0792 (trust: 0.44, seen 8.3s ago)
Active proposals:
  6e1e7676 [PRUNE] - 2/3 votes
  a1b2c3d4 [PROPOSAL] - 1/3 votes (EXECUTED)
```

## Data Storage

Node data is stored in `db/<address_hash>/`:

```
db/
  <hash>/
    identity.cbor    # Keypair and DID (post-quantum safe)
    governance.cbor  # Entries, proposals, trust scores, pruned CIDs, pubkeys
```

### Persistence Format (governance.cbor)

```rust
SavedState {
    entries: HashMap<Cid, Entry>,
    proposals: HashMap<Cid, Proposal>,
    trust_scores: HashMap<Did, TrustScore>,
    pruned_cids: HashSet<Cid>,
    pubkeys: HashMap<Did, Vec<u8>>,
}
```

Identity persists across restarts. State is atomically saved every 30 seconds and on shutdown. On reload, all entries are validated (CID integrity + signature verification).

## Security Model

### Cryptographic Guarantees

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Signatures | Dilithium3 | NIST PQC Level 3 |
| Hashing | SHA-256 | 128-bit collision |
| Pool Auth | SHA-256 commitment | Pre-image resistant |
| Comparison | Constant-time XOR | Timing-attack resistant |

### Trust Model

1. **Pool Membership**: Only nodes with matching pool commitment can connect
2. **Signature Verification**: All entries and votes cryptographically signed
3. **CID Binding**: Content addresses prevent tampering
4. **Trust Scoring**: Elaboration quality determines participation rights
5. **Byzantine Tolerance**: 67% threshold for proposal execution
6. **Democratic Pruning**: Community can remove content by vote
7. **Validated Reload**: Corrupted/tampered entries rejected on restart

### Trust Scoring Algorithm

```rust
fn score_elaboration(text: &str) -> f64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    let unique: HashSet<&str> = words.iter().copied().collect();
    
    // Vocabulary diversity (0.0 - 1.0)
    let uniqueness = unique.len() as f64 / words.len() as f64;
    
    // Substance score, caps at 100 words (0.0 - 1.0)
    let length_score = (words.len() as f64 / 100.0).min(1.0);
    
    // Equal weight to diversity and substance
    (uniqueness * 0.5 + length_score * 0.5).clamp(0.0, 1.0)
}

// Trust update: 70% history, 30% new score
new_trust = (old_trust * 0.7) + (elaboration_score * 0.3)
```

## Protocol Messages

| Message | Phase | Direction | Purpose |
|---------|-------|-----------|---------|
| `Connect` | Auth | C→S | Initiate with DID, pubkey, pool |
| `Challenge` | Auth | S→C | Send nonce with server signature |
| `Response` | Auth | C→S | Client signature + elaboration |
| `Authenticated` | Auth | S→C | Confirm mutual authentication |
| `Propose` | Gov | Broadcast | Submit new proposal |
| `Vote` | Gov | Broadcast | Cast signed vote |
| `SyncRequest` | Sync | C→S | Request missing entries |
| `SyncReply` | Sync | S→C | Send missing entries |
| `NewEntry` | Sync | Broadcast | Propagate new entry |
| `Heartbeat` | Keep | Both | Connection liveness (30s) |

## Entry Types

| Type | Votable | Purpose |
|------|---------|---------|
| `Knowledge` | No | Store categorized information |
| `Proposal` | Yes | Governance decisions requiring consensus |
| `Prune` | Yes | Democratic content removal |

## Configuration Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_MESSAGE_SIZE` | 1MB | Maximum protocol message |
| `AUTH_TIMEOUT_SECS` | 30s | Handshake timeout |
| `MIN_ELABORATION_LEN` | 20 | Minimum elaboration length |
| `MAX_ELABORATION_LEN` | 10KB | Maximum elaboration length |
| `MAX_ENTRY_DATA_SIZE` | 60KB | Maximum entry payload |
| `HEARTBEAT_SECS` | 30s | Keepalive interval |
| `PEER_TIMEOUT_SECS` | 150s | Peer inactivity timeout |
| `MAX_TIMESTAMP_DRIFT_SECS` | 300s | Clock skew tolerance |
| `MIN_TRUST_FOR_PROPOSALS` | 0.4 | Trust threshold for proposals |
| `INITIAL_TRUST` | 0.5 | Starting trust for new participants |

## Changelog

### v0.5.1
- Added trust scoring based on elaboration quality
- Added trust-gated proposals (requires trust ≥ 0.4)
- Added democratic pruning with `EntryType::Prune`
- Added entry type tracking in proposals
- Added validated persistence (signature verification on reload)
- Added pruned CID tracking to prevent re-addition
- Enhanced status output with trust levels

### v0.5.0
- Actor-based architecture with PeerHandle/ConnectionActor separation
- Mutual authentication (server proves identity)
- Constant-time pool comparison
- Deterministic CID generation
- Improved Windows compatibility

## License

Custom GNU-LGPL

---

*"In the struggle between truth and deception, let mathematics be the arbiter."*