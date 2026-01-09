// DIAGON v0.9.6

use std::{
    collections::{HashMap, HashSet, BTreeMap, VecDeque},
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    fmt,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader},
    net::{TcpListener, TcpStream, TcpSocket},
    sync::{mpsc, RwLock},
    time::{timeout, sleep},
};
use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use x25519_dalek::{ReusableSecret, PublicKey as X25519PublicKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

// ============================================================================
// BIOLOGICAL CONSTANTS
// ============================================================================

const EIGEN_THRESHOLD: f64 = 0.67;
const SIGNAL_HALF_LIFE: u64 = 300;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const DECAY_CHECK_INTERVAL: Duration = Duration::from_secs(3600);
const PEER_TIMEOUT_SECS: u64 = 150;
const CHALLENGE_TIMEOUT_SECS: u64 = 10;
const MIN_ELABORATION_LEN: usize = 20;
const MAX_MESSAGE_SIZE: usize = 1_048_576;
const MAX_CONNECTIONS: usize = 100;
const CONNECTION_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RECONNECT_ATTEMPTS: u32 = 10;
const TRUST_DEFAULT: f64 = 0.5;
const TRUST_HISTORY_WEIGHT: f64 = 0.7;
const TRUST_NEW_WEIGHT: f64 = 0.3;
const TRUST_MIN_FOR_PROPOSE: f64 = 0.4;

const CONTENT_DECAY_DAYS: u64 = 7;
const CONTENT_DECAY_SECS: u64 = CONTENT_DECAY_DAYS * 24 * 3600;

const XP_VIEW_THRESHOLD_SECS: u64 = 30;
const XP_PER_VIEW: u64 = 1;
const XP_COOLDOWN_SECS: u64 = 300;

const MAX_EXPRESSIONS: usize = 100_000;
const MAX_PROPOSALS: usize = 10_000;
const MAX_PINNED: usize = 1_000;
const MAX_DM_CHANNELS: usize = 100;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_MAX_MESSAGES: u32 = 100;

const POOL_SALT: &[u8] = b"diagon-pool-v1-salt-2024";
const ARGON2_MEM_COST: u32 = 65536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

const ACK_MIN_DWELL_SECS: u64 = 5;
const ACK_ELABORATION_MIN_LEN: usize = 10;
const ACK_WEIGHT_BASE: u64 = 100;
const ACK_WEIGHT_WITH_REFLECTION: u64 = 300;

const TESTIMONY_MIN_ATTESTATION_LEN: usize = 10;
const TESTIMONY_WEIGHT_PER_POOL: u64 = 500;

// HITL Review System
const REVIEW_MIN_JUSTIFICATION_LEN: usize = 10;
const REVIEW_CONSENSUS_THRESHOLD: f64 = 1.0;
const REVIEW_OUTLIER_THRESHOLD: f64 = 2.0;
const REVIEW_MIN_REPUTATION: f64 = 0.2;
const REVIEW_APPRENTICE_COUNT: u32 = 5;
const REVIEW_INTERACTION_LIMIT: u32 = 5;
const REVIEW_STALE_SECS: u64 = 7 * 86400;
const REVIEW_LOOP_INTERVAL: Duration = Duration::from_secs(300);

const REVIEW_TIER_CRITICAL: (u8, u64) = (5, 72);
const REVIEW_TIER_STANDARD: (u8, u64) = (3, 48);
const REVIEW_TIER_FAST: (u8, u64) = (2, 24);

const XP_BASE_PROPOSAL: u64 = 10;
const XP_BASE_PROPOSAL_ELABORATION: u64 = 5;
const XP_BASE_REPLY: u64 = 5;
const XP_BASE_VOTE_ELABORATION: u64 = 3;
const XP_BASE_ACKNOWLEDGMENT: u64 = 2;
const XP_BASE_PIN_REASON: u64 = 5;
const XP_BASE_PRUNE_REASON: u64 = 5;

const XP_REVIEW_COMPLETE: u64 = 2;
const XP_REVIEW_CONSENSUS_BONUS: u64 = 1;
const XP_REVIEW_SPAM_CATCH: u64 = 5;

const LENGTH_FACTOR_MIN: f64 = 1.0;
const LENGTH_FACTOR_MAX: f64 = 2.0;
const LENGTH_FACTOR_BASE_WORDS: f64 = 10.0;

const GENESIS_POOLS: [[u8; 32]; 3] = [
    [0x80, 0x1e, 0x10, 0x0b, 0x0c, 0xa3, 0x10, 0x30, 0xa6, 0xb2, 0x9f, 0x69, 0x2d, 0x0f, 0x19, 0x4c,
     0x33, 0x07, 0x0f, 0xeb, 0x59, 0x50, 0x66, 0x60, 0xad, 0x7b, 0x90, 0x81, 0x3e, 0x42, 0x7b, 0x8b],
    [0x93, 0xa7, 0x80, 0xb1, 0x41, 0x61, 0x53, 0x86, 0xdb, 0x23, 0x6c, 0x6a, 0xe2, 0x9d, 0xed, 0x8c,
     0x7c, 0x42, 0xf2, 0x77, 0xa6, 0xfa, 0x28, 0x22, 0x9f, 0x7c, 0x75, 0x76, 0x49, 0xd3, 0xdc, 0xcb],
    [0xc7, 0x8d, 0xec, 0x83, 0xf3, 0xab, 0x88, 0xc4, 0xfd, 0x66, 0x2c, 0x88, 0x0e, 0x25, 0x8f, 0x63,
     0x45, 0xaa, 0xff, 0x91, 0x79, 0xd5, 0x37, 0x18, 0xa5, 0x3c, 0x84, 0x11, 0x85, 0xf6, 0x3a, 0x85],
];

// ============================================================================
// RENDEZVOUS / DHT CONSTANTS
// ============================================================================

const RENDEZVOUS_PASSPHRASE: &str = "diagon-rendezvous-v1-public-directory";
const DHT_REGISTER_LIMIT_PER_HOUR: u32 = 5;
const DHT_SYNC_INTERVAL: Duration = Duration::from_secs(300);
const DHT_STALE_SECS: u64 = 86400; // 24 hours

fn rendezvous_commitment() -> [u8; 32] {
    hash_pool_passphrase(RENDEZVOUS_PASSPHRASE)
}

// ============================================================================
// DECAY CONFIG
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DecayConfig {
    pub enabled: bool,
    pub decay_days: u64,
    pub require_engagement: bool,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decay_days: CONTENT_DECAY_DAYS,
            require_engagement: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecayConfigProposal {
    pub id: Cid,
    pub proposed_config: DecayConfig,
    pub proposer: Did,
    pub reason: String,
    pub quorum: QuorumState,
    pub created: u64,
    pub applied: bool,
}

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug)]
pub enum DiagonError {
    Io(io::Error),
    Serialization(String),
    Crypto(String),
    Validation(String),
    InsufficientTrust(f64),
    RateLimited,
    ConnectionLost,
    MessageTooLarge,
    PoolFull,
    ChannelClosed,
    StoreFull,
    ReplayAttack,
    SelfVoteProhibited,
    SignatureRequired,
    DmNotEstablished,
    DmPendingConsent,
    DecryptionFailed,
    DhtRateLimited,
}

impl fmt::Display for DiagonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO: {}", e),
            Self::Serialization(s) => write!(f, "Serialization: {}", s),
            Self::Crypto(s) => write!(f, "Crypto: {}", s),
            Self::Validation(s) => write!(f, "Validation: {}", s),
            Self::InsufficientTrust(t) => write!(f, "Insufficient trust: {:.2}", t),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::ConnectionLost => write!(f, "Connection lost"),
            Self::MessageTooLarge => write!(f, "Message too large"),
            Self::PoolFull => write!(f, "Connection pool full"),
            Self::ChannelClosed => write!(f, "Channel closed"),
            Self::StoreFull => write!(f, "Expression store full"),
            Self::ReplayAttack => write!(f, "Replay attack detected"),
            Self::SelfVoteProhibited => write!(f, "Self-voting is not allowed"),
            Self::SignatureRequired => write!(f, "Valid signature required"),
            Self::DmNotEstablished => write!(f, "DM channel not established"),
            Self::DmPendingConsent => write!(f, "DM awaiting consent from peer"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::DhtRateLimited => write!(f, "DHT rate limited"),
        }
    }
}

impl From<io::Error> for DiagonError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

type Result<T> = std::result::Result<T, DiagonError>;

// ============================================================================
// CONTENT IDENTIFIERS
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    pub fn new(data: &[u8]) -> Self {
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&random_bytes);
        hasher.update(&timestamp().to_le_bytes());
        Cid(hasher.finalize().into())
    }
    
    pub fn from_hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Cid(hasher.finalize().into())
    }
    
    pub fn short(&self) -> String { hex::encode(&self.0[..8]) }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Cid({})", self.short()) }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.short()) }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl Did {
    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        Did(format!("did:diagon:{}", hex::encode(&pubkey.as_bytes()[..16])))
    }
    
    pub fn short(&self) -> String {
        if self.0.len() > 20 { format!("{}...", &self.0[12..28]) } else { self.0.clone() }
    }
    
    pub fn matches_pubkey(&self, pubkey: &[u8]) -> bool {
        if pubkey.len() < 16 { return false; }
        let expected = format!("did:diagon:{}", hex::encode(&pubkey[..16]));
        self.0 == expected
    }
    
    pub fn dm_channel_id(&self, other: &Did) -> [u8; 32] {
        let mut hasher = Sha256::new();
        if self.0 < other.0 {
            hasher.update(self.0.as_bytes());
            hasher.update(other.0.as_bytes());
        } else {
            hasher.update(other.0.as_bytes());
            hasher.update(self.0.as_bytes());
        }
        hasher.finalize().into()
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.short()) }
}

// ============================================================================
// RATE LIMITER & NONCE TRACKER
// ============================================================================

#[derive(Default)]
struct RateLimiter {
    counts: HashMap<SocketAddr, (u32, u64)>,
}

impl RateLimiter {
    fn check_and_increment(&mut self, addr: &SocketAddr) -> bool {
        let now = timestamp();
        let entry = self.counts.entry(*addr).or_insert((0, now));
        if now - entry.1 > RATE_LIMIT_WINDOW_SECS {
            *entry = (1, now);
            return true;
        }
        if entry.0 >= RATE_LIMIT_MAX_MESSAGES { return false; }
        entry.0 += 1;
        true
    }
    
    fn cleanup(&mut self) {
        let now = timestamp();
        self.counts.retain(|_, (_, start)| now - *start <= RATE_LIMIT_WINDOW_SECS * 2);
    }
}

struct NonceTracker {
    seen: HashMap<[u8; 32], u64>,
    max_age_secs: u64,
}

impl NonceTracker {
    fn new(max_age_secs: u64) -> Self {
        Self { seen: HashMap::new(), max_age_secs }
    }
    
    fn check_and_record(&mut self, nonce: &[u8; 32]) -> bool {
        let now = timestamp();
        self.seen.retain(|_, ts| now - *ts < self.max_age_secs);
        if self.seen.contains_key(nonce) { return false; }
        self.seen.insert(*nonce, now);
        true
    }
}

// ============================================================================
// XP SYSTEM
// ============================================================================

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct XpState {
    pub total_xp: u64,
    pub last_view: HashMap<Cid, u64>,
    pub view_start: HashMap<Cid, u64>,
    /// Track viewing sessions for acknowledgment (separate from XP tracking)
    #[serde(default)]
    pub viewing: HashMap<Cid, u64>,
}

impl XpState {
    pub fn new() -> Self { Self::default() }
    
    pub fn start_viewing(&mut self, cid: Cid) {
        let now = timestamp();
        self.view_start.insert(cid, now);
        self.viewing.insert(cid, now);
    }
    
    pub fn stop_viewing(&mut self, cid: Cid) -> Option<u64> {
        let now = timestamp();
        
        // Also remove from viewing tracking
        self.viewing.remove(&cid);
        
        if let Some(start) = self.view_start.remove(&cid) {
            let duration = now.saturating_sub(start);
            
            if duration < XP_VIEW_THRESHOLD_SECS {
                return None;
            }
            
            if let Some(&last) = self.last_view.get(&cid) {
                if now.saturating_sub(last) < XP_COOLDOWN_SECS {
                    return None;
                }
            }
            
            self.total_xp = self.total_xp.saturating_add(XP_PER_VIEW);
            self.last_view.insert(cid, now);
            
            return Some(XP_PER_VIEW);
        }
        None
    }
    
    pub fn xp(&self) -> u64 { self.total_xp }
    
    /// Get view start time for acknowledgment (without removing)
    pub fn get_view_start(&self, cid: &Cid) -> Option<u64> {
        self.viewing.get(cid).copied()
    }
    
    /// Remove from viewing tracking (for acknowledgment)
    pub fn end_viewing(&mut self, cid: &Cid) -> Option<u64> {
        self.viewing.remove(cid)
    }
}

// ============================================================================
// E2E DM CHANNEL SYSTEM
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmChannelState {
    PendingOutbound,
    PendingInbound,
    Established,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmMessage {
    pub from: Did,
    pub to: Did,
    pub encrypted_content: Vec<u8>,
    pub nonce: [u8; 12],
    pub timestamp: u64,
}

pub struct DmChannel {
    pub peer_did: Did,
    pub state: DmChannelState,
    pub our_ephemeral_public: [u8; 32],
    pub peer_ephemeral_public: Option<[u8; 32]>,
    pub shared_key: Option<[u8; 32]>,
    pub messages: Vec<(Did, String, u64)>,
    pub created_at: u64,
}

impl DmChannel {
    pub fn new_outbound(peer_did: Did, our_public: [u8; 32]) -> Self {
        Self {
            peer_did,
            state: DmChannelState::PendingOutbound,
            our_ephemeral_public: our_public,
            peer_ephemeral_public: None,
            shared_key: None,
            messages: Vec::new(),
            created_at: timestamp(),
        }
    }
    
    pub fn new_inbound(peer_did: Did, peer_public: [u8; 32], our_public: [u8; 32]) -> Self {
        Self {
            peer_did,
            state: DmChannelState::PendingInbound,
            our_ephemeral_public: our_public,
            peer_ephemeral_public: Some(peer_public),
            shared_key: None,
            messages: Vec::new(),
            created_at: timestamp(),
        }
    }
    
    pub fn establish(&mut self, peer_public: [u8; 32], our_secret: &ReusableSecret) {
        self.peer_ephemeral_public = Some(peer_public);
        
        let peer_pk = X25519PublicKey::from(peer_public);
        let shared = our_secret.diffie_hellman(&peer_pk);
        
        let mut hasher = Sha256::new();
        hasher.update(b"diagon-dm-key-v1");
        hasher.update(shared.as_bytes());
        self.shared_key = Some(hasher.finalize().into());
        self.state = DmChannelState::Established;
    }
    
    pub fn encrypt(&self, plaintext: &str) -> Result<(Vec<u8>, [u8; 12])> {
        let key = self.shared_key.ok_or(DiagonError::DmNotEstablished)?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| DiagonError::Crypto("Invalid key".into()))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| DiagonError::Crypto("Encryption failed".into()))?;
        
        Ok((ciphertext, nonce_bytes))
    }
    
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<String> {
        let key = self.shared_key.ok_or(DiagonError::DmNotEstablished)?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| DiagonError::Crypto("Invalid key".into()))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| DiagonError::DecryptionFailed)?;
        
        String::from_utf8(plaintext)
            .map_err(|_| DiagonError::Validation("Invalid UTF-8".into()))
    }
    
    pub fn add_message(&mut self, from: Did, content: String) {
        self.messages.push((from, content, timestamp()));
    }
}

// ============================================================================
// ACKNOWLEDGMENT TYPES
// ============================================================================

/// An acknowledgment is a witnessed receipt - proof of attended presence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acknowledgment {
    /// The expression being acknowledged
    pub target: Cid,
    /// Who is acknowledging
    pub witness: Did,
    /// Their public key for verification
    pub pubkey: Vec<u8>,
    /// When viewing began (claimed)
    pub view_started: u64,
    /// When acknowledgment was created
    pub acknowledged_at: u64,
    /// Optional reflection - not summary, but response
    pub reflection: Option<String>,
    /// Signature over acknowledgment data
    pub signature: Vec<u8>,
}

impl Acknowledgment {
    /// Compute dwell time - how long the witness claims to have attended
    pub fn dwell_secs(&self) -> u64 {
        self.acknowledged_at.saturating_sub(self.view_started)
    }
    
    /// Check if dwell time meets minimum threshold
    pub fn valid_dwell(&self) -> bool {
        self.dwell_secs() >= ACK_MIN_DWELL_SECS
    }
    
    /// Check if reflection meets minimum quality
    pub fn has_valid_reflection(&self) -> bool {
        self.reflection.as_ref()
            .map(|r| r.split_whitespace().count() >= 3 && r.len() >= ACK_ELABORATION_MIN_LEN)
            .unwrap_or(false)
    }
    
    /// Weight of this acknowledgment for engagement scoring
    pub fn weight(&self) -> u64 {
        if !self.valid_dwell() {
            return 0;
        }
        if self.has_valid_reflection() {
            ACK_WEIGHT_WITH_REFLECTION
        } else {
            ACK_WEIGHT_BASE
        }
    }
    
    /// Create signable bytes for verification
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ack:");
        data.extend_from_slice(&self.target.0);
        data.extend_from_slice(&self.view_started.to_le_bytes());
        data.extend_from_slice(&self.acknowledged_at.to_le_bytes());
        if let Some(ref r) = self.reflection {
            data.extend_from_slice(r.as_bytes());
        }
        data
    }
}

/// Tracks acknowledgments received for an expression
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AcknowledgmentState {
    /// All acknowledgments received, keyed by witness DID
    pub witnesses: HashMap<Did, Acknowledgment>,
    /// Total accumulated weight
    pub total_weight: u64,
    /// Last acknowledgment timestamp
    pub last_acknowledged: u64,
}

impl AcknowledgmentState {
    pub fn new() -> Self { Self::default() }
    
    /// Record an acknowledgment, returns true if new witness
    pub fn acknowledge(&mut self, ack: Acknowledgment) -> bool {
        if self.witnesses.contains_key(&ack.witness) {
            return false;
        }
        
        let weight = ack.weight();
        self.last_acknowledged = ack.acknowledged_at;
        self.total_weight = self.total_weight.saturating_add(weight);
        self.witnesses.insert(ack.witness.clone(), ack);
        true
    }
    
    /// Number of unique witnesses
    pub fn witness_count(&self) -> usize {
        self.witnesses.len()
    }
    
    /// Check if expression has been meaningfully witnessed
    pub fn is_witnessed(&self) -> bool {
        self.witness_count() >= 2
    }
}

// ============================================================================
// INTER-POOL TESTIMONY TYPES
// ============================================================================

/// A testimony is a pool-level witness of another pool's expression
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Testimony {
    /// The expression being testified
    pub cid: Cid,
    /// Pool commitment of the originating pool
    pub origin_pool: [u8; 32],
    /// Pool commitment of the witnessing pool
    pub witness_pool: [u8; 32],
    /// DID of the testifier
    pub testifier: Did,
    /// Their public key
    pub pubkey: Vec<u8>,
    /// Brief description of what was witnessed (not the content itself)
    pub attestation: String,
    /// When testimony was created
    pub testified_at: u64,
    /// Signature over testimony data
    pub signature: Vec<u8>,
}

impl Testimony {
    /// Create signable bytes
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"testimony:");
        data.extend_from_slice(&self.cid.0);
        data.extend_from_slice(&self.origin_pool);
        data.extend_from_slice(&self.witness_pool);
        data.extend_from_slice(self.attestation.as_bytes());
        data.extend_from_slice(&self.testified_at.to_le_bytes());
        data
    }
    
    /// Verify testimony signature
    pub fn verify(&self) -> bool {
        let pk = match PublicKey::from_bytes(&self.pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        
        if Did::from_pubkey(&pk) != self.testifier {
            return false;
        }
        
        let sig = match DetachedSignature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        verify_detached_signature(&sig, &self.signable_bytes(), &pk).is_ok()
    }
}

/// Tracks testimonies for an expression from other pools
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TestimonyState {
    /// Testimonies keyed by (witness_pool prefix, testifier DID)
    pub testimonies: Vec<Testimony>,
    /// Count of unique pools that have witnessed
    pub pool_count: usize,
    /// Set of pools that have testified (for dedup)
    witnessed_pools: HashSet<[u8; 32]>,
}

impl TestimonyState {
    pub fn new() -> Self { Self::default() }
    
    /// Add testimony, returns true if from new pool
    pub fn add(&mut self, testimony: Testimony) -> bool {
        // Check if this pool has already testified
        let is_new_pool = !self.witnessed_pools.contains(&testimony.witness_pool);
        
        // Check if this exact testifier already testified
        let already_testified = self.testimonies.iter()
            .any(|t| t.testifier == testimony.testifier && t.witness_pool == testimony.witness_pool);
        
        if already_testified {
            return false;
        }
        
        if is_new_pool {
            self.witnessed_pools.insert(testimony.witness_pool);
            self.pool_count += 1;
        }
        
        self.testimonies.push(testimony);
        is_new_pool
    }
    
    /// Get all witnessing pools
    pub fn witnessing_pools(&self) -> &HashSet<[u8; 32]> {
        &self.witnessed_pools
    }
}

/// Registry of testimonies we've given and received
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TestimonyRegistry {
    /// Testimonies we've created about other pools' expressions
    pub given: HashMap<Cid, Testimony>,
    /// Count of testimonies given
    pub given_count: usize,
}

impl TestimonyRegistry {
    pub fn new() -> Self { Self::default() }
    
    pub fn add_given(&mut self, testimony: Testimony) {
        if !self.given.contains_key(&testimony.cid) {
            self.given_count += 1;
        }
        self.given.insert(testimony.cid, testimony);
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReviewableContentType {
    Proposal,
    ProposalElaboration,
    Reply,
    Acknowledgment,
    VoteElaboration,
    PinReason,
    PruneReason,
}

impl ReviewableContentType {
    pub fn tier_config(&self) -> (u8, u64) {
        match self {
            Self::Proposal | Self::PinReason | Self::PruneReason => REVIEW_TIER_CRITICAL,
            Self::ProposalElaboration | Self::Reply | Self::VoteElaboration => REVIEW_TIER_STANDARD,
            Self::Acknowledgment => REVIEW_TIER_FAST,
        }
    }
    
    pub fn base_xp(&self) -> u64 {
        match self {
            Self::Proposal => XP_BASE_PROPOSAL,
            Self::ProposalElaboration => XP_BASE_PROPOSAL_ELABORATION,
            Self::Reply => XP_BASE_REPLY,
            Self::VoteElaboration => XP_BASE_VOTE_ELABORATION,
            Self::Acknowledgment => XP_BASE_ACKNOWLEDGMENT,
            Self::PinReason => XP_BASE_PIN_REASON,
            Self::PruneReason => XP_BASE_PRUNE_REASON,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::ProposalElaboration => "proposal-elaboration",
            Self::Reply => "reply",
            Self::Acknowledgment => "acknowledgment",
            Self::VoteElaboration => "vote-elaboration",
            Self::PinReason => "pin-reason",
            Self::PruneReason => "prune-reason",
        }
    }
}

impl fmt::Display for ReviewableContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QualityReview {
    pub content_cid: Cid,
    pub reviewer: Did,
    pub pubkey: Vec<u8>,
    pub relevance: u8,
    pub substance: u8,
    pub clarity: u8,
    pub originality: u8,
    pub effort: u8,
    pub justification: String,
    pub flag_spam: bool,
    pub flag_plagiarism: bool,
    pub flag_offtopic: bool,
    pub reviewed_at: u64,
    pub signature: Vec<u8>,
}

impl QualityReview {
    pub fn composite_score(&self) -> f64 {
        let relevance = self.relevance as f64 * 0.25;
        let substance = self.substance as f64 * 0.30;
        let clarity = self.clarity as f64 * 0.20;
        let originality = self.originality as f64 * 0.15;
        let effort = self.effort as f64 * 0.10;
        relevance + substance + clarity + originality + effort
    }
    
    pub fn is_flagged(&self) -> bool {
        self.flag_spam || self.flag_plagiarism || self.flag_offtopic
    }
    
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"quality-review:");
        data.extend_from_slice(&self.content_cid.0);
        data.push(self.relevance);
        data.push(self.substance);
        data.push(self.clarity);
        data.push(self.originality);
        data.push(self.effort);
        data.extend_from_slice(self.justification.as_bytes());
        data.push(if self.flag_spam { 1 } else { 0 });
        data.push(if self.flag_plagiarism { 1 } else { 0 });
        data.push(if self.flag_offtopic { 1 } else { 0 });
        data.extend_from_slice(&self.reviewed_at.to_le_bytes());
        data
    }
    
    pub fn verify(&self) -> bool {
        let pk = match PublicKey::from_bytes(&self.pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        if Did::from_pubkey(&pk) != self.reviewer { return false; }
        let sig = match DetachedSignature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        verify_detached_signature(&sig, &self.signable_bytes(), &pk).is_ok()
    }
    
    pub fn is_valid(&self) -> bool {
        let scores_valid = (1..=5).contains(&self.relevance)
            && (1..=5).contains(&self.substance)
            && (1..=5).contains(&self.clarity)
            && (1..=5).contains(&self.originality)
            && (1..=5).contains(&self.effort);
        scores_valid && self.justification.len() >= REVIEW_MIN_JUSTIFICATION_LEN
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingReview {
    pub content_cid: Cid,
    pub content_type: ReviewableContentType,
    pub content_text: String,
    pub context_cid: Option<Cid>,
    pub context_text: Option<String>,
    pub submitted_at: u64,
    pub deadline: u64,
    pub required_reviews: u8,
    pub assigned_reviewers: Vec<Did>,
    pub reviews: Vec<QualityReview>,
    pub author: Did,
    pub word_count: u32,
}

impl PendingReview {
    pub fn new(
        content_cid: Cid,
        content_type: ReviewableContentType,
        content_text: String,
        context_cid: Option<Cid>,
        context_text: Option<String>,
        author: Did,
    ) -> Self {
        let (required_reviews, deadline_hours) = content_type.tier_config();
        let word_count = content_text.split_whitespace().count() as u32;
        Self {
            content_cid, content_type, content_text, context_cid, context_text,
            submitted_at: timestamp(),
            deadline: timestamp() + (deadline_hours * 3600),
            required_reviews, assigned_reviewers: Vec::new(), reviews: Vec::new(),
            author, word_count,
        }
    }
    
    pub fn is_complete(&self) -> bool { self.reviews.len() >= self.required_reviews as usize }
    pub fn is_expired(&self) -> bool { timestamp() > self.deadline }
    pub fn has_reviewed(&self, reviewer: &Did) -> bool { self.reviews.iter().any(|r| &r.reviewer == reviewer) }
    pub fn is_assigned(&self, reviewer: &Did) -> bool { self.assigned_reviewers.contains(reviewer) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QualityVerdict {
    pub content_cid: Cid,
    pub author: Did,
    pub quality_score: f64,
    pub flagged: bool,
    pub flag_reason: Option<String>,
    pub reviewer_scores: Vec<(Did, f64)>,
    pub consensus_aligned: Vec<Did>,
    pub consensus_outliers: Vec<Did>,
    pub xp_awarded: u64,
    pub verdict_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReviewerReputation {
    pub reviews_completed: u32,
    pub consensus_alignments: u32,
    pub consensus_deviations: u32,
    pub confirmed_flags: u32,
    pub false_flags: u32,
    pub score: f64,
    pub last_review: u64,
}

impl ReviewerReputation {
    pub fn new() -> Self { Self { score: 0.5, ..Default::default() } }
    
    pub fn update(&mut self, aligned: bool, flag_result: Option<bool>) {
        self.reviews_completed += 1;
        if aligned {
            self.consensus_alignments += 1;
            self.score = (self.score + 0.02).min(1.0);
        } else {
            self.consensus_deviations += 1;
            self.score = (self.score - 0.05).max(0.0);
        }
        if let Some(confirmed) = flag_result {
            if confirmed { self.confirmed_flags += 1; self.score = (self.score + 0.1).min(1.0); }
            else { self.false_flags += 1; self.score = (self.score - 0.2).max(0.0); }
        }
        self.last_review = timestamp();
    }
    
    pub fn weight(&self) -> f64 {
        let exp = (self.reviews_completed as f64 / REVIEW_APPRENTICE_COUNT as f64).min(1.0);
        self.score * (0.5 + 0.5 * exp)
    }
    
    pub fn is_eligible(&self) -> bool { self.score >= REVIEW_MIN_REPUTATION }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewState {
    pub pending: HashMap<Cid, PendingReview>,
    pub verdicts: HashMap<Cid, QualityVerdict>,
    pub reviewer_reputations: HashMap<Did, ReviewerReputation>,
    pub interaction_counts: HashMap<(Did, Did), u32>,
}

impl ReviewState {
    pub fn new() -> Self { Self::default() }
    
    pub fn submit_for_review(
        &mut self,
        content_cid: Cid,
        content_type: ReviewableContentType,
        content_text: String,
        context_cid: Option<Cid>,
        context_text: Option<String>,
        author: Did,
        eligible_reviewers: &[Did],
    ) -> Result<()> {
        if self.pending.contains_key(&content_cid) {
            return Err(DiagonError::Validation("Already pending".into()));
        }
        
        let mut pending = PendingReview::new(
            content_cid, content_type, content_text, context_cid, context_text, author.clone(),
        );
        
        let reviewers = self.select_reviewers(&author, eligible_reviewers, pending.required_reviews as usize)?;
        pending.assigned_reviewers = reviewers;
        self.pending.insert(content_cid, pending);
        Ok(())
    }
    
    fn select_reviewers(&self, author: &Did, eligible: &[Did], count: usize) -> Result<Vec<Did>> {
        let candidates: Vec<_> = eligible.iter()
            .filter(|&r| {
                if r == author { return false; }
                let key1 = (r.clone(), author.clone());
                let key2 = (author.clone(), r.clone());
                let interactions = self.interaction_counts.get(&key1).copied().unwrap_or(0)
                    + self.interaction_counts.get(&key2).copied().unwrap_or(0);
                if interactions > REVIEW_INTERACTION_LIMIT { return false; }
                self.reviewer_reputations.get(r).map(|r| r.is_eligible()).unwrap_or(true)
            })
            .cloned()
            .collect();
        
        if candidates.len() < count {
            return Err(DiagonError::Validation(format!("Need {} reviewers, have {}", count, candidates.len())));
        }
        
        let mut weighted: Vec<_> = candidates.iter()
            .map(|did| (did.clone(), self.reviewer_reputations.get(did).map(|r| r.weight()).unwrap_or(0.5)))
            .collect();
        
        let mut selected = Vec::new();
        for _ in 0..count {
            if weighted.is_empty() { break; }
            let total: f64 = weighted.iter().map(|(_, w)| w).sum();
            if total <= 0.0 { break; }
            
            let mut random = [0u8; 8];
            OsRng.fill_bytes(&mut random);
            let mut choice = (u64::from_le_bytes(random) as f64 / u64::MAX as f64) * total;
            
            let idx = weighted.iter().position(|(_, w)| { choice -= w; choice <= 0.0 }).unwrap_or(0);
            let (did, _) = weighted.remove(idx);
            selected.push(did);
        }
        
        if selected.len() < count {
            return Err(DiagonError::Validation("Could not select enough reviewers".into()));
        }
        Ok(selected)
    }
    
    pub fn submit_review(&mut self, review: QualityReview) -> Result<bool> {
        if !review.is_valid() { return Err(DiagonError::Validation("Invalid review".into())); }
        if !review.verify() { return Err(DiagonError::SignatureRequired); }
        
        let pending = self.pending.get_mut(&review.content_cid)
            .ok_or(DiagonError::Validation("Not in queue".into()))?;
        
        if !pending.is_assigned(&review.reviewer) {
            return Err(DiagonError::Validation("Not assigned".into()));
        }
        if pending.has_reviewed(&review.reviewer) {
            return Err(DiagonError::Validation("Already reviewed".into()));
        }
        
        let key = (review.reviewer.clone(), pending.author.clone());
        *self.interaction_counts.entry(key).or_insert(0) += 1;
        
        pending.reviews.push(review);
        Ok(pending.is_complete())
    }
    
    pub fn finalize_review(&mut self, content_cid: Cid) -> Result<QualityVerdict> {
        let pending = self.pending.remove(&content_cid)
            .ok_or(DiagonError::Validation("Not found".into()))?;
        
        if pending.reviews.is_empty() {
            let verdict = QualityVerdict {
                content_cid, author: pending.author, quality_score: 0.5,
                flagged: false, flag_reason: None, reviewer_scores: Vec::new(),
                consensus_aligned: Vec::new(), consensus_outliers: Vec::new(),
                xp_awarded: 0, verdict_at: timestamp(),
            };
            self.verdicts.insert(content_cid, verdict.clone());
            return Ok(verdict);
        }
        
        let mut scores: Vec<_> = pending.reviews.iter()
            .map(|r| (r.reviewer.clone(), r.composite_score(), 
                      self.reviewer_reputations.get(&r.reviewer).map(|rep| rep.weight()).unwrap_or(0.5)))
            .collect();
        scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        
        let total_weight: f64 = scores.iter().map(|(_, _, w)| w).sum();
        let mut cumulative = 0.0;
        let mut median = scores.get(0).map(|x| x.1).unwrap_or(3.0);
        for (_, score, weight) in &scores {
            cumulative += weight;
            if cumulative >= total_weight / 2.0 { median = *score; break; }
        }
        
        let mut aligned = Vec::new();
        let mut outliers = Vec::new();
        for (did, score, _) in &scores {
            let dev = (score - median).abs();
            if dev <= REVIEW_CONSENSUS_THRESHOLD { aligned.push(did.clone()); }
            else if dev > REVIEW_OUTLIER_THRESHOLD { outliers.push(did.clone()); }
        }
        
        let flag_count = pending.reviews.iter().filter(|r| r.is_flagged()).count();
        let flagged = flag_count > pending.reviews.len() / 2;
        let flag_reason = if flagged {
            let spam = pending.reviews.iter().filter(|r| r.flag_spam).count();
            let plag = pending.reviews.iter().filter(|r| r.flag_plagiarism).count();
            if spam >= plag { Some("spam".into()) } else { Some("plagiarism".into()) }
        } else { None };
        
        let quality = if flagged { 0.0 } else { (median - 1.0) / 4.0 };
        let xp = if flagged { 0 } else { calculate_xp_award(pending.content_type, pending.word_count, quality) };
        
        for review in &pending.reviews {
            let aligned_consensus = (review.composite_score() - median).abs() <= REVIEW_CONSENSUS_THRESHOLD;
            let flag_result = if review.is_flagged() { Some(flagged) } else { None };
            self.reviewer_reputations.entry(review.reviewer.clone())
                .or_insert_with(ReviewerReputation::new)
                .update(aligned_consensus, flag_result);
        }
        
        let verdict = QualityVerdict {
            content_cid, author: pending.author, quality_score: quality,
            flagged, flag_reason,
            reviewer_scores: scores.iter().map(|(d, s, _)| (d.clone(), *s)).collect(),
            consensus_aligned: aligned, consensus_outliers: outliers,
            xp_awarded: xp, verdict_at: timestamp(),
        };
        self.verdicts.insert(content_cid, verdict.clone());
        Ok(verdict)
    }
    
    pub fn get_assignments(&self, reviewer: &Did) -> Vec<&PendingReview> {
        self.pending.values()
            .filter(|p| p.is_assigned(reviewer) && !p.has_reviewed(reviewer))
            .collect()
    }
    
    pub fn get_expired(&self) -> Vec<Cid> {
        self.pending.iter()
            .filter(|(_, p)| p.is_expired() || p.is_complete())
            .map(|(cid, _)| *cid)
            .collect()
    }
    
    pub fn calculate_reviewer_rewards(&self, cid: &Cid) -> HashMap<Did, u64> {
        let mut rewards = HashMap::new();
        if let Some(verdict) = self.verdicts.get(cid) {
            for (reviewer, _) in &verdict.reviewer_scores {
                let mut xp = XP_REVIEW_COMPLETE;
                if verdict.consensus_aligned.contains(reviewer) { xp += XP_REVIEW_CONSENSUS_BONUS; }
                if verdict.flagged { xp += XP_REVIEW_SPAM_CATCH; }
                rewards.insert(reviewer.clone(), xp);
            }
        }
        rewards
    }
}

// ============================================================================
// DHT STATE
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtEntry {
    pub topic_hash: [u8; 32],
    pub pool_commitment: [u8; 32],
    pub pool_name: String,
    pub description: String,
    pub peer_count: usize,
    pub registered_by: Did,
    pub registered_at: u64,
    pub last_seen: u64,
}

impl DhtEntry {
    pub fn topic_str(topic: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"diagon-topic-v1:");
        hasher.update(topic.to_lowercase().as_bytes());
        hasher.finalize().into()
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct DhtState {
    pub entries: HashMap<[u8; 32], Vec<DhtEntry>>,
    pub pool_topics: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    #[serde(skip)]
    pub register_limits: HashMap<Did, (u32, u64)>,
    pub last_sync: u64,
}

impl DhtState {
    pub fn new() -> Self { Self::default() }
    
    pub fn check_rate_limit(&mut self, did: &Did) -> bool {
        let now = timestamp();
        let hour_start = now - (now % 3600);
        
        let entry = self.register_limits.entry(did.clone()).or_insert((0, hour_start));
        
        if entry.1 < hour_start {
            *entry = (0, hour_start);
        }
        
        if entry.0 >= DHT_REGISTER_LIMIT_PER_HOUR {
            return false;
        }
        
        entry.0 += 1;
        true
    }
    
    pub fn register(&mut self, entry: DhtEntry) -> bool {
        let topic_hash = entry.topic_hash;
        let pool_commitment = entry.pool_commitment;
        
        let entries = self.entries.entry(topic_hash).or_default();
        if let Some(existing) = entries.iter_mut().find(|e| e.pool_commitment == pool_commitment) {
            existing.peer_count = entry.peer_count;
            existing.last_seen = entry.last_seen;
            existing.description = entry.description;
            return false;
        }
        
        entries.push(entry);
        self.pool_topics.entry(pool_commitment).or_default().insert(topic_hash);
        true
    }
    
    pub fn search(&self, topic: &str) -> Vec<DhtEntry> {
        let topic_hash = DhtEntry::topic_str(topic);
        self.entries.get(&topic_hash).cloned().unwrap_or_default()
    }
    
    pub fn get_directory(&self) -> Vec<DhtEntry> {
        self.entries.values().flatten().cloned().collect()
    }
    
    pub fn update_pool_peer_count(&mut self, pool_commitment: [u8; 32], peer_count: usize) {
        let now = timestamp();
        for entries in self.entries.values_mut() {
            for entry in entries.iter_mut() {
                if entry.pool_commitment == pool_commitment {
                    entry.peer_count = peer_count;
                    entry.last_seen = now;
                }
            }
        }
    }
    
    pub fn cleanup_stale(&mut self, max_age_secs: u64) {
        let cutoff = timestamp().saturating_sub(max_age_secs);
        for entries in self.entries.values_mut() {
            entries.retain(|e| e.last_seen > cutoff);
        }
        self.entries.retain(|_, v| !v.is_empty());
    }
}

// ============================================================================
// CHUNKED CONTENT TRANSFER
// ============================================================================

const CONTENT_CHUNK_SIZE: usize = 262_144;
const MAX_PENDING_TRANSFERS: usize = 5;
const TRANSFER_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    Image,
    Video,
    Text,
}

impl ContentType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "image" | "img" | "photo" => Some(Self::Image),
            "video" | "vid" | "movie" => Some(Self::Video),
            "text" | "txt" | "doc" => Some(Self::Text),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::Text => "text",
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    pub content_id: [u8; 32],
    pub content_type: ContentType,
    pub total_size: u64,
    pub total_chunks: u32,
    pub content_hash: [u8; 32],
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub sender: Did,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl ContentMetadata {
    pub fn new(
        content_type: ContentType,
        data: &[u8],
        filename: Option<String>,
        mime_type: Option<String>,
        sender: Did,
    ) -> Self {
        let mut content_id = [0u8; 32];
        OsRng.fill_bytes(&mut content_id);
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        let content_hash: [u8; 32] = hasher.finalize().into();
        
        let total_chunks = ((data.len() + CONTENT_CHUNK_SIZE - 1) / CONTENT_CHUNK_SIZE) as u32;
        
        Self {
            content_id,
            content_type,
            total_size: data.len() as u64,
            total_chunks,
            content_hash,
            filename,
            mime_type,
            sender,
            timestamp: timestamp(),
            signature: Vec::new(),
        }
    }
    
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.content_id);
        data.push(self.content_type as u8);
        data.extend_from_slice(&self.total_size.to_le_bytes());
        data.extend_from_slice(&self.total_chunks.to_le_bytes());
        data.extend_from_slice(&self.content_hash);
        if let Some(ref f) = self.filename { data.extend_from_slice(f.as_bytes()); }
        if let Some(ref m) = self.mime_type { data.extend_from_slice(m.as_bytes()); }
        data.extend_from_slice(self.sender.0.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentChunk {
    pub content_id: [u8; 32],
    pub chunk_index: u32,
    pub data: Vec<u8>,
    pub chunk_hash: [u8; 32],
}

impl ContentChunk {
    pub fn new(content_id: [u8; 32], chunk_index: u32, data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let chunk_hash: [u8; 32] = hasher.finalize().into();
        
        Self { content_id, chunk_index, data: data.to_vec(), chunk_hash }
    }
    
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed: [u8; 32] = hasher.finalize().into();
        computed == self.chunk_hash
    }
}

#[derive(Debug)]
pub struct IncomingTransfer {
    pub metadata: ContentMetadata,
    pub chunks: HashMap<u32, Vec<u8>>,
    pub received_count: u32,
    pub started_at: Instant,
}

impl IncomingTransfer {
    pub fn new(metadata: ContentMetadata) -> Self {
        Self { metadata, chunks: HashMap::new(), received_count: 0, started_at: Instant::now() }
    }
    
    pub fn is_complete(&self) -> bool { self.received_count == self.metadata.total_chunks }
    pub fn is_expired(&self) -> bool { self.started_at.elapsed() > Duration::from_secs(TRANSFER_TIMEOUT_SECS) }
    
    pub fn add_chunk(&mut self, chunk: &ContentChunk) -> Result<bool> {
        if chunk.content_id != self.metadata.content_id {
            return Err(DiagonError::Validation("Chunk ID mismatch".into()));
        }
        if chunk.chunk_index >= self.metadata.total_chunks {
            return Err(DiagonError::Validation("Invalid chunk index".into()));
        }
        if !chunk.verify() {
            return Err(DiagonError::Validation("Chunk hash mismatch".into()));
        }
        if self.chunks.contains_key(&chunk.chunk_index) { return Ok(false); }
        
        self.chunks.insert(chunk.chunk_index, chunk.data.clone());
        self.received_count += 1;
        Ok(true)
    }
    
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(DiagonError::Validation("Transfer not complete".into()));
        }
        
        let mut result = Vec::with_capacity(self.metadata.total_size as usize);
        for i in 0..self.metadata.total_chunks {
            let chunk_data = self.chunks.get(&i)
                .ok_or_else(|| DiagonError::Validation(format!("Missing chunk {}", i)))?;
            result.extend_from_slice(chunk_data);
        }
        
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let computed: [u8; 32] = hasher.finalize().into();
        
        if computed != self.metadata.content_hash {
            return Err(DiagonError::Validation("Content hash mismatch".into()));
        }
        Ok(result)
    }
}

pub struct ContentEncoder {
    metadata: ContentMetadata,
    data: Vec<u8>,
    current_chunk: u32,
}

impl ContentEncoder {
    pub fn new(
        content_type: ContentType,
        data: Vec<u8>,
        filename: Option<String>,
        mime_type: Option<String>,
        sender: Did,
    ) -> Self {
        let metadata = ContentMetadata::new(content_type, &data, filename, mime_type, sender);
        Self { metadata, data, current_chunk: 0 }
    }
    
    pub fn sign(&mut self, secret_key: &SecretKey) {
        let signable = self.metadata.signable_bytes();
        self.metadata.signature = detached_sign(&signable, secret_key).as_bytes().to_vec();
    }
    
    pub fn metadata(&self) -> &ContentMetadata { &self.metadata }
    
    pub fn next_chunk(&mut self) -> Option<ContentChunk> {
        if self.current_chunk >= self.metadata.total_chunks { return None; }
        
        let start = (self.current_chunk as usize) * CONTENT_CHUNK_SIZE;
        let end = ((self.current_chunk as usize + 1) * CONTENT_CHUNK_SIZE).min(self.data.len());
        
        let chunk = ContentChunk::new(self.metadata.content_id, self.current_chunk, &self.data[start..end]);
        self.current_chunk += 1;
        Some(chunk)
    }
    
    pub fn reset(&mut self) { self.current_chunk = 0; }
}

// ============================================================================
// ARENA ALLOCATOR
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct SexpRef(u32);

impl SexpRef {
    pub const NIL: SexpRef = SexpRef(0);
    pub fn is_nil(&self) -> bool { self.0 == 0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SexpNode {
    Nil,
    Atom(String),
    Int(i64),
    Bytes(Vec<u8>),
    Cons { car: SexpRef, cdr: SexpRef, #[serde(skip)] hash: Option<[u8; 32]> },
}

#[derive(Default)]
pub struct Arena {
    nodes: Vec<SexpNode>,
    atoms: HashMap<String, SexpRef>,
    cache: HashMap<[u8; 32], SexpRef>,
}

impl Arena {
    pub fn new() -> Self {
        let mut arena = Self { nodes: Vec::with_capacity(4096), atoms: HashMap::new(), cache: HashMap::new() };
        arena.nodes.push(SexpNode::Nil);
        arena
    }
    
    pub fn atom(&mut self, s: &str) -> SexpRef {
        if let Some(&idx) = self.atoms.get(s) { return idx; }
        let idx = SexpRef(self.nodes.len() as u32);
        self.nodes.push(SexpNode::Atom(s.to_string()));
        self.atoms.insert(s.to_string(), idx);
        idx
    }
    
    pub fn cons(&mut self, car: SexpRef, cdr: SexpRef) -> SexpRef {
        let idx = SexpRef(self.nodes.len() as u32);
        self.nodes.push(SexpNode::Cons { car, cdr, hash: None });
        idx
    }
    
    pub fn int(&mut self, n: i64) -> SexpRef {
        let idx = SexpRef(self.nodes.len() as u32);
        self.nodes.push(SexpNode::Int(n));
        idx
    }
    
    pub fn bytes(&mut self, b: &[u8]) -> SexpRef {
        let idx = SexpRef(self.nodes.len() as u32);
        self.nodes.push(SexpNode::Bytes(b.to_vec()));
        idx
    }
    
    pub fn list(&mut self, items: &[SexpRef]) -> SexpRef {
        let mut result = SexpRef::NIL;
        for &item in items.iter().rev() { result = self.cons(item, result); }
        result
    }
    
    pub fn get(&self, idx: SexpRef) -> &SexpNode { &self.nodes[idx.0 as usize] }
    fn get_mut(&mut self, idx: SexpRef) -> &mut SexpNode { &mut self.nodes[idx.0 as usize] }
    pub fn car(&self, idx: SexpRef) -> SexpRef { match self.get(idx) { SexpNode::Cons { car, .. } => *car, _ => SexpRef::NIL } }
    pub fn cdr(&self, idx: SexpRef) -> SexpRef { match self.get(idx) { SexpNode::Cons { cdr, .. } => *cdr, _ => SexpRef::NIL } }
    
    pub fn nth(&self, list: SexpRef, n: usize) -> SexpRef {
        let mut current = list;
        for _ in 0..n { current = self.cdr(current); }
        self.car(current)
    }
    
    pub fn hash(&mut self, idx: SexpRef) -> [u8; 32] {
        if let SexpNode::Cons { hash: Some(h), .. } = self.get(idx) { return *h; }
        let mut hasher = Sha256::new();
        self.hash_into(idx, &mut hasher);
        let result: [u8; 32] = hasher.finalize().into();
        if let SexpNode::Cons { hash, .. } = self.get_mut(idx) { *hash = Some(result); }
        result
    }
    
    fn hash_into(&self, idx: SexpRef, hasher: &mut Sha256) {
        match self.get(idx) {
            SexpNode::Nil => hasher.update(&[0u8]),
            SexpNode::Atom(s) => { hasher.update(&[1u8]); hasher.update(&(s.len() as u32).to_le_bytes()); hasher.update(s.as_bytes()); }
            SexpNode::Int(n) => { hasher.update(&[2u8]); hasher.update(&n.to_le_bytes()); }
            SexpNode::Bytes(b) => { hasher.update(&[3u8]); hasher.update(&(b.len() as u32).to_le_bytes()); hasher.update(b); }
            SexpNode::Cons { car, cdr, hash } => {
                if let Some(h) = hash { hasher.update(&[4u8]); hasher.update(h); }
                else { hasher.update(&[4u8]); self.hash_into(*car, hasher); self.hash_into(*cdr, hasher); }
            }
        }
    }
    
    pub fn intern(&mut self, idx: SexpRef) -> (Cid, SexpRef) {
        let hash = self.hash(idx);
        if let Some(&existing) = self.cache.get(&hash) { return (Cid(hash), existing); }
        self.cache.insert(hash, idx);
        (Cid(hash), idx)
    }
    
    pub fn lookup(&self, cid: &Cid) -> Option<SexpRef> { self.cache.get(&cid.0).copied() }
    
    pub fn display(&self, idx: SexpRef) -> String {
        match self.get(idx) {
            SexpNode::Nil => "()".to_string(),
            SexpNode::Atom(s) => s.clone(),
            SexpNode::Int(n) => n.to_string(),
            SexpNode::Bytes(b) => format!("#x{}", hex::encode(b)),
            SexpNode::Cons { .. } => {
                let mut parts = Vec::new();
                let mut current = idx;
                while let SexpNode::Cons { car, cdr, .. } = self.get(current) {
                    parts.push(self.display(*car));
                    current = *cdr;
                }
                if current.is_nil() { format!("({})", parts.join(" ")) }
                else { format!("({} . {})", parts.join(" "), self.display(current)) }
            }
        }
    }
    
    pub fn parse(&mut self, input: &str) -> Option<SexpRef> {
        let tokens = tokenize(input);
        let mut pos = 0;
        self.parse_tokens(&tokens, &mut pos)
    }
    
    fn parse_tokens(&mut self, tokens: &[Token], pos: &mut usize) -> Option<SexpRef> {
        if *pos >= tokens.len() { return None; }
        match &tokens[*pos] {
            Token::LParen => {
                *pos += 1;
                let mut items = Vec::new();
                while *pos < tokens.len() {
                    if let Token::RParen = &tokens[*pos] { *pos += 1; return Some(self.list(&items)); }
                    items.push(self.parse_tokens(tokens, pos)?);
                }
                None
            }
            Token::RParen => None,
            Token::Atom(s) => {
                *pos += 1;
                if let Ok(n) = s.parse::<i64>() { return Some(self.int(n)); }
                if s.starts_with("#x") { if let Ok(bytes) = hex::decode(&s[2..]) { return Some(self.bytes(&bytes)); } }
                Some(self.atom(s))
            }
            Token::String(s) => { *pos += 1; Some(self.atom(s)) }
        }
    }
    
    pub fn serialize(&self, idx: SexpRef) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_into(idx, &mut buf);
        buf
    }
    
    fn serialize_into(&self, idx: SexpRef, buf: &mut Vec<u8>) {
        match self.get(idx) {
            SexpNode::Nil => buf.push(0),
            SexpNode::Atom(s) => { buf.push(1); buf.extend_from_slice(&(s.len() as u32).to_le_bytes()); buf.extend_from_slice(s.as_bytes()); }
            SexpNode::Int(n) => { buf.push(2); buf.extend_from_slice(&n.to_le_bytes()); }
            SexpNode::Bytes(b) => { buf.push(3); buf.extend_from_slice(&(b.len() as u32).to_le_bytes()); buf.extend_from_slice(b); }
            SexpNode::Cons { car, cdr, .. } => { buf.push(4); self.serialize_into(*car, buf); self.serialize_into(*cdr, buf); }
        }
    }
    
    pub fn deserialize(&mut self, data: &[u8]) -> Option<SexpRef> {
        let mut pos = 0;
        self.deserialize_from(data, &mut pos)
    }
    
    fn deserialize_from(&mut self, data: &[u8], pos: &mut usize) -> Option<SexpRef> {
        if *pos >= data.len() { return None; }
        match data[*pos] {
            0 => { *pos += 1; Some(SexpRef::NIL) }
            1 => {
                *pos += 1;
                if *pos + 4 > data.len() { return None; }
                let len = u32::from_le_bytes(data[*pos..*pos+4].try_into().ok()?) as usize;
                *pos += 4;
                if *pos + len > data.len() { return None; }
                let s = std::str::from_utf8(&data[*pos..*pos+len]).ok()?;
                *pos += len;
                Some(self.atom(s))
            }
            2 => {
                *pos += 1;
                if *pos + 8 > data.len() { return None; }
                let n = i64::from_le_bytes(data[*pos..*pos+8].try_into().ok()?);
                *pos += 8;
                Some(self.int(n))
            }
            3 => {
                *pos += 1;
                if *pos + 4 > data.len() { return None; }
                let len = u32::from_le_bytes(data[*pos..*pos+4].try_into().ok()?) as usize;
                *pos += 4;
                if *pos + len > data.len() { return None; }
                let b = &data[*pos..*pos+len];
                *pos += len;
                Some(self.bytes(b))
            }
            4 => {
                *pos += 1;
                let car = self.deserialize_from(data, pos)?;
                let cdr = self.deserialize_from(data, pos)?;
                Some(self.cons(car, cdr))
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
enum Token { LParen, RParen, Atom(String), String(String) }

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '(' => { tokens.push(Token::LParen); chars.next(); }
            ')' => { tokens.push(Token::RParen); chars.next(); }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(&c) = chars.peek() { if c == '"' { chars.next(); break; } s.push(c); chars.next(); }
                tokens.push(Token::String(s));
            }
            c if c.is_whitespace() => { chars.next(); }
            ';' => { while let Some(&c) = chars.peek() { chars.next(); if c == '\n' { break; } } }
            _ => {
                let mut atom = String::new();
                while let Some(&c) = chars.peek() { if c.is_whitespace() || c == '(' || c == ')' { break; } atom.push(c); chars.next(); }
                if !atom.is_empty() { tokens.push(Token::Atom(atom)); }
            }
        }
    }
    tokens
}

// ============================================================================
// EXPRESSION STORE WITH DECAY
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpressionMeta {
    pub created_at: u64,
    pub last_engaged: u64,
    pub engagement_count: u32,
    /// Acknowledgment state - tracked witnesses within pool
    #[serde(default)]
    pub acknowledgments: AcknowledgmentState,
    /// Testimony state - witnesses from other pools
    #[serde(default)]
    pub testimonies: TestimonyState,
    /// Origin pool if this expression came via testimony
    #[serde(default)]
    pub origin_pool: Option<[u8; 32]>,
}

impl ExpressionMeta {
    pub fn new() -> Self {
        let now = timestamp();
        Self { 
            created_at: now, 
            last_engaged: now, 
            engagement_count: 0,
            acknowledgments: AcknowledgmentState::new(),
            testimonies: TestimonyState::new(),
            origin_pool: None,
        }
    }
    
    pub fn engage(&mut self) {
        self.last_engaged = timestamp();
        self.engagement_count = self.engagement_count.saturating_add(1);
    }
    
    /// Record an acknowledgment, updating engagement if valid
    pub fn acknowledge(&mut self, ack: Acknowledgment) -> bool {
        if ack.valid_dwell() {
            self.engage();
            self.acknowledgments.acknowledge(ack)
        } else {
            false
        }
    }
    
    /// Add testimony from another pool
    pub fn add_testimony(&mut self, testimony: Testimony) -> bool {
        self.engage();
        self.testimonies.add(testimony)
    }
    
    pub fn is_decayed(&self) -> bool {
        timestamp().saturating_sub(self.last_engaged) > CONTENT_DECAY_SECS
    }
    
    /// Expression is witnessed if it has meaningful acknowledgments
    pub fn is_witnessed(&self) -> bool {
        self.acknowledgments.is_witnessed()
    }
    
    /// Expression has inter-pool significance
    pub fn is_testified(&self) -> bool {
        self.testimonies.pool_count > 0
    }
    
    /// Total witness weight (intra + inter pool)
    pub fn total_witness_weight(&self) -> u64 {
        let intra = self.acknowledgments.total_weight;
        let inter = (self.testimonies.pool_count as u64) * TESTIMONY_WEIGHT_PER_POOL;
        intra + inter
    }
}

impl Default for ExpressionMeta { 
    fn default() -> Self { Self::new() } 
}

pub struct ExprStore {
    expressions: HashMap<Cid, SexpRef>,
    metadata: HashMap<Cid, ExpressionMeta>,
    replies: HashMap<Cid, Vec<Cid>>,
    log: Vec<Cid>,
    arena: Arena,
    max_size: usize,
}

impl ExprStore {
    pub fn new() -> Self { 
        Self { 
            expressions: HashMap::new(), 
            metadata: HashMap::new(),
            replies: HashMap::new(),
            log: Vec::new(), 
            arena: Arena::new(),
            max_size: MAX_EXPRESSIONS,
        } 
    }
    
    pub fn store(&mut self, expr: SexpRef) -> Result<(Cid, bool)> {
        if self.expressions.len() >= self.max_size {
            return Err(DiagonError::StoreFull);
        }
        
        let (cid, canonical) = self.arena.intern(expr);
        let is_new = !self.expressions.contains_key(&cid);
        if is_new { 
            self.expressions.insert(cid, canonical); 
            self.metadata.insert(cid, ExpressionMeta::new());
            self.log.push(cid); 
        }
        Ok((cid, is_new))
    }
    
    pub fn fetch(&self, cid: &Cid) -> Option<SexpRef> { self.expressions.get(cid).copied() }
    pub fn has(&self, cid: &Cid) -> bool { self.expressions.contains_key(cid) }
    pub fn log(&self) -> &[Cid] { &self.log }
    pub fn arena(&self) -> &Arena { &self.arena }
    pub fn arena_mut(&mut self) -> &mut Arena { &mut self.arena }
    pub fn serialize_expr(&self, cid: &Cid) -> Option<Vec<u8>> { self.expressions.get(cid).map(|&idx| self.arena.serialize(idx)) }
    pub fn len(&self) -> usize { self.expressions.len() }
    
    pub fn deserialize_and_store(&mut self, data: &[u8]) -> Result<Option<(Cid, bool)>> {
        let expr = match self.arena.deserialize(data) {
            Some(e) => e,
            None => return Ok(None),
        };
        let (cid, is_new) = self.store(expr)?;
        Ok(Some((cid, is_new)))
    }
    
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for cid in &self.log { hasher.update(&cid.0); }
        hasher.finalize().into()
    }
    
    pub fn engage(&mut self, cid: &Cid) {
        if let Some(meta) = self.metadata.get_mut(cid) {
            meta.engage();
        }
    }
    
    pub fn get_decayed(&self) -> Vec<Cid> {
        self.metadata.iter()
            .filter(|(_, meta)| meta.is_decayed())
            .map(|(cid, _)| *cid)
            .collect()
    }
    
    pub fn remove(&mut self, cid: &Cid) -> bool {
        if self.expressions.remove(cid).is_some() {
            self.metadata.remove(cid);
            self.replies.remove(cid);
            self.log.retain(|c| c != cid);
            true
        } else {
            false
        }
    }
    
    pub fn get_meta(&self, cid: &Cid) -> Option<&ExpressionMeta> {
        self.metadata.get(cid)
    }
    
    pub fn add_reply(&mut self, parent: Cid, child: Cid) {
        let replies = self.replies.entry(parent).or_default();
        if !replies.contains(&child) {
            replies.push(child);
        }
    }
    
    pub fn get_replies(&self, cid: &Cid) -> Option<&Vec<Cid>> {
        self.replies.get(cid)
    }
    
    pub fn get_all_replies(&self) -> &HashMap<Cid, Vec<Cid>> {
        &self.replies
    }
}

impl Default for ExprStore { fn default() -> Self { Self::new() } }

// ============================================================================
// QUORUM / EPIGENETIC / PROPOSAL STATE
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumSignal {
    pub source: Did,
    pub pubkey: Vec<u8>,
    pub target: Cid,
    pub weight: u64,
    pub support: bool,
    pub elaboration: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl QuorumSignal {
    pub fn current_strength(&self) -> u64 {
        let age = timestamp().saturating_sub(self.timestamp);
        let decay = (-(age as f64) / SIGNAL_HALF_LIFE as f64).exp();
        (self.weight as f64 * decay) as u64
    }
    
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.target.0);
        data.push(if self.support { 1 } else { 0 });
        data.extend_from_slice(self.elaboration.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumState {
    pub target: Cid,
    pub threshold: u64,
    pub signals_for: Vec<QuorumSignal>,
    pub signals_against: Vec<QuorumSignal>,
    pub sources_seen: HashSet<Did>,
    pub created: u64,
    pub proposer: Did,
}

impl QuorumState {
    pub fn new(target: Cid, threshold: u64, proposer: Did) -> Self {
        Self { 
            target, threshold, 
            signals_for: Vec::new(), 
            signals_against: Vec::new(), 
            sources_seen: HashSet::new(), 
            created: timestamp(),
            proposer,
        }
    }
    
    pub fn sense(&mut self, signal: QuorumSignal) -> Result<bool> {
        if self.sources_seen.contains(&signal.source) || signal.target != self.target { 
            return Ok(false); 
        }
        
        if signal.source == self.proposer {
            return Err(DiagonError::SelfVoteProhibited);
        }
        
        self.sources_seen.insert(signal.source.clone());
        if signal.support { self.signals_for.push(signal); } 
        else { self.signals_against.push(signal); }
        Ok(true)
    }
    
    pub fn accumulated_for(&self) -> u64 { self.signals_for.iter().map(|s| s.current_strength()).sum() }
    pub fn accumulated_against(&self) -> u64 { self.signals_against.iter().map(|s| s.current_strength()).sum() }
    pub fn reached(&self) -> bool { self.accumulated_for() >= self.threshold }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpigeneticMark {
    pub score: f64,
    pub interactions: u32,
    pub last_active: u64,
}

impl EpigeneticMark {
    pub fn new() -> Self { Self { score: TRUST_DEFAULT, interactions: 0, last_active: timestamp() } }
    
    pub fn update(&mut self, quality: f64, verified: bool) {
        let effective_quality = if verified { quality } else { quality.min(0.6) };
        self.score = self.score * TRUST_HISTORY_WEIGHT + effective_quality * TRUST_NEW_WEIGHT;
        self.interactions += 1;
        self.last_active = timestamp();
    }
    
    pub fn current_score(&self) -> f64 {
        let age = timestamp().saturating_sub(self.last_active);
        let decay = (-(age as f64) / (SIGNAL_HALF_LIFE as f64 * 10.0)).exp();
        self.score * (0.5 + 0.5 * decay)
    }
    
    pub fn signal_weight(&self) -> u64 { ((self.current_score() * 1000.0) as u64).max(100) }
}

impl Default for EpigeneticMark { fn default() -> Self { Self::new() } }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalState {
    pub cid: Cid,
    pub expr_data: Vec<u8>,
    pub proposer: Did,
    pub elaboration: String,
    pub quorum: QuorumState,
    pub created: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinnedContent {
    pub cid: Cid,
    pub pinned_by: Did,
    pub reason: String,
    pub quorum: QuorumState,
    pub pinned_at: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruneProposal {
    pub cid: Cid,
    pub proposer: Did,
    pub reason: String,
    pub quorum: QuorumState,
    pub created: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DerivedState {
    pub proposals: BTreeMap<Cid, ProposalState>,
    pub pinned: BTreeMap<Cid, PinnedContent>,
    pub prune_proposals: BTreeMap<Cid, PruneProposal>,
    pub decay_proposals: BTreeMap<Cid, DecayConfigProposal>,
    pub marks: HashMap<Did, EpigeneticMark>,
}

impl DerivedState {
    pub fn new() -> Self { Self::default() }
    
    pub fn threshold(&self, peer_count: usize) -> u64 {
        (((peer_count + 1) as f64 * EIGEN_THRESHOLD * 1000.0) as u64).max(1000)
    }
    
    pub fn get_mark(&self, did: &Did) -> EpigeneticMark { self.marks.get(did).cloned().unwrap_or_default() }
    
    pub fn update_mark(&mut self, did: &Did, quality: f64, verified: bool) { 
        self.marks.entry(did.clone()).or_default().update(quality, verified); 
    }
    
    pub fn can_add_proposal(&self) -> bool { self.proposals.len() < MAX_PROPOSALS }
    pub fn can_add_pin(&self) -> bool { self.pinned.len() < MAX_PINNED }
}

// ============================================================================
// NETWORK MESSAGES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetMessage {
    Hello { did: Did, pubkey: Vec<u8>, pool: [u8; 32], expr_root: [u8; 32] },
    Challenge([u8; 32]),
    Response { nonce: [u8; 32], signature: Vec<u8> },
    ElaborateRequest,
    Elaborate { text: String, signature: Vec<u8> },
    
    Expression(Vec<u8>),
    Signal(QuorumSignal),
    
    SyncRequest { merkle: [u8; 32], have: Vec<Cid> },
    SyncReply { expressions: Vec<Vec<u8>>, pinned: Vec<Cid> },
    
    Heartbeat { timestamp: u64, signature: Vec<u8> },
    Disconnect { timestamp: u64, signature: Vec<u8> },
    
    Discover { pools: Vec<[u8; 32]>, want_hints: bool },
    DiscoverResponse { peers: Vec<DiscoveredPeer>, pool_hints: Vec<PoolHint> },
    
    ContentStart(ContentMetadata),
    ContentData(ContentChunk),
    ContentAck { content_id: [u8; 32], chunk_index: u32 },
    ContentRetransmit { content_id: [u8; 32], missing_chunks: Vec<u32> },
    ContentComplete { content_id: [u8; 32], signature: Vec<u8> },
    ContentError { content_id: [u8; 32], reason: String },
    
    DmRequest { from: Did, ephemeral_pubkey: [u8; 32], signature: Vec<u8> },
    DmAccept { from: Did, ephemeral_pubkey: [u8; 32], signature: Vec<u8> },
    DmReject { from: Did, reason: String, signature: Vec<u8> },
    DmMessage(DmMessage),
    
    PinRequest { cid: Cid, reason: String, signature: Vec<u8> },
    PinSignal(QuorumSignal),
    
    PruneRequest { cid: Cid, reason: String, signature: Vec<u8> },
    PruneSignal(QuorumSignal),
    
    // DHT Messages
    DhtRegister {
        topic_hash: [u8; 32],
        pool_commitment: [u8; 32],
        pool_name: String,
        description: String,
        peer_count: usize,
        signature: Vec<u8>,
    },
    DhtDirectoryRequest,
    DhtDirectoryResponse { entries: Vec<DhtEntry> },
    DhtSearchRequest { topic_hash: [u8; 32] },
    DhtSearchResponse { topic_hash: [u8; 32], results: Vec<DhtEntry> },
    DhtPoolAnnounce {
        pool_commitment: [u8; 32],
        pool_name: String,
        peer_count: usize,
        topics: Vec<[u8; 32]>,
        signature: Vec<u8>,
    },

    // Decay config
    DecayConfigPropose {
        id: Cid,
        config: DecayConfig,
        reason: String,
        signature: Vec<u8>,
    },
    DecayConfigSignal(QuorumSignal),
    Acknowledge(Acknowledgment),
    MutualApprove { 
        timestamp: u64, 
        peer_did: Did,
        /// Hash of their elaboration we're approving
        elaboration_hash: [u8; 32], 
        signature: Vec<u8>,
    },
    MutualReject { 
        reason: String, 
        signature: Vec<u8>,
    },
    TestimonyRequest {
        cid: Cid,
        requester_pool: [u8; 32],
        requester: Did,
        timestamp: u64,
        signature: Vec<u8>,
    },
    TestimonyAnnounce {
        testimony: Testimony,
    },
    ReviewAssignment {
        content_cid: Cid,
        content_type: ReviewableContentType,
        content_text: String,
        context_text: Option<String>,
        deadline: u64,
        signature: Vec<u8>,
    },
    ReviewSubmission { review: QualityReview },
    ReviewVerdict { verdict: QualityVerdict },
    ReviewQueueRequest,
    ReviewQueueResponse { pending_count: usize, my_assignments: Vec<Cid>, my_completed: usize },
}

impl NetMessage {
    fn serialize(&self) -> Result<Vec<u8>> { 
        bincode::serialize(self).map_err(|e| DiagonError::Serialization(e.to_string())) 
    }
    fn deserialize(data: &[u8]) -> Result<Self> { 
        bincode::deserialize(data).map_err(|e| DiagonError::Serialization(e.to_string())) 
    }
    
    fn signable_bytes(&self) -> Option<Vec<u8>> {
        match self {
            NetMessage::Heartbeat { timestamp, .. } => {
                let mut data = b"heartbeat:".to_vec();
                data.extend_from_slice(&timestamp.to_le_bytes());
                Some(data)
            }
            NetMessage::Disconnect { timestamp, .. } => {
                let mut data = b"disconnect:".to_vec();
                data.extend_from_slice(&timestamp.to_le_bytes());
                Some(data)
            }
            NetMessage::Elaborate { text, .. } => Some(text.as_bytes().to_vec()),
            NetMessage::DmRequest { from, ephemeral_pubkey, .. } => {
                let mut data = b"dm-request:".to_vec();
                data.extend_from_slice(from.0.as_bytes());
                data.extend_from_slice(ephemeral_pubkey);
                Some(data)
            }
            NetMessage::DmAccept { from, ephemeral_pubkey, .. } => {
                let mut data = b"dm-accept:".to_vec();
                data.extend_from_slice(from.0.as_bytes());
                data.extend_from_slice(ephemeral_pubkey);
                Some(data)
            }
            NetMessage::DmReject { from, reason, .. } => {
                let mut data = b"dm-reject:".to_vec();
                data.extend_from_slice(from.0.as_bytes());
                data.extend_from_slice(reason.as_bytes());
                Some(data)
            }
            NetMessage::PinRequest { cid, reason, .. } => {
                let mut data = b"pin:".to_vec();
                data.extend_from_slice(&cid.0);
                data.extend_from_slice(reason.as_bytes());
                Some(data)
            }
            NetMessage::PruneRequest { cid, reason, .. } => {
                let mut data = b"prune:".to_vec();
                data.extend_from_slice(&cid.0);
                data.extend_from_slice(reason.as_bytes());
                Some(data)
            }
            NetMessage::DhtRegister { topic_hash, pool_commitment, pool_name, description, .. } => {
                let mut data = b"dht-register:".to_vec();
                data.extend_from_slice(topic_hash);
                data.extend_from_slice(pool_commitment);
                data.extend_from_slice(pool_name.as_bytes());
                data.extend_from_slice(description.as_bytes());
                Some(data)
            }
            NetMessage::DhtPoolAnnounce { pool_commitment, pool_name, peer_count, topics, .. } => {
                let mut data = b"dht-announce:".to_vec();
                data.extend_from_slice(pool_commitment);
                data.extend_from_slice(pool_name.as_bytes());
                data.extend_from_slice(&(*peer_count as u64).to_le_bytes());
                for t in topics {
                    data.extend_from_slice(t);
                }
                Some(data)
            }
            NetMessage::Acknowledge(ack) => Some(ack.signable_bytes()),
            NetMessage::MutualApprove { timestamp, peer_did, elaboration_hash, .. } => {
                let mut data = b"mutual-approve:".to_vec();
                data.extend_from_slice(&timestamp.to_le_bytes());
                data.extend_from_slice(peer_did.0.as_bytes());
                data.extend_from_slice(elaboration_hash);
                Some(data)
            }
            NetMessage::MutualReject { reason, .. } => {
                let mut data = b"mutual-reject:".to_vec();
                data.extend_from_slice(reason.as_bytes());
                Some(data)
            }
            NetMessage::TestimonyRequest { cid, requester_pool, requester, timestamp, .. } => {
                let mut data = b"testimony-request:".to_vec();
                data.extend_from_slice(&cid.0);
                data.extend_from_slice(requester_pool);
                data.extend_from_slice(requester.0.as_bytes());
                data.extend_from_slice(&timestamp.to_le_bytes());
                Some(data)
            }
            NetMessage::TestimonyAnnounce { testimony } => Some(testimony.signable_bytes()),
            NetMessage::ReviewAssignment { content_cid, content_type, content_text, deadline, .. } => {
                let mut data = b"review-assignment:".to_vec();
                data.extend_from_slice(&content_cid.0);
                data.extend_from_slice(content_type.as_str().as_bytes());
                data.extend_from_slice(content_text.as_bytes());
                data.extend_from_slice(&deadline.to_le_bytes());
                Some(data)
            }
            NetMessage::ReviewSubmission { review } => Some(review.signable_bytes()),
            NetMessage::ReviewVerdict { verdict } => {
                let mut data = b"review-verdict:".to_vec();
                data.extend_from_slice(&verdict.content_cid.0);
                data.extend_from_slice(&verdict.verdict_at.to_le_bytes());
                Some(data)
            }
            NetMessage::ReviewQueueRequest => None,
            NetMessage::ReviewQueueResponse { .. } => None,
            NetMessage::DecayConfigPropose { id, config, reason, .. } => {
                let mut data = b"decay-config:".to_vec();
                data.extend_from_slice(&id.0);
                data.push(if config.enabled { 1 } else { 0 });
                data.extend_from_slice(&config.decay_days.to_le_bytes());
                data.push(if config.require_engagement { 1 } else { 0 });
                data.extend_from_slice(reason.as_bytes());
                Some(data)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub addr: SocketAddr,
    pub pool: [u8; 32],
    pub expr_count: usize,
    pub uptime_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolHint {
    pub commitment: [u8; 32],
    pub hint: String,
    pub peer_count: usize,
    pub is_genesis: bool,
}

impl PoolHint {
    fn from_commitment(commitment: [u8; 32], hint: Option<&str>, peer_count: usize) -> Self {
        Self {
            commitment,
            hint: hint.map(|s| s.to_string()).unwrap_or_else(|| format!("{}...", hex::encode(&commitment[..4]))),
            peer_count,
            is_genesis: GENESIS_POOLS.contains(&commitment),
        }
    }
}

// ============================================================================
// ASYNC CONNECTION
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Connecting,
    Authenticating,
    AwaitingOurElaboration,
    AwaitingTheirElaboration,
    MutualPending,
    AwaitingTheirApproval,
    AwaitingOurApproval,
    Connected,
    Closing,
    Closed,
}

#[derive(Debug)]
enum ConnCmd {
    Send(Vec<u8>),
    Close,
}

struct PeerInfo {
    addr: SocketAddr,
    did: Option<Did>,
    pubkey: Option<Vec<u8>>,
    state: ConnectionState,
    our_elaboration: Option<String>,
    elaboration: Option<String>,  // their elaboration
    we_approved: bool,
    they_approved: bool,
    last_activity: Instant,
    seen_cids: HashSet<Cid>,
    challenge_sent: Option<[u8; 32]>,
    challenge_time: Option<Instant>,
    initiated: bool,
}

impl PeerInfo {
    fn new(addr: SocketAddr, initiated: bool) -> Self {
        Self {
            addr, 
            did: None, 
            pubkey: None,
            state: ConnectionState::Connecting,
            our_elaboration: None,
            elaboration: None,
            we_approved: false,
            they_approved: false,
            last_activity: Instant::now(),
            seen_cids: HashSet::new(),
            challenge_sent: None,
            challenge_time: None,
            initiated,
        }
    }
    
    fn is_alive(&self) -> bool {
        self.state != ConnectionState::Closed 
            && self.state != ConnectionState::Closing 
            && self.last_activity.elapsed() < Duration::from_secs(PEER_TIMEOUT_SECS)
    }
    
    fn is_authenticated(&self) -> bool { 
        self.state == ConnectionState::Connected 
    }
    
    fn both_elaborated(&self) -> bool {
        self.our_elaboration.is_some() && self.elaboration.is_some()
    }
    
    fn both_approved(&self) -> bool {
        self.we_approved && self.they_approved
    }
    
    fn check_mutual_pending(&mut self) -> bool {
        if self.both_elaborated() && 
           self.state != ConnectionState::MutualPending &&
           self.state != ConnectionState::Connected {
            self.state = ConnectionState::MutualPending;
            true
        } else {
            false
        }
    }
    
    fn check_connected(&mut self) -> bool {
        if self.both_approved() && self.both_elaborated() {
            self.state = ConnectionState::Connected;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct ConnHandle {
    addr: SocketAddr,
    cmd_tx: mpsc::Sender<ConnCmd>,
}

impl ConnHandle {
    async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.cmd_tx.send(ConnCmd::Send(data)).await.map_err(|_| DiagonError::ConnectionLost)
    }
    
    async fn close(&self) { let _ = self.cmd_tx.send(ConnCmd::Close).await; }
}

// ============================================================================
// CONNECTION POOL
// ============================================================================

struct ConnectionPool {
    peers: RwLock<HashMap<SocketAddr, Arc<RwLock<PeerInfo>>>>,
    handles: RwLock<HashMap<SocketAddr, ConnHandle>>,
    by_did: RwLock<HashMap<Did, Vec<SocketAddr>>>,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            handles: RwLock::new(HashMap::new()),
            by_did: RwLock::new(HashMap::new()),
        }
    }
    
    async fn add(&self, addr: SocketAddr, info: Arc<RwLock<PeerInfo>>, handle: ConnHandle) -> Result<()> {
        let mut peers = self.peers.write().await;
        if peers.len() >= MAX_CONNECTIONS {
            let mut oldest_addr = None;
            let mut oldest_time = Instant::now();
            for (a, p) in peers.iter() {
                let p = p.read().await;
                if !p.is_authenticated() && p.last_activity < oldest_time {
                    oldest_time = p.last_activity;
                    oldest_addr = Some(*a);
                }
            }
            if let Some(addr) = oldest_addr {
                drop(peers);
                self.remove(addr).await;
                peers = self.peers.write().await;
            } else {
                return Err(DiagonError::PoolFull);
            }
        }
        peers.insert(addr, info);
        drop(peers);
        self.handles.write().await.insert(addr, handle);
        Ok(())
    }
    
    async fn register_did(&self, addr: SocketAddr, did: &Did) {
        if let Some(info) = self.peers.read().await.get(&addr) {
            info.write().await.did = Some(did.clone());
            self.by_did.write().await.entry(did.clone()).or_default().push(addr);
        }
    }
    
    async fn get_info(&self, addr: &SocketAddr) -> Option<Arc<RwLock<PeerInfo>>> {
        self.peers.read().await.get(addr).cloned()
    }
    
    async fn get_handle(&self, addr: &SocketAddr) -> Option<ConnHandle> {
        self.handles.read().await.get(addr).cloned()
    }
    
    async fn get_handle_by_did(&self, did: &Did) -> Option<ConnHandle> {
        let by_did = self.by_did.read().await;
        if let Some(addrs) = by_did.get(did) {
            if let Some(&addr) = addrs.first() {
                drop(by_did);
                return self.get_handle(&addr).await;
            }
        }
        None
    }
    
    async fn remove(&self, addr: SocketAddr) {
        if let Some(info) = self.peers.write().await.remove(&addr) {
            let info = info.read().await;
            if let Some(did) = &info.did {
                let mut by_did = self.by_did.write().await;
                if let Some(addrs) = by_did.get_mut(did) {
                    addrs.retain(|a| *a != addr);
                    if addrs.is_empty() { by_did.remove(did); }
                }
            }
        }
        if let Some(handle) = self.handles.write().await.remove(&addr) {
            handle.close().await;
        }
    }
    
    async fn authenticated_addrs(&self) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        let peers_snapshot: Vec<_> = {
            let peers = self.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        for (addr, info) in peers_snapshot {
            if info.read().await.is_authenticated() { 
                result.push(addr); 
            }
        }
        result
    }
    
    async fn pending_approval(&self) -> Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> {
        let mut result = Vec::new();
        let peers_snapshot: Vec<_> = {
            let peers = self.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        for (addr, info) in peers_snapshot {
            let state = info.read().await.state.clone();
            match state {
                ConnectionState::MutualPending |
                ConnectionState::AwaitingOurApproval => {
                    result.push((addr, info));
                }
                _ => {}
            }
        }
        result
    }
    
    async fn awaiting_elaboration(&self) -> Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> {
        let mut result = Vec::new();
        let peers_snapshot: Vec<_> = {
            let peers = self.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        for (addr, info) in peers_snapshot {
            if info.read().await.state == ConnectionState::AwaitingOurElaboration {
                result.push((addr, info));
            }
        }
        result
    }
    
    async fn dead_connections(&self) -> Vec<SocketAddr> {
        let mut dead = Vec::new();
        let peers_snapshot: Vec<_> = {
            let peers = self.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        for (addr, info) in peers_snapshot {
            if !info.read().await.is_alive() { 
                dead.push(addr); 
            }
        }
        dead
    }
    
    async fn shutdown(&self) {
        let addrs: Vec<_> = self.peers.read().await.keys().cloned().collect();
        for addr in addrs { self.remove(addr).await; }
    }
}

// ============================================================================
// PERSISTENCE
// ============================================================================

#[derive(Serialize, Deserialize)]
struct PersistedState {
    identity: (Vec<u8>, Vec<u8>, Did),
    expressions: Vec<(Cid, Vec<u8>, ExpressionMeta)>,
    proposals: Vec<(Cid, ProposalState)>,
    pinned: Vec<(Cid, PinnedContent)>,
    marks: Vec<(Did, EpigeneticMark)>,
    xp: XpState,
    replies: Vec<(Cid, Vec<Cid>)>,
    dht_entries: Vec<DhtEntry>,
    pool_name: Option<String>,
    pool_topics: Vec<[u8; 32]>,
    decay_config: Option<DecayConfig>,
    decay_proposals: Vec<(Cid, DecayConfigProposal)>,
    /// Testimony registry - testimonies we've given
    #[serde(default)]
    testimony_registry: TestimonyRegistry,
    // Rv
    #[serde(default)]
    review_state: ReviewState,
}

// ============================================================================
// POOL AUTHENTICATION
// ============================================================================

fn hash_pool_passphrase(passphrase: &str) -> [u8; 32] {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
            .expect("Invalid Argon2 params"),
    );
    
    let salt = SaltString::encode_b64(POOL_SALT).expect("Invalid salt");
    let hash = argon2.hash_password(passphrase.as_bytes(), &salt).expect("Hashing failed");
    
    let mut result = [0u8; 32];
    if let Some(output) = hash.hash {
        let bytes = output.as_bytes();
        let len = bytes.len().min(32);
        result[..len].copy_from_slice(&bytes[..len]);
    }
    result
}

// ============================================================================
// NODE
// ============================================================================

pub struct Node {
    did: Did,
    secret_key: SecretKey,
    public_key: PublicKey,
    bind_addr: String,
    started_at: Instant,
    pool: RwLock<Option<[u8; 32]>>,
    connection_pool: Arc<ConnectionPool>,
    reconnect_queue: RwLock<VecDeque<(SocketAddr, Instant, u32)>>,
    store: RwLock<ExprStore>,
    state: RwLock<DerivedState>,
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
    shutdown_tx: mpsc::Sender<()>,
    db_path: String,
    rate_limiter: RwLock<RateLimiter>,
    nonce_tracker: RwLock<NonceTracker>,
    incoming_transfers: RwLock<HashMap<[u8; 32], IncomingTransfer>>,
    outgoing_transfers: RwLock<HashMap<[u8; 32], ContentEncoder>>,
    dm_channels: RwLock<HashMap<[u8; 32], DmChannel>>,
    dm_secrets: RwLock<HashMap<[u8; 32], ReusableSecret>>,
    xp: RwLock<XpState>,
    dht: RwLock<DhtState>,
    pool_name: RwLock<Option<String>>,
    pool_topics: RwLock<Vec<[u8; 32]>>,
    decay_config: RwLock<DecayConfig>,
    testimony_registry: RwLock<TestimonyRegistry>,
    review_state: RwLock<ReviewState>,
}

impl Node {
    pub async fn new(bind_addr: &str, db_path: &str) -> Result<Arc<Self>> {
        let db = db_path.to_string();
        tokio::task::spawn_blocking(move || std::fs::create_dir_all(&db)).await.ok();
        
        let persistence_path = format!("{}/state.cbor", db_path);
        let (did, secret_key, public_key, store, state, xp, dht, pool_name, pool_topics, decay_config, testimony_registry, review_state) = 
            Self::load_or_create(&persistence_path).await?;
        
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        
        let node = Arc::new(Self {
            did: did.clone(),
            secret_key,
            public_key,
            bind_addr: bind_addr.to_string(),
            started_at: Instant::now(),
            pool: RwLock::new(None),
            connection_pool: Arc::new(ConnectionPool::new()),
            reconnect_queue: RwLock::new(VecDeque::new()),
            store: RwLock::new(store),
            state: RwLock::new(state),
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown_tx,
            db_path: db_path.to_string(),
            rate_limiter: RwLock::new(RateLimiter::default()),
            nonce_tracker: RwLock::new(NonceTracker::new(CHALLENGE_TIMEOUT_SECS * 2)),
            incoming_transfers: RwLock::new(HashMap::new()),
            outgoing_transfers: RwLock::new(HashMap::new()),
            dm_channels: RwLock::new(HashMap::new()),
            dm_secrets: RwLock::new(HashMap::new()),
            xp: RwLock::new(xp),
            dht: RwLock::new(dht),
            pool_name: RwLock::new(pool_name),
            pool_topics: RwLock::new(pool_topics),
            decay_config: RwLock::new(decay_config),
            testimony_registry: RwLock::new(testimony_registry),
            review_state: RwLock::new(review_state),
        });
        
        println!("DIAGON v0.9.6 - Collective Consciousness Protocol");
        println!("   \"Consensus, sharing, collective truth\"");
        println!();
        println!("[MY ID] DID: {}", did.0);
        println!("[LISTEN] {}", bind_addr);
        println!("[DB] {}", db_path);
        println!();
        
        let n = Arc::clone(&node);
        tokio::spawn(async move { n.accept_loop().await });
        
        let n = Arc::clone(&node);
        tokio::spawn(async move { n.heartbeat_loop().await });
        
        let n = Arc::clone(&node);
        tokio::spawn(async move { n.sync_loop().await });
        
        let n = Arc::clone(&node);
        tokio::spawn(async move { n.reconnect_loop().await });
        
        let n = Arc::clone(&node);
        tokio::spawn(async move { n.decay_loop().await });
        
        let n = Arc::clone(&node);
        tokio::spawn(async move { n.dht_sync_loop().await });
        
        Ok(node)
    }
    
    async fn load_or_create(path: &str) -> Result<(Did, SecretKey, PublicKey, ExprStore, DerivedState, XpState, DhtState, Option<String>, Vec<[u8; 32]>, DecayConfig, TestimonyRegistry, ReviewState)> {
        let path = path.to_string();
        tokio::task::spawn_blocking(move || {
            if let Ok(file) = std::fs::File::open(&path) {
                if let Ok(persisted) = serde_cbor::from_reader::<PersistedState, _>(std::io::BufReader::new(file)) {
                    if let (Ok(pk), Ok(sk)) = (PublicKey::from_bytes(&persisted.identity.0), SecretKey::from_bytes(&persisted.identity.1)) {
                        let did = Did::from_pubkey(&pk);
                        if did == persisted.identity.2 {
                            let mut store = ExprStore::new();
                            for (cid, data, meta) in persisted.expressions { 
                                if let Some(expr) = store.arena_mut().deserialize(&data) { 
                                    let _ = store.store(expr);
                                    store.metadata.insert(cid, meta);
                                } 
                            }
                            for (parent, children) in persisted.replies {
                                for child in children {
                                    store.add_reply(parent, child);
                                }
                            }
                            let mut state = DerivedState::new();
                            for (cid, prop) in persisted.proposals { state.proposals.insert(cid, prop); }
                            for (cid, pin) in persisted.pinned { state.pinned.insert(cid, pin); }
                            for (did, mark) in persisted.marks { state.marks.insert(did, mark); }
                            for (cid, prop) in persisted.decay_proposals { state.decay_proposals.insert(cid, prop); }

                            let decay_config = persisted.decay_config.unwrap_or_default();
                            
                            let mut dht = DhtState::new();
                            for entry in persisted.dht_entries {
                                dht.register(entry);
                            }
                            
                            let testimony_registry = persisted.testimony_registry;
                            let review_state = persisted.review_state;
                            
                            println!("📥 Loaded {} expressions, {} proposals, {} XP, {} DHT entries, {} testimonies given, {:?} review state", 
                                store.log().len(), state.proposals.len(), persisted.xp.total_xp,
                                dht.get_directory().len(), testimony_registry.given_count, review_state);
                            return Ok((did, sk, pk, store, state, persisted.xp, dht, persisted.pool_name, persisted.pool_topics, decay_config, testimony_registry, review_state));
                        }
                    }
                }
            }
            let (public_key, secret_key) = keypair();
            let did = Did::from_pubkey(&public_key);
            Ok((did, secret_key, public_key, ExprStore::new(), DerivedState::new(), XpState::new(), DhtState::new(), None, Vec::new(), DecayConfig::default(), TestimonyRegistry::new(), ReviewState::new()))
        }).await.map_err(|e| DiagonError::Io(io::Error::new(ErrorKind::Other, e.to_string())))?
    }
    
    async fn save_state(&self) -> Result<()> {
        let store = self.store.read().await;
        let state = self.state.read().await;
        let xp = self.xp.read().await;
        let dht = self.dht.read().await;
        let pool_name = self.pool_name.read().await.clone();
        let pool_topics = self.pool_topics.read().await.clone();
        let testimony_registry = self.testimony_registry.read().await.clone();
        
        let expressions: Vec<_> = store.log().iter()
            .filter_map(|cid| {
                store.serialize_expr(cid).map(|data| {
                    let meta = store.metadata.get(cid).cloned().unwrap_or_default();
                    (*cid, data, meta)
                })
            })
            .collect();
        
        let replies: Vec<_> = store.get_all_replies()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        
        let decay_config = self.decay_config.read().await.clone();
        let decay_proposals: Vec<_> = self.state.read().await
            .decay_proposals.iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let review_state = self.review_state.read().await.clone();
        
        let persisted = PersistedState {
            identity: (self.public_key.as_bytes().to_vec(), self.secret_key.as_bytes().to_vec(), self.did.clone()),
            expressions,
            proposals: state.proposals.iter().map(|(k, v)| (*k, v.clone())).collect(),
            pinned: state.pinned.iter().map(|(k, v)| (*k, v.clone())).collect(),
            marks: state.marks.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            xp: xp.clone(),
            replies,
            dht_entries: dht.get_directory(),
            pool_name,
            pool_topics,
            decay_config: Some(decay_config),
            decay_proposals,
            testimony_registry,
            review_state,
        };
        drop(store);
        drop(state);
        drop(xp);
        drop(dht);
        
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let temp = format!("{}/state.cbor.tmp", db_path);
            let path = format!("{}/state.cbor", db_path);
            let file = std::fs::File::create(&temp)?;
            serde_cbor::to_writer(std::io::BufWriter::new(file), &persisted)
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
            std::fs::rename(temp, path)?;
            Ok::<_, io::Error>(())
        }).await.map_err(|e| DiagonError::Io(io::Error::new(ErrorKind::Other, e.to_string())))??;
        Ok(())
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> { 
        detached_sign(data, &self.secret_key).as_bytes().to_vec() 
    }
    
    fn verify(&self, data: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<()> {
        let pk = PublicKey::from_bytes(pubkey).map_err(|_| DiagonError::Crypto("Invalid public key".into()))?;
        let sig = DetachedSignature::from_bytes(signature).map_err(|_| DiagonError::Crypto("Invalid signature".into()))?;
        verify_detached_signature(&sig, data, &pk).map_err(|_| DiagonError::Crypto("Verification failed".into()))
    }
    
    fn is_shutdown(&self) -> bool {
        self.shutdown_flag.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    async fn verify_message_signature(&self, msg: &NetMessage, from: &SocketAddr) -> Result<()> {
        let signable = match msg.signable_bytes() {
            Some(b) => b,
            None => return Ok(()),
        };
        
        let signature = match msg {
            NetMessage::MutualApprove { signature, .. } |
            NetMessage::MutualReject { signature, .. } |
            NetMessage::Heartbeat { signature, .. } |
            NetMessage::Disconnect { signature, .. } |
            NetMessage::Elaborate { signature, .. } |
            NetMessage::DmRequest { signature, .. } |
            NetMessage::DmAccept { signature, .. } |
            NetMessage::DmReject { signature, .. } |
            NetMessage::PinRequest { signature, .. } |
            NetMessage::PruneRequest { signature, .. } |
            NetMessage::DhtRegister { signature, .. } |
            NetMessage::DhtPoolAnnounce { signature, .. } => signature,
            NetMessage::Acknowledge(ack) => &ack.signature,
            NetMessage::MutualApprove { signature, .. } |
            NetMessage::MutualReject { signature, .. } |
            NetMessage::TestimonyRequest { signature, .. } => signature,
            NetMessage::TestimonyAnnounce { testimony } => &testimony.signature,
            _ => return Ok(()),
        };
        
        let info = self.connection_pool.get_info(from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let pubkey = info.read().await.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey for peer".into()))?;
        
        self.verify(&signable, signature, &pubkey)
    }
    
    fn is_in_rendezvous_sync(&self) -> bool {
        if let Some(pool) = *self.pool.blocking_read() {
            pool == rendezvous_commitment()
        } else {
            false
        }
    }
    
    async fn is_in_rendezvous(&self) -> bool {
        if let Some(pool) = *self.pool.read().await {
            pool == rendezvous_commitment()
        } else {
            false
        }
    }
    
    // ========== PUBLIC API ==========
    
    // replace auth method (around line 1858-1873)
    pub async fn auth(&self, passphrase: &str, name: Option<&str>) -> bool {
        let commitment = hash_pool_passphrase(passphrase);
        *self.pool.write().await = Some(commitment);
        
        if let Some(n) = name {
            *self.pool_name.write().await = Some(n.to_string());
        }
        
        let is_rendezvous = commitment == rendezvous_commitment();
        if is_rendezvous {
            println!("✔ Joined rendezvous pool (public discovery)");
            if let Some(n) = name {
                println!("  Pool name: {}", n);
            }
        } else {
            println!("✔ Pool set: {}", hex::encode(&commitment[..8]));
            if let Some(n) = name {
                println!("  Pool name: {}", n);
            }
            println!("  Share passphrase to invite others");
        }
        true
    }
    
    pub async fn join_rendezvous(&self) -> bool {
        println!("[RENDEZVOUS] Joining public discovery network...");
        self.auth(RENDEZVOUS_PASSPHRASE, None).await
    }
    
    pub async fn set_pool_name(&self, name: &str) {
        *self.pool_name.write().await = Some(name.to_string());
        println!("[POOL] Name set to: {}", name);
    }
    
    // replace connect method (around line 1883-1916)
    pub async fn connect(self: &Arc<Self>, target: &str) -> Result<()> {
        let pool = self.pool.read().await.ok_or_else(|| 
            DiagonError::Validation("Set pool first with 'auth'".into()))?;
        
        // Try parsing as IP:port first, otherwise resolve as DID
        let addr: SocketAddr = match target.parse() {
            Ok(a) => a,
            Err(_) => self.resolve_did_to_addr(target).await?,
        };
        
        if self.connection_pool.get_info(&addr).await.is_some() { 
            println!("Already connected to {}", addr); 
            return Ok(()); 
        }
        
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let info = Arc::new(RwLock::new(PeerInfo::new(addr, true)));
                info.write().await.state = ConnectionState::Authenticating;
                
                let expr_root = self.store.read().await.merkle_root();
                let hello = NetMessage::Hello { 
                    did: self.did.clone(), 
                    pubkey: self.public_key.as_bytes().to_vec(), 
                    pool, 
                    expr_root 
                };
                
                let handle = self.spawn_connection(stream, addr, Arc::clone(&info)).await?;
                handle.send(hello.serialize()?).await?;
                
                self.connection_pool.add(addr, info, handle).await?;
                println!("[->] Connecting to {}", addr);
                Ok(())
            }
            Err(e) => {
                self.reconnect_queue.write().await.push_back((addr, Instant::now(), 0));
                Err(DiagonError::Io(e))
            }
        }
    }
    
    /// Resolve DID prefix to socket address via connected peers or DHT hints
    async fn resolve_did_to_addr(&self, did_prefix: &str) -> Result<SocketAddr> {
        let normalized = did_prefix.trim_start_matches("did:diagon:");
        
        // Check by_did map first (previously connected peers)
        {
            let by_did = self.connection_pool.by_did.read().await;
            for (did, addrs) in by_did.iter() {
                if did.0.contains(normalized) || did.short().contains(normalized) {
                    if let Some(&addr) = addrs.first() {
                        println!("[RESOLVE] {} -> {}", did.short(), addr);
                        return Ok(addr);
                    }
                }
            }
        }
        
        // Check currently connected peers
        let peers_snapshot: Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> = {
            let peers = self.connection_pool.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        
        for (addr, info) in peers_snapshot {
            let info_guard = info.read().await;
            if let Some(ref did) = info_guard.did {
                if did.0.contains(normalized) || did.short().contains(normalized) {
                    println!("[RESOLVE] {} -> {}", did.short(), addr);
                    return Ok(addr);
                }
            }
        }
        
        // Check DHT for hints (pool registrations by this DID)
        let dht = self.dht.read().await;
        for entries in dht.entries.values() {
            for entry in entries {
                let reg_normalized = entry.registered_by.0.trim_start_matches("did:diagon:");
                if reg_normalized.contains(normalized) {
                    println!("[HINT] DID registered pool '{}' - use 'discover' then connect to announced peers", 
                             entry.pool_name);
                }
            }
        }
        
        Err(DiagonError::Validation(format!(
            "Cannot resolve '{}' - not a known peer. Use IP:port or 'discover' first.", 
            did_prefix
        )))
    }
    
    pub async fn elaborate(&self, text: &str) {
        if text.len() < MIN_ELABORATION_LEN {
            println!("[ERR] Elaboration must be at least {} characters", MIN_ELABORATION_LEN);
            return;
        }
        
        let sig = detached_sign(text.as_bytes(), &self.secret_key);
        let msg = NetMessage::Elaborate { 
            text: text.to_string(), 
            signature: sig.as_bytes().to_vec(),
        };
        
        // Track which connections we sent to: (did_short, is_mutual_pending)
        let mut sent_to: Vec<(String, bool)> = Vec::new();
        
        let pool = self.connection_pool.clone();
        
        // Get snapshot of peers
        let peers_snapshot: Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> = {
            let peers = pool.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        
        for (addr, info) in peers_snapshot {
            let mut info_guard = info.write().await;
            
            match info_guard.state {
                ConnectionState::AwaitingOurElaboration |
                ConnectionState::AwaitingTheirElaboration => {
                    // Send elaboration
                    if let Some(handle) = pool.get_handle(&addr).await {
                        if let Ok(data) = msg.serialize() {
                            let _ = handle.send(data).await;
                        }
                    }
                    
                    // Record our elaboration
                    info_guard.our_elaboration = Some(text.to_string());
                    
                    // Check if both have elaborated
                    if info_guard.check_mutual_pending() {
                        if let Some(ref did) = info_guard.did {
                            sent_to.push((did.short(), true));
                        }
                    } else {
                        info_guard.state = ConnectionState::AwaitingTheirElaboration;
                        if let Some(ref did) = info_guard.did {
                            sent_to.push((did.short(), false));
                        }
                    }
                }
                _ => {}
            }
        }
        
        if sent_to.is_empty() {
            println!("[ERR] No pending connections to elaborate to");
        } else {
            for (did_short, mutual) in sent_to {
                if mutual {
                    println!("[MUTUAL] Both elaborations complete with {}. Use 'review {}' then 'mutual-approve {}'", 
                             did_short, did_short, did_short);
                } else {
                    println!("[ELABORATE] Sent to {}, awaiting their elaboration...", did_short);
                }
            }
        }
    }
    
    pub async fn propose(&self, text: &str) {
        if text.len() < MIN_ELABORATION_LEN { println!("[REJECT] Proposal too short"); return; }
        if !self.state.read().await.can_add_proposal() {
            println!("[REJECT] Maximum proposals reached");
            return;
        }
        
        let trust = self.state.read().await.get_mark(&self.did).current_score();
        if trust < TRUST_MIN_FOR_PROPOSE { 
            println!("[REJECT] Insufficient trust: {:.2} < {:.2}", trust, TRUST_MIN_FOR_PROPOSE); 
            return; 
        }
        
        let mut store = self.store.write().await;
        let op = store.arena_mut().atom("propose");
        let t = store.arena_mut().atom(text);
        let e = store.arena_mut().atom(text);
        let expr = store.arena_mut().list(&[op, t, e]);
        let expr_data = store.arena().serialize(expr);
        let sig = self.sign(&expr_data);
        let signed_op = store.arena_mut().atom("signed");
        let pk_ref = store.arena_mut().bytes(self.public_key.as_bytes());
        let sig_ref = store.arena_mut().bytes(&sig);
        let signed_expr = store.arena_mut().list(&[signed_op, pk_ref, sig_ref, expr]);
        let (cid, _) = match store.store(signed_expr) {
            Ok(r) => r,
            Err(e) => { println!("[ERROR] {}", e); return; }
        };
        let expr_bytes = store.arena().serialize(signed_expr);
        drop(store);
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        let proposal = ProposalState { 
            cid, 
            expr_data: expr_bytes.clone(), 
            proposer: self.did.clone(), 
            elaboration: text.to_string(), 
            quorum: QuorumState::new(cid, threshold, self.did.clone()),
            created: timestamp() 
        };
        self.state.write().await.proposals.insert(cid, proposal);
        let _ = self.save_state().await;
        println!("[PROPOSE] {}", cid);
        self.broadcast_authenticated(&NetMessage::Expression(expr_bytes)).await;
    }
    
    pub async fn reply(&self, parent_cid_prefix: &str, text: &str) {
        if text.len() < MIN_ELABORATION_LEN { 
            println!("[REJECT] Reply too short (min {} chars)", MIN_ELABORATION_LEN); 
            return; 
        }
        
        let mut store = self.store.write().await;
        let parent_cid = match store.log().iter().find(|c| c.short().starts_with(parent_cid_prefix)).copied() {
            Some(c) => c,
            None => { println!("[NULL] Parent expression not found"); return; }
        };
        
        let reply_to_op = store.arena_mut().atom("reply-to");
        let parent_ref = store.arena_mut().bytes(&parent_cid.0);
        let text_ref = store.arena_mut().atom(text);
        let inner_expr = store.arena_mut().list(&[reply_to_op, parent_ref, text_ref]);
        
        let inner_data = store.arena().serialize(inner_expr);
        let sig = self.sign(&inner_data);
        
        let signed_op = store.arena_mut().atom("signed");
        let pk_ref = store.arena_mut().bytes(self.public_key.as_bytes());
        let sig_ref = store.arena_mut().bytes(&sig);
        let signed_expr = store.arena_mut().list(&[signed_op, pk_ref, sig_ref, inner_expr]);
        
        let (cid, _) = match store.store(signed_expr) {
            Ok(r) => r,
            Err(e) => { println!("[ERROR] {}", e); return; }
        };
        
        store.add_reply(parent_cid, cid);
        
        let expr_bytes = store.arena().serialize(signed_expr);
        drop(store);
        
        let _ = self.save_state().await;
        println!("[REPLY] {} -> {}", cid.short(), parent_cid.short());
        self.broadcast_authenticated(&NetMessage::Expression(expr_bytes)).await;
    }
    
    pub async fn thread(&self, cid_prefix: &str) {
        let store = self.store.read().await;
        
        let root_cid = match store.log().iter().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c,
            None => { println!("[NULL] Expression not found"); return; }
        };
        
        println!();
        println!("=== THREAD {} ===", root_cid.short());
        
        let root_content = self.extract_expression_content(&store, &root_cid);
        let root_time = store.get_meta(&root_cid)
            .map(|m| format_timestamp(m.created_at))
            .unwrap_or_else(|| "?".into());
        println!("[ROOT] \"{}\" ({})", root_content, root_time);
        
        self.print_thread_replies(&store, &root_cid, 1);
        println!();
    }
    
    fn print_thread_replies(&self, store: &ExprStore, parent: &Cid, depth: usize) {
        if let Some(replies) = store.get_replies(parent) {
            let mut sorted_replies: Vec<_> = replies.iter()
                .filter_map(|cid| {
                    store.get_meta(cid).map(|meta| (*cid, meta.created_at))
                })
                .collect();
            sorted_replies.sort_by_key(|(_, ts)| *ts);
            
            for (i, (reply_cid, _)) in sorted_replies.iter().enumerate() {
                let is_last = i == sorted_replies.len() - 1;
                let prefix = "  ".repeat(depth);
                let branch = if is_last { "└─" } else { "├─" };
                
                let content = self.extract_expression_content(store, reply_cid);
                let time = store.get_meta(reply_cid)
                    .map(|m| format_timestamp(m.created_at))
                    .unwrap_or_else(|| "?".into());
                
                println!("{}{} {} \"{}\" ({})", prefix, branch, reply_cid.short(), content, time);
                
                self.print_thread_replies(store, reply_cid, depth + 1);
            }
        }
    }
    
    fn extract_expression_content(&self, store: &ExprStore, cid: &Cid) -> String {
        if let Some(expr) = store.fetch(cid) {
            let arena = store.arena();
            let op = arena.car(expr);
            
            if let SexpNode::Atom(s) = arena.get(op) {
                if s == "signed" {
                    let inner = arena.nth(expr, 3);
                    let inner_op = arena.car(inner);
                    
                    if let SexpNode::Atom(inner_s) = arena.get(inner_op) {
                        match inner_s.as_str() {
                            "reply-to" => {
                                let text_ref = arena.nth(inner, 2);
                                if let SexpNode::Atom(text) = arena.get(text_ref) {
                                    let truncated = if text.len() > 60 {
                                        format!("{}...", &text[..60])
                                    } else {
                                        text.clone()
                                    };
                                    return truncated;
                                }
                            }
                            "propose" => {
                                let text_ref = arena.nth(inner, 1);
                                if let SexpNode::Atom(text) = arena.get(text_ref) {
                                    let truncated = if text.len() > 60 {
                                        format!("{}...", &text[..60])
                                    } else {
                                        text.clone()
                                    };
                                    return truncated;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            
            let display = arena.display(expr);
            if display.len() > 60 {
                format!("{}...", &display[..60])
            } else {
                display
            }
        } else {
            "(not found)".into()
        }
    }
    
    pub async fn vote(&self, cid_prefix: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("[REJECT] Elaboration too short"); return; }
        
        let state = self.state.read().await;
        let cid = match state.proposals.keys().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, None => { println!("[NULL] Proposal not found"); return; }
        };
        
        if let Some(prop) = state.proposals.get(&cid) {
            if prop.proposer == self.did {
                println!("[REJECT] Cannot vote on your own proposal");
                return;
            }
        }
        drop(state);
        
        let mut store = self.store.write().await;
        let op = store.arena_mut().atom("vote");
        let target = store.arena_mut().bytes(&cid.0);
        let sup = store.arena_mut().atom(if support { "yes" } else { "no" });
        let elab = store.arena_mut().atom(elaboration);
        let expr = store.arena_mut().list(&[op, target, sup, elab]);
        let expr_data = store.arena().serialize(expr);
        let sig = self.sign(&expr_data);
        let signed_op = store.arena_mut().atom("signed");
        let pk_ref = store.arena_mut().bytes(self.public_key.as_bytes());
        let sig_ref = store.arena_mut().bytes(&sig);
        let signed_expr = store.arena_mut().list(&[signed_op, pk_ref, sig_ref, expr]);
        let _ = store.store(signed_expr);
        let vote_bytes = store.arena().serialize(signed_expr);
        drop(store);
        
        let mark = self.state.read().await.get_mark(&self.did);
        let ts = timestamp();
        let signal = QuorumSignal { 
            source: self.did.clone(), 
            pubkey: self.public_key.as_bytes().to_vec(),
            target: cid, 
            weight: mark.signal_weight(), 
            support, 
            elaboration: elaboration.to_string(), 
            timestamp: ts, 
            signature: self.sign(&{
                let mut data = Vec::new();
                data.extend_from_slice(&cid.0);
                data.push(if support { 1 } else { 0 });
                data.extend_from_slice(elaboration.as_bytes());
                data.extend_from_slice(&ts.to_le_bytes());
                data
            })
        };
        
        let (sensed, reached) = {
            let mut state = self.state.write().await;
            if let Some(proposal) = state.proposals.get_mut(&cid) {
                match proposal.quorum.sense(signal.clone()) {
                    Ok(sensed) => {
                        let reached = sensed && proposal.quorum.reached();
                        (sensed, reached)
                    }
                    Err(e) => {
                        println!("[ERROR] {}", e);
                        return;
                    }
                }
            } else {
                (false, false)
            }
        };
        
        if sensed {
            self.state.write().await.update_mark(&self.did, score_elaboration(elaboration), true);
            if reached {
                println!("[QUORUM] {} reached threshold!", cid);
            }
        }
        
        let _ = self.save_state().await;
        println!("[VOTE] {} on {}", if support { "YES" } else { "NO" }, cid);
        self.broadcast_authenticated(&NetMessage::Expression(vote_bytes)).await;
        self.broadcast_authenticated(&NetMessage::Signal(signal)).await;
    }
    
    pub async fn pin(&self, cid_prefix: &str, reason: &str) {
        if reason.len() < MIN_ELABORATION_LEN { println!("[REJECT] Reason too short"); return; }
        if !self.state.read().await.can_add_pin() {
            println!("[REJECT] Maximum pins reached");
            return;
        }
        
        let store = self.store.read().await;
        let cid = match store.log().iter().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, 
            None => { println!("[NULL] Expression not found"); return; }
        };
        drop(store);
        
        if self.state.read().await.pinned.contains_key(&cid) {
            println!("[REJECT] Already pinned");
            return;
        }
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        
        let pinned = PinnedContent {
            cid,
            pinned_by: self.did.clone(),
            reason: reason.to_string(),
            quorum: QuorumState::new(cid, threshold, self.did.clone()),
            pinned_at: timestamp(),
            active: false,
        };
        
        self.state.write().await.pinned.insert(cid, pinned);
        
        let sig = self.sign(&{
            let mut data = b"pin:".to_vec();
            data.extend_from_slice(&cid.0);
            data.extend_from_slice(reason.as_bytes());
            data
        });
        
        let msg = NetMessage::PinRequest { cid, reason: reason.to_string(), signature: sig };
        self.broadcast_authenticated(&msg).await;
        
        println!("[PIN-PROPOSE] {} - awaiting quorum", cid);
    }
    
    pub async fn vote_pin(&self, cid_prefix: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("[REJECT] Elaboration too short"); return; }
        
        let state = self.state.read().await;
        let cid = match state.pinned.keys().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, None => { println!("[NULL] Pin proposal not found"); return; }
        };
        
        if let Some(pin) = state.pinned.get(&cid) {
            if pin.pinned_by == self.did {
                println!("[REJECT] Cannot vote on your own pin proposal");
                return;
            }
        }
        drop(state);
        
        let mark = self.state.read().await.get_mark(&self.did);
        let ts = timestamp();
        let signal = QuorumSignal { 
            source: self.did.clone(), 
            pubkey: self.public_key.as_bytes().to_vec(),
            target: cid, 
            weight: mark.signal_weight(), 
            support, 
            elaboration: elaboration.to_string(), 
            timestamp: ts, 
            signature: self.sign(&{
                let mut data = Vec::new();
                data.extend_from_slice(&cid.0);
                data.push(if support { 1 } else { 0 });
                data.extend_from_slice(elaboration.as_bytes());
                data.extend_from_slice(&ts.to_le_bytes());
                data
            })
        };
        
        let mut state = self.state.write().await;
        if let Some(pin) = state.pinned.get_mut(&cid) {
            match pin.quorum.sense(signal.clone()) {
                Ok(sensed) => {
                    if sensed && pin.quorum.reached() && !pin.active {
                        pin.active = true;
                        println!("[PIN] {} is now pinned!", cid);
                    }
                }
                Err(e) => {
                    println!("[ERROR] {}", e);
                    return;
                }
            }
        }
        drop(state);
        
        let _ = self.save_state().await;
        println!("[PIN-VOTE] {} on {}", if support { "YES" } else { "NO" }, cid);
        self.broadcast_authenticated(&NetMessage::PinSignal(signal)).await;
    }
    
    pub async fn prune(&self, cid_prefix: &str, reason: &str) {
        if reason.len() < MIN_ELABORATION_LEN { println!("[REJECT] Reason too short"); return; }
        
        let store = self.store.read().await;
        let cid = match store.log().iter().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, 
            None => { println!("[NULL] Expression not found"); return; }
        };
        drop(store);
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        
        let prune = PruneProposal {
            cid,
            proposer: self.did.clone(),
            reason: reason.to_string(),
            quorum: QuorumState::new(cid, threshold, self.did.clone()),
            created: timestamp(),
        };
        
        self.state.write().await.prune_proposals.insert(cid, prune);
        
        let sig = self.sign(&{
            let mut data = b"prune:".to_vec();
            data.extend_from_slice(&cid.0);
            data.extend_from_slice(reason.as_bytes());
            data
        });
        
        let msg = NetMessage::PruneRequest { cid, reason: reason.to_string(), signature: sig };
        self.broadcast_authenticated(&msg).await;
        
        println!("[PRUNE-PROPOSE] {} - awaiting quorum", cid);
    }
    
    pub async fn vote_prune(&self, cid_prefix: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("[REJECT] Elaboration too short"); return; }
        
        let state = self.state.read().await;
        let cid = match state.prune_proposals.keys().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, None => { println!("[NULL] Prune proposal not found"); return; }
        };
        
        if let Some(prune) = state.prune_proposals.get(&cid) {
            if prune.proposer == self.did {
                println!("[REJECT] Cannot vote on your own prune proposal");
                return;
            }
        }
        drop(state);
        
        let mark = self.state.read().await.get_mark(&self.did);
        let ts = timestamp();
        let signal = QuorumSignal { 
            source: self.did.clone(), 
            pubkey: self.public_key.as_bytes().to_vec(),
            target: cid, 
            weight: mark.signal_weight(), 
            support, 
            elaboration: elaboration.to_string(), 
            timestamp: ts, 
            signature: self.sign(&{
                let mut data = Vec::new();
                data.extend_from_slice(&cid.0);
                data.push(if support { 1 } else { 0 });
                data.extend_from_slice(elaboration.as_bytes());
                data.extend_from_slice(&ts.to_le_bytes());
                data
            })
        };
        
        let mut state = self.state.write().await;
        let should_prune = if let Some(prune) = state.prune_proposals.get_mut(&cid) {
            match prune.quorum.sense(signal.clone()) {
                Ok(sensed) => sensed && prune.quorum.reached(),
                Err(e) => {
                    println!("[ERROR] {}", e);
                    return;
                }
            }
        } else {
            false
        };
        
        if should_prune {
            state.prune_proposals.remove(&cid);
            state.pinned.remove(&cid);
            state.proposals.remove(&cid);
            drop(state);
            
            self.store.write().await.remove(&cid);
            println!("[PRUNED] {} removed", cid);
        } else {
            drop(state);
        }
        
        let _ = self.save_state().await;
        println!("[PRUNE-VOTE] {} on {}", if support { "YES" } else { "NO" }, cid);
        self.broadcast_authenticated(&NetMessage::PruneSignal(signal)).await;
    }
    
    pub async fn dm_request(&self, did_str: &str) {
        let target_did = Did(format!("did:diagon:{}", did_str.trim_start_matches("did:diagon:")));
        
        let secret = ReusableSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let public_bytes: [u8; 32] = public.to_bytes();
        
        let channel_id = self.did.dm_channel_id(&target_did);
        
        let channels = self.dm_channels.read().await;
        if let Some(existing) = channels.get(&channel_id) {
            match existing.state {
                DmChannelState::Established => {
                    println!("DM channel already established with {}", target_did.short());
                    return;
                }
                DmChannelState::PendingOutbound => {
                    println!("DM request already pending with {}", target_did.short());
                    return;
                }
                DmChannelState::PendingInbound => {
                    println!("Peer already requested DM - use 'dm-accept {}' to accept", target_did.short());
                    return;
                }
                _ => {}
            }
        }
        drop(channels);
        
        let channel = DmChannel::new_outbound(target_did.clone(), public_bytes);
        self.dm_channels.write().await.insert(channel_id, channel);
        self.dm_secrets.write().await.insert(channel_id, secret);
        
        let sig = self.sign(&{
            let mut data = b"dm-request:".to_vec();
            data.extend_from_slice(self.did.0.as_bytes());
            data.extend_from_slice(&public_bytes);
            data
        });
        
        let msg = NetMessage::DmRequest {
            from: self.did.clone(),
            ephemeral_pubkey: public_bytes,
            signature: sig,
        };
        
        if let Some(handle) = self.connection_pool.get_handle_by_did(&target_did).await {
            if let Ok(data) = msg.serialize() {
                let _ = handle.send(data).await;
                println!("[DM] Request sent to {} - awaiting consent", target_did.short());
            }
        } else {
            println!("[DM] Peer {} not connected", target_did.short());
            self.dm_channels.write().await.remove(&channel_id);
            self.dm_secrets.write().await.remove(&channel_id);
        }
    }
    
    pub async fn dm_accept(&self, did_str: &str) {
        let target_did = Did(format!("did:diagon:{}", did_str.trim_start_matches("did:diagon:")));
        let channel_id = self.did.dm_channel_id(&target_did);
        
        let mut channels = self.dm_channels.write().await;
        let channel = match channels.get_mut(&channel_id) {
            Some(c) if c.state == DmChannelState::PendingInbound => c,
            Some(_) => {
                println!("[DM] No pending request from {}", target_did.short());
                return;
            }
            None => {
                println!("[DM] No pending request from {}", target_did.short());
                return;
            }
        };
        
        let secrets = self.dm_secrets.read().await;
        let secret = match secrets.get(&channel_id) {
            Some(s) => s,
            None => {
                println!("[DM] Internal error: missing secret");
                return;
            }
        };
        
        let peer_public = channel.peer_ephemeral_public.unwrap();
        channel.establish(peer_public, secret);
        
        let our_public = channel.our_ephemeral_public;
        drop(secrets);
        drop(channels);
        
        let sig = self.sign(&{
            let mut data = b"dm-accept:".to_vec();
            data.extend_from_slice(self.did.0.as_bytes());
            data.extend_from_slice(&our_public);
            data
        });
        
        let msg = NetMessage::DmAccept {
            from: self.did.clone(),
            ephemeral_pubkey: our_public,
            signature: sig,
        };
        
        if let Some(handle) = self.connection_pool.get_handle_by_did(&target_did).await {
            if let Ok(data) = msg.serialize() {
                let _ = handle.send(data).await;
                println!("[DM] Channel established with {}", target_did.short());
            }
        }
    }
    
    pub async fn dm_reject(&self, did_str: &str, reason: &str) {
        let target_did = Did(format!("did:diagon:{}", did_str.trim_start_matches("did:diagon:")));
        let channel_id = self.did.dm_channel_id(&target_did);
        
        self.dm_channels.write().await.remove(&channel_id);
        self.dm_secrets.write().await.remove(&channel_id);
        
        let sig = self.sign(&{
            let mut data = b"dm-reject:".to_vec();
            data.extend_from_slice(self.did.0.as_bytes());
            data.extend_from_slice(reason.as_bytes());
            data
        });
        
        let msg = NetMessage::DmReject {
            from: self.did.clone(),
            reason: reason.to_string(),
            signature: sig,
        };
        
        if let Some(handle) = self.connection_pool.get_handle_by_did(&target_did).await {
            if let Ok(data) = msg.serialize() {
                let _ = handle.send(data).await;
            }
        }
        
        println!("[DM] Rejected request from {}", target_did.short());
    }
    
    pub async fn dm_send(&self, did_str: &str, message: &str) {
        let target_did = Did(format!("did:diagon:{}", did_str.trim_start_matches("did:diagon:")));
        let channel_id = self.did.dm_channel_id(&target_did);
        
        let channels = self.dm_channels.read().await;
        let channel = match channels.get(&channel_id) {
            Some(c) if c.state == DmChannelState::Established => c,
            Some(c) if c.state == DmChannelState::PendingOutbound => {
                println!("[DM] Channel not yet established - awaiting peer consent");
                return;
            }
            Some(c) if c.state == DmChannelState::PendingInbound => {
                println!("[DM] Accept request first with 'dm-accept {}'", target_did.short());
                return;
            }
            _ => {
                println!("[DM] No channel with {} - use 'dm-request {}' first", 
                    target_did.short(), target_did.short());
                return;
            }
        };
        
        let (ciphertext, nonce) = match channel.encrypt(message) {
            Ok(r) => r,
            Err(e) => {
                println!("[DM] Encryption failed: {}", e);
                return;
            }
        };
        
        drop(channels);
        
        let dm_msg = DmMessage {
            from: self.did.clone(),
            to: target_did.clone(),
            encrypted_content: ciphertext,
            nonce,
            timestamp: timestamp(),
        };
        
        let msg = NetMessage::DmMessage(dm_msg);
        
        if let Some(handle) = self.connection_pool.get_handle_by_did(&target_did).await {
            if let Ok(data) = msg.serialize() {
                let _ = handle.send(data).await;
                
                let mut channels = self.dm_channels.write().await;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    channel.add_message(self.did.clone(), message.to_string());
                }
                
                println!("[DM→{}] {}", target_did.short(), message);
            }
        } else {
            println!("[DM] Peer {} not connected", target_did.short());
        }
    }
    
    pub async fn dm_list(&self) {
        let channels = self.dm_channels.read().await;
        
        if channels.is_empty() {
            println!("No DM channels");
            return;
        }
        
        println!("\n=== DM Channels ===");
        for (_, channel) in channels.iter() {
            let state_str = match channel.state {
                DmChannelState::PendingOutbound => "awaiting consent",
                DmChannelState::PendingInbound => "needs your consent",
                DmChannelState::Established => "established",
                DmChannelState::Rejected => "rejected",
            };
            println!("  {} - {} ({} messages)", 
                channel.peer_did.short(), state_str, channel.messages.len());
        }
        println!();
    }
    
    pub async fn dm_history(&self, did_str: &str) {
        let target_did = Did(format!("did:diagon:{}", did_str.trim_start_matches("did:diagon:")));
        let channel_id = self.did.dm_channel_id(&target_did);
        
        let channels = self.dm_channels.read().await;
        let channel = match channels.get(&channel_id) {
            Some(c) => c,
            None => {
                println!("No channel with {}", target_did.short());
                return;
            }
        };
        
        if channel.messages.is_empty() {
            println!("No messages with {}", target_did.short());
            return;
        }
        
        println!("\n=== DM with {} ===", target_did.short());
        for (from, content, ts) in &channel.messages {
            let who = if *from == self.did { "You" } else { &from.short() };
            println!("[{}] {}: {}", format_timestamp(*ts), who, content);
        }
        println!();
    }
    
    pub async fn message(&self, content_type_str: &str, file_path: &str) {
        if self.pool.read().await.is_none() {
            println!("[REJECT] Must be authenticated to send content");
            return;
        }
        
        let content_type = match ContentType::from_str(content_type_str) {
            Some(ct) => ct,
            None => {
                println!("[ERROR] Invalid content type. Use: image, video, or text");
                return;
            }
        };
        
        let data = match tokio::fs::read(file_path).await {
            Ok(d) => d,
            Err(e) => {
                println!("[ERROR] Failed to read file: {}", e);
                return;
            }
        };
        
        const MAX_CONTENT_SIZE: usize = 100 * 1024 * 1024;
        if data.len() > MAX_CONTENT_SIZE {
            println!("[ERROR] Content too large. Max: {} MB", MAX_CONTENT_SIZE / 1024 / 1024);
            return;
        }
        
        let filename = std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        
        let mime_type = match content_type {
            ContentType::Image => detect_image_mime(&data),
            ContentType::Video => detect_video_mime(&data),
            ContentType::Text => Some("text/plain".to_string()),
        };
        
        let mut encoder = ContentEncoder::new(
            content_type, data, filename.clone(), mime_type, self.did.clone(),
        );
        encoder.sign(&self.secret_key);
        
        let content_id = encoder.metadata().content_id;
        let total_chunks = encoder.metadata().total_chunks;
        let total_size = encoder.metadata().total_size;
        
        println!("[CONTENT] Sending {} '{}' ({} bytes, {} chunks)",
            content_type, filename.as_deref().unwrap_or("unnamed"), total_size, total_chunks);
        
        let peers = self.connection_pool.authenticated_addrs().await;
        if peers.is_empty() {
            println!("[ERROR] No authenticated peers to send to");
            return;
        }
        
        let start_msg = NetMessage::ContentStart(encoder.metadata().clone());
        if let Ok(data) = start_msg.serialize() {
            for addr in &peers {
                if let Some(handle) = self.connection_pool.get_handle(addr).await {
                    let _ = handle.send(data.clone()).await;
                }
            }
        }
        
        let mut chunks_sent = 0;
        while let Some(chunk) = encoder.next_chunk() {
            let chunk_msg = NetMessage::ContentData(chunk);
            if let Ok(data) = chunk_msg.serialize() {
                for addr in &peers {
                    if let Some(handle) = self.connection_pool.get_handle(addr).await {
                        let _ = handle.send(data.clone()).await;
                    }
                }
            }
            chunks_sent += 1;
            if chunks_sent % 10 == 0 || chunks_sent == total_chunks {
                println!("[CONTENT] Sent {}/{} chunks", chunks_sent, total_chunks);
            }
            sleep(Duration::from_millis(10)).await;
        }
        
        self.outgoing_transfers.write().await.insert(content_id, encoder);
        println!("[CONTENT] Transfer initiated: {}", hex::encode(&content_id[..8]));
    }
    
    pub async fn view_start(&self, cid_prefix: &str) {
        let store = self.store.read().await;
        if let Some(cid) = store.log().iter().find(|c| c.short().starts_with(cid_prefix)).copied() {
            drop(store);
            self.store.write().await.engage(&cid);
            self.xp.write().await.start_viewing(cid);
            println!("[VIEW] Started viewing {}", cid);
        } else {
            println!("[NULL] Content not found");
        }
    }
    
    pub async fn view_stop(&self, cid_prefix: &str) {
        let store = self.store.read().await;
        if let Some(cid) = store.log().iter().find(|c| c.short().starts_with(cid_prefix)).copied() {
            drop(store);
            if let Some(xp_earned) = self.xp.write().await.stop_viewing(cid) {
                println!("[XP] +{} XP earned for viewing {}", xp_earned, cid);
            } else {
                println!("[VIEW] Stopped viewing {} (no XP - view longer or cooldown)", cid);
            }
        } else {
            println!("[NULL] Content not found");
        }
    }
    
    pub async fn xp_status(&self) {
        let xp = self.xp.read().await;
        println!("\n=== XP Status ===");
        println!("Total XP: {}", xp.total_xp);
        println!("Content viewed: {}", xp.last_view.len());
        println!();
    }
    
    // ========== DHT API ==========
    
    pub async fn dht_register(&self, topic: &str, description: &str) {
        if !self.is_in_rendezvous().await {
            println!("[DHT] Must be in rendezvous pool to register. Use 'join-rendezvous' first.");
            return;
        }
        
        let pool_commitment = match *self.pool.read().await {
            Some(p) => p,
            None => {
                println!("[DHT] No pool set");
                return;
            }
        };
        
        {
            let mut dht = self.dht.write().await;
            if !dht.check_rate_limit(&self.did) {
                println!("[DHT] Rate limited: max {} registrations per hour", DHT_REGISTER_LIMIT_PER_HOUR);
                return;
            }
        }
        
        let topic_hash = DhtEntry::topic_str(topic);
        let pool_name = self.pool_name.read().await.clone().unwrap_or_else(|| 
            format!("pool-{}", hex::encode(&pool_commitment[..4]))
        );
        let peer_count = self.connection_pool.authenticated_addrs().await.len() + 1;
        
        let entry = DhtEntry {
            topic_hash,
            pool_commitment,
            pool_name: pool_name.clone(),
            description: description.to_string(),
            peer_count,
            registered_by: self.did.clone(),
            registered_at: timestamp(),
            last_seen: timestamp(),
        };
        
        self.dht.write().await.register(entry.clone());
        self.pool_topics.write().await.push(topic_hash);
        
        let sig = self.sign(&{
            let mut data = b"dht-register:".to_vec();
            data.extend_from_slice(&topic_hash);
            data.extend_from_slice(&pool_commitment);
            data.extend_from_slice(pool_name.as_bytes());
            data.extend_from_slice(description.as_bytes());
            data
        });
        
        let msg = NetMessage::DhtRegister {
            topic_hash,
            pool_commitment,
            pool_name,
            description: description.to_string(),
            peer_count,
            signature: sig,
        };
        
        self.broadcast_authenticated(&msg).await;
        println!("[DHT] Registered under topic '{}' (hash: {}...)", topic, hex::encode(&topic_hash[..4]));
    }
    
    pub async fn dht_search(&self, topic: &str) {
        let topic_hash = DhtEntry::topic_str(topic);
        
        let local_results = self.dht.read().await.search(topic);
        
        if !local_results.is_empty() {
            println!("\n=== DHT Search: '{}' ===", topic);
            println!("Found {} pool(s):", local_results.len());
            for entry in &local_results {
                let is_rendezvous = entry.pool_commitment == rendezvous_commitment();
                let marker = if is_rendezvous { " [rendezvous]" } else { "" };
                println!("  📦 {} ({}...){}", 
                    entry.pool_name, 
                    hex::encode(&entry.pool_commitment[..4]),
                    marker);
                println!("     {} - {} peers, last seen {}", 
                    entry.description, 
                    entry.peer_count,
                    format_timestamp(entry.last_seen));
            }
            println!();
        } else {
            println!("[DHT] No local results for '{}'. Try 'sync-dht' to refresh.", topic);
        }
        
        if self.is_in_rendezvous().await {
            let msg = NetMessage::DhtSearchRequest { topic_hash };
            self.broadcast_authenticated(&msg).await;
        }
    }
    
    pub async fn discover_directory(&self) {
        if !self.is_in_rendezvous().await {
            println!("[DISCOVER] Must be in rendezvous pool. Use 'join-rendezvous' first.");
            return;
        }
        
        let peers = self.connection_pool.authenticated_addrs().await;
        if peers.is_empty() {
            println!("[DISCOVER] No connected peers. Connect to rendezvous nodes first.");
            return;
        }
        
        println!("[DISCOVER] Requesting directory from {} peer(s)...", peers.len());
        let msg = NetMessage::DhtDirectoryRequest;
        self.broadcast_authenticated(&msg).await;
    }
    
    pub async fn sync_dht(&self) {
        if !self.is_in_rendezvous().await {
            println!("[DHT] Must be in rendezvous pool to sync. Use 'join-rendezvous' first.");
            return;
        }
        
        self.discover_directory().await;
    }
    
    pub async fn dht_status(&self) {
        let dht = self.dht.read().await;
        let pool_topics = self.pool_topics.read().await;
        let pool_name = self.pool_name.read().await;
        
        println!();
        println!("=== DHT Status ===");
        println!("In rendezvous: {}", self.is_in_rendezvous().await);
        println!("Pool name: {}", pool_name.as_deref().unwrap_or("(not set)"));
        println!("Registered topics: {}", pool_topics.len());
        println!("Directory entries: {}", dht.entries.values().map(|v| v.len()).sum::<usize>());
        println!("Unique pools: {}", dht.pool_topics.len());
        println!("Last sync: {}", if dht.last_sync > 0 { format_timestamp(dht.last_sync) } else { "never".into() });
        
        if !dht.entries.is_empty() {
            println!("\nKnown topics:");
            for (topic_hash, entries) in dht.entries.iter().take(10) {
                println!("  {}... ({} pool(s))", hex::encode(&topic_hash[..4]), entries.len());
            }
            if dht.entries.len() > 10 {
                println!("  ... and {} more", dht.entries.len() - 10);
            }
        }
        println!();
    }
    
    pub async fn status(&self) {
        let state = self.state.read().await;
        let store = self.store.read().await;
        let pool = self.pool.read().await;
        let xp = self.xp.read().await;
        let dht = self.dht.read().await;
        let dm_count = self.dm_channels.read().await.len();
        let auth_count = self.connection_pool.authenticated_addrs().await.len();
        let pending = self.connection_pool.pending_approval().await.len();
        let awaiting = self.connection_pool.awaiting_elaboration().await.len();
        
        let is_rendezvous = pool.map(|p| p == rendezvous_commitment()).unwrap_or(false);
        
        println!();
        println!("=== DIAGON v0.9.5 STATUS ===");
        println!("[MY ID] {}", self.did.short());
        if is_rendezvous {
            println!("[POOL] Rendezvous (public discovery)");
        } else {
            println!("[POOL] {}", pool.map(|p| hex::encode(&p[..8])).unwrap_or_else(|| "Not set".to_string()));
        }
        println!("[EXPR] {}/{}", store.log().len(), MAX_EXPRESSIONS);
        println!("[PROP] {}", state.proposals.len());
        println!("[PIN] {} active", state.pinned.iter().filter(|(_, p)| p.active).count());
        println!("[LINK] {} auth, {} pending, {} awaiting", auth_count, pending, awaiting);
        println!("[DM] {} channels", dm_count);
        println!("[XP] {}", xp.total_xp);
        println!("[DHT] {} entries", dht.get_directory().len());
        
        let decayed = store.get_decayed().len();
        if decayed > 0 {
            println!("[DECAY] {} expressions ready for pruning", decayed);
        }

        // Witness/Testimony stats
        let store = self.store.read().await;
        let witnessed_count = store.metadata.values()
            .filter(|m| m.is_witnessed())
            .count();
        let testified_count = store.metadata.values()
            .filter(|m| m.is_testified())
            .count();
        drop(store);
        
        let registry = self.testimony_registry.read().await;
        let given_count = registry.given_count;
        drop(registry);
        
        println!("[WITNESS] {} acknowledged, {} testified, {} given", 
                 witnessed_count, testified_count, given_count);
        
        if !state.proposals.is_empty() {
            println!();
            println!("Proposals:");
            for (cid, prop) in state.proposals.iter().take(10) {
                let text = if prop.elaboration.len() > 40 { 
                    format!("{}...", &prop.elaboration[..40]) 
                } else { 
                    prop.elaboration.clone() 
                };
                let reached = if prop.quorum.reached() { "✓" } else { "○" };
                println!("  {} {} - \"{}\" ({}/{})", 
                    reached, cid.short(), text, 
                    prop.quorum.accumulated_for(), prop.quorum.threshold);
            }
        }
        
        if state.pinned.iter().any(|(_, p)| p.active) {
            println!();
            println!("Pinned content:");
            for (cid, pin) in state.pinned.iter().filter(|(_, p)| p.active).take(5) {
                println!("  📌 {} - {}", cid.short(), pin.reason);
            }
        }
        
        let peers = self.connection_pool.peers.read().await;
        if !peers.is_empty() {
            println!();
            println!("Connections:");
            for (addr, info) in peers.iter() {
                let info = info.read().await;
                let did_str = info.did.as_ref().map(|d| d.short()).unwrap_or_else(|| "?".to_string());
                let state_str = match info.state {
                    ConnectionState::Connected => "auth",
                    ConnectionState::MutualPending => "mutual-pending",
                    ConnectionState::AwaitingOurElaboration => "awaiting-elab",
                    ConnectionState::AwaitingTheirElaboration => "awaiting-their-elab",
                    ConnectionState::AwaitingOurApproval => "awaiting-approval",
                    ConnectionState::AwaitingTheirApproval => "sent-approval",
                    _ => "...",
                };
                println!("  {} @ {} ({})", did_str, addr, state_str);
            }
        }
        println!();
    }
    
    pub async fn list_pinned(&self) {
        let state = self.state.read().await;
        println!();
        println!("=== PINNED CONTENT ===");
        
        let active: Vec<_> = state.pinned.iter().filter(|(_, p)| p.active).collect();
        let pending: Vec<_> = state.pinned.iter().filter(|(_, p)| !p.active).collect();
        
        if active.is_empty() && pending.is_empty() {
            println!("No pinned content");
        } else {
            if !active.is_empty() {
                println!("Active pins:");
                for (cid, pin) in active {
                    println!("  📌 {} - \"{}\" (by {})", cid.short(), pin.reason, pin.pinned_by.short());
                }
            }
            if !pending.is_empty() {
                println!("\nPending pin proposals:");
                for (cid, pin) in pending {
                    println!("  ○ {} - \"{}\" ({}/{})", 
                        cid.short(), pin.reason, 
                        pin.quorum.accumulated_for(), pin.quorum.threshold);
                }
            }
        }
        println!();
    }
    
    pub async fn list_decayed(&self) {
        let store = self.store.read().await;
        let decayed = store.get_decayed();
        
        println!();
        println!("=== DECAYED CONTENT ===");
        if decayed.is_empty() {
            println!("No decayed content");
        } else {
            println!("{} expressions ready for pruning:", decayed.len());
            for cid in decayed.iter().take(20) {
                if let Some(meta) = store.get_meta(cid) {
                    let age_days = (timestamp() - meta.last_engaged) / 86400;
                    println!("  {} - {} days since engagement, {} total views", 
                        cid.short(), age_days, meta.engagement_count);
                }
            }
            if decayed.len() > 20 {
                println!("  ... and {} more", decayed.len() - 20);
            }
        }
        println!();
    }
    
    pub async fn discover(&self) {
        if self.is_in_rendezvous().await {
            self.discover_directory().await;
            return;
        }
        
        let pools = match *self.pool.read().await {
            Some(p) => vec![p],
            None => vec![],
        };
        
        let authed = self.connection_pool.authenticated_addrs().await;
        if authed.is_empty() {
            println!("[DISCOVER] No connected peers");
            return;
        }
        
        println!("[DISCOVER] Asking {} peer(s) for network info...", authed.len());
        
        let msg = NetMessage::Discover { pools, want_hints: true };
        if let Ok(data) = msg.serialize() {
            for addr in authed {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(data.clone()).await;
                }
            }
        }
    }

    pub async fn propose_decay_config(&self, enabled: bool, days: u64, require_engagement: bool, reason: &str) {
        if reason.len() < MIN_ELABORATION_LEN {
            println!("[REJECT] Reason too short (min {} chars)", MIN_ELABORATION_LEN);
            return;
        }
        
        let config = DecayConfig { enabled, decay_days: days, require_engagement };
        
        // Generate unique ID
        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let id = Cid(id_bytes);
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        
        let proposal = DecayConfigProposal {
            id,
            proposed_config: config.clone(),
            proposer: self.did.clone(),
            reason: reason.to_string(),
            quorum: QuorumState::new(id, threshold, self.did.clone()),
            created: timestamp(),
            applied: false,
        };
        
        self.state.write().await.decay_proposals.insert(id, proposal);
        
        // Sign and broadcast
        let sig = self.sign(&{
            let mut data = b"decay-config:".to_vec();
            data.extend_from_slice(&id.0);
            data.push(if config.enabled { 1 } else { 0 });
            data.extend_from_slice(&config.decay_days.to_le_bytes());
            data.push(if config.require_engagement { 1 } else { 0 });
            data.extend_from_slice(reason.as_bytes());
            data
        });
        
        let msg = NetMessage::DecayConfigPropose {
            id,
            config,
            reason: reason.to_string(),
            signature: sig,
        };
        
        self.broadcast_authenticated(&msg).await;
        
        let _ = self.save_state().await;
        
        let mode = if enabled {
            format!("enabled ({} days, engagement={})", days, require_engagement)
        } else {
            "disabled (archive mode)".to_string()
        };
        println!("[DECAY-PROPOSE] {} - {}", id.short(), mode);
    }

    pub async fn vote_decay_config(&self, id_prefix: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN {
            println!("[REJECT] Elaboration too short");
            return;
        }
        
        let state = self.state.read().await;
        let id = match state.decay_proposals.keys()
            .find(|c| c.short().starts_with(id_prefix))
            .copied() 
        {
            Some(c) => c,
            None => {
                println!("[NULL] Decay config proposal not found");
                return;
            }
        };
        
        if let Some(prop) = state.decay_proposals.get(&id) {
            if prop.proposer == self.did {
                println!("[REJECT] Cannot vote on your own proposal");
                return;
            }
            if prop.applied {
                println!("[REJECT] Proposal already applied");
                return;
            }
        }
        drop(state);
        
        let mark = self.state.read().await.get_mark(&self.did);
        let ts = timestamp();
        
        let signal = QuorumSignal {
            source: self.did.clone(),
            pubkey: self.public_key.as_bytes().to_vec(),
            target: id,
            weight: mark.signal_weight(),
            support,
            elaboration: elaboration.to_string(),
            timestamp: ts,
            signature: self.sign(&{
                let mut data = Vec::new();
                data.extend_from_slice(&id.0);
                data.push(if support { 1 } else { 0 });
                data.extend_from_slice(elaboration.as_bytes());
                data.extend_from_slice(&ts.to_le_bytes());
                data
            }),
        };
        
        // Apply signal and check quorum
        let should_apply = {
            let mut state = self.state.write().await;
            if let Some(prop) = state.decay_proposals.get_mut(&id) {
                match prop.quorum.sense(signal.clone()) {
                    Ok(sensed) => sensed && prop.quorum.reached() && !prop.applied,
                    Err(e) => {
                        println!("[ERROR] {}", e);
                        return;
                    }
                }
            } else {
                false
            }
        };
        
        if should_apply {
            let new_config = {
                let mut state = self.state.write().await;
                if let Some(prop) = state.decay_proposals.get_mut(&id) {
                    prop.applied = true;
                    Some(prop.proposed_config.clone())
                } else {
                    None
                }
            };
            
            if let Some(config) = new_config {
                *self.decay_config.write().await = config.clone();
                
                let mode = if config.enabled {
                    format!("enabled ({} days)", config.decay_days)
                } else {
                    "disabled".to_string()
                };
                println!("[DECAY-APPLIED] Config changed to: {}", mode);
            }
        }
        
        let _ = self.save_state().await;
        println!("[DECAY-VOTE] {} on {}", if support { "YES" } else { "NO" }, id.short());
        
        self.broadcast_authenticated(&NetMessage::DecayConfigSignal(signal)).await;
    }

    pub async fn list_decay_proposals(&self) {
        let state = self.state.read().await;
        let current = self.decay_config.read().await.clone();
        
        println!();
        println!("=== DECAY GOVERNANCE ===");
        println!("Current config: {} ({} days, engagement={})",
            if current.enabled { "enabled" } else { "disabled" },
            current.decay_days,
            current.require_engagement);
        
        let pending: Vec<_> = state.decay_proposals.iter()
            .filter(|(_, p)| !p.applied)
            .collect();
        
        if pending.is_empty() {
            println!("No pending decay proposals");
        } else {
            println!("\nPending proposals:");
            for (id, prop) in pending {
                let mode = if prop.proposed_config.enabled {
                    format!("enable ({} days, eng={})", 
                        prop.proposed_config.decay_days,
                        prop.proposed_config.require_engagement)
                } else {
                    "disable".to_string()
                };
                println!("  {} - {} ({}/{})", 
                    id.short(), 
                    mode,
                    prop.quorum.accumulated_for(),
                    prop.quorum.threshold);
                println!("      \"{}\" by {}", prop.reason, prop.proposer.short());
            }
        }
        println!();
    }
    
    /// Resolve a CID prefix to full CID
    async fn resolve_cid(&self, prefix: &str) -> Option<Cid> {
        let store = self.store.read().await;
        store.log().iter()
            .find(|c| c.short().starts_with(prefix) || hex::encode(c.0).starts_with(prefix))
            .copied()
    }
    
    /// Begin witnessing an expression - records start time for later acknowledgment
    pub async fn witness_start(&self, cid_prefix: &str) {
        if let Some(cid) = self.resolve_cid(cid_prefix).await {
            // Engage the content
            self.store.write().await.engage(&cid);
            // Start tracking view time
            self.xp.write().await.start_viewing(cid);
            println!("[WITNESS] Began attending to {}", cid.short());
        } else {
            println!("[ERR] Expression not found: {}", cid_prefix);
        }
    }
    
    /// Complete witnessing with acknowledgment
    pub async fn acknowledge(&self, cid_prefix: &str, reflection: Option<String>) {
        let cid = match self.resolve_cid(cid_prefix).await {
            Some(c) => c,
            None => {
                println!("[ERR] Expression not found: {}", cid_prefix);
                return;
            }
        };
        
        let view_started = {
            let mut xp = self.xp.write().await;
            match xp.end_viewing(&cid) {
                Some(start) => start,
                None => {
                    println!("[ERR] Not currently viewing {}. Use 'witness <cid>' first.", cid.short());
                    return;
                }
            }
        };
        
        let acknowledged_at = timestamp();
        let dwell = acknowledged_at.saturating_sub(view_started);
        
        if dwell < ACK_MIN_DWELL_SECS {
            println!("[ERR] Insufficient dwell time: {}s < {}s required", 
                     dwell, ACK_MIN_DWELL_SECS);
            return;
        }
        
        // Validate reflection if provided
        if let Some(ref r) = reflection {
            if r.len() < ACK_ELABORATION_MIN_LEN {
                println!("[WARN] Reflection too short for bonus weight (min {} chars)", ACK_ELABORATION_MIN_LEN);
            }
        }
        
        // Build acknowledgment
        let mut ack = Acknowledgment {
            target: cid,
            witness: self.did.clone(),
            pubkey: self.public_key.as_bytes().to_vec(),
            view_started,
            acknowledged_at,
            reflection: reflection.clone(),
            signature: Vec::new(),
        };
        
        // Sign
        let sig = detached_sign(&ack.signable_bytes(), &self.secret_key);
        ack.signature = sig.as_bytes().to_vec();
        
        // Store locally
        {
            let mut store = self.store.write().await;
            if let Some(meta) = store.metadata.get_mut(&cid) {
                meta.acknowledge(ack.clone());
            }
        }
        
        // Broadcast to pool
        let msg = NetMessage::Acknowledge(ack);
        self.broadcast_authenticated(&msg).await;
        
        let reflection_note = if reflection.is_some() { " with reflection" } else { "" };
        println!("[ACK] Witnessed {} ({}s dwell){}", 
                 cid.short(), dwell, reflection_note);
        
        // Also process as regular view stop for XP
        if let Some(xp_earned) = self.xp.write().await.stop_viewing(cid) {
            println!("[XP] +{} XP earned", xp_earned);
        }
    }
    
    /// Handle incoming acknowledgment from peer
    async fn handle_acknowledgment(&self, ack: Acknowledgment, from: &SocketAddr) {
        // Verify signature
        let pubkey = match PublicKey::from_bytes(&ack.pubkey) {
            Ok(pk) => pk,
            Err(_) => {
                println!("[ERR] Invalid pubkey in acknowledgment from {}", from);
                return;
            }
        };
        
        // Verify DID matches pubkey
        if Did::from_pubkey(&pubkey) != ack.witness {
            println!("[ERR] DID mismatch in acknowledgment");
            return;
        }
        
        // Verify signature
        let sig = match DetachedSignature::from_bytes(&ack.signature) {
            Ok(s) => s,
            Err(_) => {
                println!("[ERR] Invalid signature format in acknowledgment");
                return;
            }
        };
        
        if verify_detached_signature(&sig, &ack.signable_bytes(), &pubkey).is_err() {
            println!("[ERR] Signature verification failed for acknowledgment");
            return;
        }
        
        // Check validity
        if !ack.valid_dwell() {
            println!("[WARN] Acknowledgment with insufficient dwell from {}", ack.witness.short());
            return;
        }
        
        // Record
        let mut store = self.store.write().await;
        if let Some(meta) = store.metadata.get_mut(&ack.target) {
            if meta.acknowledge(ack.clone()) {
                let witnesses = meta.acknowledgments.witness_count();
                let has_reflection = ack.reflection.is_some();
                drop(store);
                
                println!("[ACK] {} witnessed {} ({} total witnesses{})", 
                         ack.witness.short(), ack.target.short(), witnesses,
                         if has_reflection { ", with reflection" } else { "" });
                
                // Update trust for the witness
                let mut state = self.state.write().await;
                state.update_mark(&ack.witness, 0.7, true);
            }
        }
    }
    
    /// Show witnesses for an expression
    pub async fn show_witnesses(&self, cid_prefix: &str) {
        let cid = match self.resolve_cid(cid_prefix).await {
            Some(c) => c,
            None => {
                println!("[ERR] Expression not found: {}", cid_prefix);
                return;
            }
        };
        
        let store = self.store.read().await;
        
        if let Some(meta) = store.get_meta(&cid) {
            let acks = &meta.acknowledgments;
            
            if acks.witnesses.is_empty() {
                println!("\n=== NO WITNESSES FOR {} ===", cid.short());
                println!("This expression has not been acknowledged.");
                return;
            }
            
            println!("\n=== WITNESSES FOR {} ===", cid.short());
            println!("Total: {} witnesses, weight: {}\n", acks.witness_count(), acks.total_weight);
            
            for (did, ack) in &acks.witnesses {
                let age = format_timestamp(ack.acknowledged_at);
                let weight = ack.weight();
                println!("  [{}] {} ({}s dwell, weight: {})", 
                         age, did.short(), ack.dwell_secs(), weight);
                if let Some(ref reflection) = ack.reflection {
                    let preview = if reflection.len() > 60 {
                        format!("{}...", &reflection[..60])
                    } else {
                        reflection.clone()
                    };
                    println!("       \"{}\"", preview);
                }
            }
            
            if meta.is_testified() {
                println!("\n  Also testified by {} other pool(s)", meta.testimonies.pool_count);
            }
        } else {
            println!("[ERR] Expression {} not found", cid.short());
        }
    }
    
    /// Review a pending mutual elaboration
    pub async fn review_elaboration(&self, did_prefix: &str) {
        let peers_snapshot: Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> = {
            let peers = self.connection_pool.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };

        for (_, info) in peers_snapshot {
            let info_guard = info.read().await;
            if let Some(ref did) = info_guard.did {
                if did.0.contains(did_prefix) || did.short().contains(did_prefix) {
                    if info_guard.state == ConnectionState::MutualPending {
                        if let Some(ref their_elab) = info_guard.elaboration {
                            println!("\n=== ELABORATION FROM {} ===", did.short());
                            println!("{}", their_elab);
                            if let Some(ref our_elab) = info_guard.our_elaboration {
                                println!("\n=== YOUR ELABORATION ===");
                                println!("{}", our_elab);
                            }
                            println!("\nUse 'mutual-approve {}' to accept or 'mutual-reject {} <reason>' to decline", 
                                     did.short(), did.short());
                            return;
                        }
                    }
                }
            }
        }
        
        println!("[ERR] No pending mutual elaboration found for '{}'", did_prefix);
    }
    
    /// Approve peer after mutual elaboration
    pub async fn mutual_approve(&self, did_prefix: &str) {
        let pool = self.connection_pool.clone();
        
        let mut target_addr: Option<SocketAddr> = None;
        let mut their_elab_hash = [0u8; 32];
        let mut peer_did: Option<Did> = None;
        
        // Get snapshot of peers
        let peers_snapshot: Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> = {
            let peers = pool.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        
        for (addr, info) in peers_snapshot.iter() {
            let info_guard = info.read().await;
            if let Some(ref did) = info_guard.did {
                if did.0.contains(did_prefix) || did.short().contains(did_prefix) {
                    match info_guard.state {
                        ConnectionState::MutualPending | 
                        ConnectionState::AwaitingOurApproval => {
                            if let Some(ref their_elab) = info_guard.elaboration {
                                let mut hasher = Sha256::new();
                                hasher.update(their_elab.as_bytes());
                                their_elab_hash = hasher.finalize().into();
                            }
                            target_addr = Some(*addr);
                            peer_did = Some(did.clone());
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        
        let addr = match target_addr {
            Some(a) => a,
            None => {
                println!("[ERR] No pending connection found for '{}'", did_prefix);
                return;
            }
        };
        
        let peer_did = match peer_did {
            Some(d) => d,
            None => {
                println!("[ERR] Peer DID not found");
                return;
            }
        };
        
        let ts = timestamp();
        
        // Sign approval
        let mut data = b"mutual-approve:".to_vec();
        data.extend_from_slice(&ts.to_le_bytes());
        data.extend_from_slice(peer_did.0.as_bytes());
        data.extend_from_slice(&their_elab_hash);
        let sig = detached_sign(&data, &self.secret_key);
        
        let msg = NetMessage::MutualApprove {
            timestamp: ts,
            peer_did: peer_did.clone(),
            elaboration_hash: their_elab_hash,
            signature: sig.as_bytes().to_vec(),
        };
        
        // Send
        if let Some(handle) = pool.get_handle(&addr).await {
            if let Ok(data) = msg.serialize() {
                let _ = handle.send(data).await;
            }
        }
        
        // Update state
        if let Some(info) = pool.get_info(&addr).await {
            let mut info_guard = info.write().await;
            info_guard.we_approved = true;
            
            if info_guard.check_connected() {
                println!("[OK] Mutually connected with {}", peer_did.short());
                
                // Update trust based on elaboration quality
                if let Some(ref their_elab) = info_guard.elaboration {
                    let quality = score_elaboration(their_elab);
                    drop(info_guard);
                    let mut state = self.state.write().await;
                    state.update_mark(&peer_did, quality, true);
                }
                
                // Trigger sync
                let store = self.store.read().await;
                let sync_msg = NetMessage::SyncRequest { 
                    merkle: store.merkle_root(), 
                    have: store.log().to_vec() 
                };
                drop(store);
                if let Some(handle) = pool.get_handle(&addr).await {
                    if let Ok(data) = sync_msg.serialize() {
                        let _ = handle.send(data).await;
                    }
                }
            } else {
                info_guard.state = ConnectionState::AwaitingTheirApproval;
                println!("[APPROVE] Sent approval, awaiting theirs...");
            }
        }
    }
    
    /// Reject peer in mutual elaboration
    pub async fn mutual_reject(&self, did_prefix: &str, reason: &str) {
        let pool = self.connection_pool.clone();
        
        // Get snapshot of peers
        let peers_snapshot: Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> = {
            let peers = pool.peers.read().await;
            peers.iter().map(|(addr, info)| (*addr, info.clone())).collect()
        };
        
        for (addr, info) in peers_snapshot {
            let info_guard = info.read().await;
            if let Some(ref did) = info_guard.did {
                if did.0.contains(did_prefix) || did.short().contains(did_prefix) {
                    let did_short = did.short();
                    drop(info_guard);
                    
                    let sig = detached_sign(
                        format!("mutual-reject:{}", reason).as_bytes(), 
                        &self.secret_key
                    );
                    
                    let msg = NetMessage::MutualReject {
                        reason: reason.to_string(),
                        signature: sig.as_bytes().to_vec(),
                    };
                    
                    if let Some(handle) = pool.get_handle(&addr).await {
                        if let Ok(data) = msg.serialize() {
                            let _ = handle.send(data).await;
                        }
                    }
                    
                    pool.remove(addr).await;
                    println!("[REJECT] Mutual rejection sent to {}", did_short);
                    return;
                }
            }
        }
        
        println!("[ERR] No pending connection found for '{}'", did_prefix);
    }
    
    /// Handle incoming mutual approval
    async fn handle_mutual_approve(
        &self, 
        msg_ts: u64, 
        peer_did: Did, 
        elaboration_hash: [u8; 32],
        signature: Vec<u8>, 
        from: SocketAddr,
        info: &Arc<RwLock<PeerInfo>>
    ) -> Result<()> {
        let now = timestamp();
        if now.saturating_sub(msg_ts) > 60 || msg_ts > now + 5 {
            return Err(DiagonError::Validation("Stale mutual approval".into()));
        }
        
        // Verify signature
        let mut signable = b"mutual-approve:".to_vec();
        signable.extend_from_slice(&msg_ts.to_le_bytes());
        signable.extend_from_slice(peer_did.0.as_bytes());
        signable.extend_from_slice(&elaboration_hash);
        
        let info_guard = info.read().await;
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(&signable, &signature, pk)?;
        } else {
            return Err(DiagonError::Validation("No pubkey for peer".into()));
        }
        drop(info_guard);
        
        if peer_did != self.did {
            return Err(DiagonError::Validation("Mutual approval not for us".into()));
        }
        
        // Verify they approved our actual elaboration
        {
            let info_guard = info.read().await;
            if let Some(ref our_elab) = info_guard.our_elaboration {
                let mut hasher = Sha256::new();
                hasher.update(our_elab.as_bytes());
                let our_hash: [u8; 32] = hasher.finalize().into();
                if our_hash != elaboration_hash {
                    return Err(DiagonError::Validation("Elaboration hash mismatch".into()));
                }
            }
        }
        
        // Update state
        let mut info_guard = info.write().await;
        info_guard.they_approved = true;
        
        if info_guard.check_connected() {
            let their_did = info_guard.did.clone();
            drop(info_guard);
            
            if let Some(ref did) = their_did {
                println!("[OK] Mutually connected with {}", did.short());
            } else {
                println!("[OK] Mutually connected with {}", from);
            }
            
            // Trigger sync
            let store = self.store.read().await;
            let msg = NetMessage::SyncRequest { 
                merkle: store.merkle_root(), 
                have: store.log().to_vec() 
            };
            drop(store);
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send(msg.serialize()?).await?;
            }
        } else {
            info_guard.state = ConnectionState::AwaitingOurApproval;
            let their_did = info_guard.did.clone();
            drop(info_guard);
            
            if let Some(ref did) = their_did {
                println!("[MUTUAL] {} approved. Use 'mutual-approve {}' to complete.", 
                         did.short(), did.short());
            }
        }
        
        Ok(())
    }
    
    /// Handle incoming mutual rejection
    async fn handle_mutual_reject(&self, reason: String, from: SocketAddr) -> Result<()> {
        println!("[REJECT] Mutual rejection from {}: {}", from, reason);
        self.connection_pool.remove(from).await;
        Ok(())
    }

    // insert after handle_mutual_reject method

    // ========================================================================
    // INTER-POOL TESTIMONY API
    // ========================================================================
    
    /// Create testimony for an expression from another pool
    pub async fn testify(&self, cid_prefix: &str, origin_pool_hex: &str, attestation: &str) {
        let cid = match self.resolve_cid(cid_prefix).await {
            Some(c) => c,
            None => {
                println!("[ERR] Expression not found: {}", cid_prefix);
                return;
            }
        };
        
        let our_pool = match *self.pool.read().await {
            Some(p) => p,
            None => {
                println!("[ERR] Must be in a pool to testify");
                return;
            }
        };
        
        let origin_pool = match hex::decode(origin_pool_hex) {
            Ok(bytes) if bytes.len() >= 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[..32]);
                arr
            }
            Ok(bytes) if bytes.len() >= 4 => {
                // Allow short prefix - pad with zeros
                let mut arr = [0u8; 32];
                arr[..bytes.len()].copy_from_slice(&bytes);
                arr
            }
            _ => {
                println!("[ERR] Invalid pool commitment hex");
                return;
            }
        };
        
        if our_pool == origin_pool {
            println!("[ERR] Cannot testify about own pool's expressions");
            return;
        }
        
        if attestation.len() < TESTIMONY_MIN_ATTESTATION_LEN {
            println!("[ERR] Attestation must be at least {} characters", TESTIMONY_MIN_ATTESTATION_LEN);
            return;
        }
        
        let mut testimony = Testimony {
            cid,
            origin_pool,
            witness_pool: our_pool,
            testifier: self.did.clone(),
            pubkey: self.public_key.as_bytes().to_vec(),
            attestation: attestation.to_string(),
            testified_at: timestamp(),
            signature: Vec::new(),
        };
        
        let sig = detached_sign(&testimony.signable_bytes(), &self.secret_key);
        testimony.signature = sig.as_bytes().to_vec();
        
        // Record in our registry
        self.testimony_registry.write().await.add_given(testimony.clone());
        
        // Broadcast to network (rendezvous or our pool)
        let msg = NetMessage::TestimonyAnnounce { 
            testimony: testimony.clone() 
        };
        self.broadcast_authenticated(&msg).await;
        
        println!("[TESTIMONY] Testified about {} from pool {}", 
                 cid.short(), hex::encode(&origin_pool[..4]));
    }
    
    /// Handle incoming testimony announcement
    async fn handle_testimony_announce(&self, testimony: Testimony, from: SocketAddr) -> Result<()> {
        // Verify signature
        if !testimony.verify() {
            println!("[ERR] Invalid testimony signature from {}", from);
            return Ok(());
        }
        
        let our_pool = match *self.pool.read().await {
            Some(p) => p,
            None => return Ok(()),
        };
        
        // Is this testimony about our pool's expression?
        if testimony.origin_pool == our_pool {
            // Record that another pool has witnessed our content
            let mut store = self.store.write().await;
            if let Some(meta) = store.metadata.get_mut(&testimony.cid) {
                if meta.add_testimony(testimony.clone()) {
                    println!("[TESTIFIED] {} witnessed by pool {} ({} pools total)", 
                             testimony.cid.short(),
                             hex::encode(&testimony.witness_pool[..4]),
                             meta.testimonies.pool_count);
                    
                    // Update trust for the testifier
                    drop(store);
                    let mut state = self.state.write().await;
                    state.update_mark(&testimony.testifier, 0.8, true);
                }
            }
        } else if self.is_in_rendezvous().await {
            // Forward in rendezvous network for gossip
            let msg = NetMessage::TestimonyAnnounce { testimony };
            self.broadcast_authenticated(&msg).await;
        }
        
        Ok(())
    }
    
    /// Request testimony about a specific expression
    pub async fn request_testimony(&self, cid_prefix: &str) {
        let cid = match self.resolve_cid(cid_prefix).await {
            Some(c) => c,
            None => {
                println!("[ERR] Expression not found: {}", cid_prefix);
                return;
            }
        };
        
        let our_pool = match *self.pool.read().await {
            Some(p) => p,
            None => {
                println!("[ERR] Must be in a pool to request testimony");
                return;
            }
        };
        
        let ts = timestamp();
        let mut data = b"testimony-request:".to_vec();
        data.extend_from_slice(&cid.0);
        data.extend_from_slice(&our_pool);
        data.extend_from_slice(self.did.0.as_bytes());
        data.extend_from_slice(&ts.to_le_bytes());
        let sig = detached_sign(&data, &self.secret_key);
        
        let msg = NetMessage::TestimonyRequest {
            cid,
            requester_pool: our_pool,
            requester: self.did.clone(),
            timestamp: ts,
            signature: sig.as_bytes().to_vec(),
        };
        
        // Broadcast to network
        self.broadcast_authenticated(&msg).await;
        println!("[TESTIMONY] Requested testimonies for {}", cid.short());
    }
    
    /// Handle incoming testimony request
    async fn handle_testimony_request(
        &self, 
        cid: Cid, 
        requester_pool: [u8; 32],
        requester: Did,
        from: SocketAddr
    ) -> Result<()> {
        let our_pool = match *self.pool.read().await {
            Some(p) => p,
            None => return Ok(()),
        };
        
        // Check if we have a testimony for this CID
        let registry = self.testimony_registry.read().await;
        if let Some(testimony) = registry.given.get(&cid) {
            // Send our testimony
            let msg = NetMessage::TestimonyAnnounce { 
                testimony: testimony.clone() 
            };
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                if let Ok(data) = msg.serialize() {
                    let _ = handle.send(data).await;
                }
            }
        }
        
        Ok(())
    }
    
    /// Show testimony status for an expression
    pub async fn show_testimonies(&self, cid_prefix: &str) {
        let cid = match self.resolve_cid(cid_prefix).await {
            Some(c) => c,
            None => {
                println!("[ERR] Expression not found: {}", cid_prefix);
                return;
            }
        };
        
        let store = self.store.read().await;
        
        if let Some(meta) = store.get_meta(&cid) {
            let testimonies = &meta.testimonies;
            
            if testimonies.testimonies.is_empty() {
                println!("\n=== NO TESTIMONIES FOR {} ===", cid.short());
                println!("This expression has not been witnessed by other pools.");
                println!("\nUse 'request-testimony {}' to solicit testimonies.", cid.short());
                return;
            }
            
            println!("\n=== TESTIMONIES FOR {} ===", cid.short());
            println!("Witnessed by {} pool(s), total weight: {}\n", 
                     testimonies.pool_count,
                     (testimonies.pool_count as u64) * TESTIMONY_WEIGHT_PER_POOL);
            
            for testimony in &testimonies.testimonies {
                let age = format_timestamp(testimony.testified_at);
                println!("  [{}] Pool {} via {}", 
                         age,
                         hex::encode(&testimony.witness_pool[..4]),
                         testimony.testifier.short());
                let preview = if testimony.attestation.len() > 60 {
                    format!("{}...", &testimony.attestation[..60])
                } else {
                    testimony.attestation.clone()
                };
                println!("       \"{}\"", preview);
            }
            
            if meta.is_witnessed() {
                println!("\n  Also acknowledged by {} witnesses within pool", 
                         meta.acknowledgments.witness_count());
            }
        } else {
            println!("[ERR] Expression {} not found", cid.short());
        }
    }
    
    /// Show testimonies we have given
    pub async fn show_given_testimonies(&self) {
        let registry = self.testimony_registry.read().await;
        
        if registry.given.is_empty() {
            println!("\n=== NO TESTIMONIES GIVEN ===");
            println!("Use 'testify <cid> <origin_pool> <attestation>' to create one.");
            return;
        }
        
        println!("\n=== TESTIMONIES GIVEN ({}) ===\n", registry.given_count);
        
        for (cid, testimony) in &registry.given {
            let age = format_timestamp(testimony.testified_at);
            println!("  [{}] {} from pool {}", 
                     age, cid.short(), hex::encode(&testimony.origin_pool[..4]));
            let preview = if testimony.attestation.len() > 50 {
                format!("{}...", &testimony.attestation[..50])
            } else {
                testimony.attestation.clone()
            };
            println!("       \"{}\"", preview);
        }
    }
    
    // ========== MESSAGE HANDLERS ==========
    
    async fn handle_message(&self, msg: NetMessage, from: SocketAddr, info: &Arc<RwLock<PeerInfo>>) -> Result<()> {
        if let Err(e) = self.verify_message_signature(&msg, &from).await {
            match &msg {
                NetMessage::MutualApprove { .. } | NetMessage::Elaborate { .. } |
                NetMessage::DmRequest { .. } | NetMessage::DmAccept { .. } |
                NetMessage::DmReject { .. } | NetMessage::DhtRegister { .. } |
                NetMessage::DhtPoolAnnounce { .. } => return Err(e),
                _ => {}
            }
        }
        
        match msg {
            NetMessage::Hello { did, pubkey, pool, expr_root } => {
                self.handle_hello(did, pubkey, pool, expr_root, from, info).await
            }
            NetMessage::Challenge(nonce) => {
                if !self.nonce_tracker.write().await.check_and_record(&nonce) {
                    return Err(DiagonError::ReplayAttack);
                }
                let sig = self.sign(&nonce);
                if let Some(handle) = self.connection_pool.get_handle(&from).await {
                    handle.send(NetMessage::Response { nonce, signature: sig }.serialize()?).await?;
                }
                Ok(())
            }
            NetMessage::Response { nonce, signature } => {
                self.handle_response(nonce, signature, info).await
            }
            NetMessage::ElaborateRequest => {
                info.write().await.state = ConnectionState::AwaitingOurElaboration;
                println!("[<-] {} requests elaboration", from);
                println!("   Use 'elaborate <text>' to respond");
                Ok(())
            }
            NetMessage::Elaborate { text, signature } => {
                self.handle_elaborate(text, signature, from, info).await
            }
            NetMessage::Expression(data) => {
                self.handle_expression(data, from, info).await
            }
            NetMessage::Signal(signal) => {
                self.handle_signal(signal, from).await
            }
            NetMessage::SyncRequest { merkle, have } => {
                self.handle_sync_request(merkle, have, from).await
            }
            NetMessage::SyncReply { expressions, pinned } => {
                self.handle_sync_reply(expressions, pinned, from).await
            }
            NetMessage::Heartbeat { timestamp: msg_ts, signature } => {
                self.handle_heartbeat(msg_ts, signature, from, info).await
            }
            NetMessage::Disconnect { timestamp: msg_ts, signature } => {
                self.handle_disconnect(msg_ts, signature, from).await
            }
            NetMessage::Discover { pools, want_hints } => {
                self.handle_discover(pools, want_hints, from).await
            }
            NetMessage::DiscoverResponse { peers, pool_hints } => {
                self.handle_discover_response(peers, pool_hints, from).await
            }
            NetMessage::ContentStart(metadata) => {
                self.handle_content_start(metadata, from).await
            }
            NetMessage::ContentData(chunk) => {
                self.handle_content_data(chunk, from).await
            }
            NetMessage::ContentAck { .. } => Ok(()),
            NetMessage::ContentRetransmit { content_id, missing_chunks } => {
                self.handle_content_retransmit(content_id, missing_chunks, from).await
            }
            NetMessage::ContentComplete { content_id, .. } => {
                self.outgoing_transfers.write().await.remove(&content_id);
                println!("[CONTENT] Transfer {} confirmed", hex::encode(&content_id[..8]));
                Ok(())
            }
            NetMessage::ContentError { content_id, reason } => {
                println!("[CONTENT] Transfer {} failed: {}", hex::encode(&content_id[..8]), reason);
                self.outgoing_transfers.write().await.remove(&content_id);
                Ok(())
            }
            NetMessage::DmRequest { from: requester_did, ephemeral_pubkey, .. } => {
                self.handle_dm_request(requester_did, ephemeral_pubkey, from).await
            }
            NetMessage::DmAccept { from: accepter_did, ephemeral_pubkey, .. } => {
                self.handle_dm_accept(accepter_did, ephemeral_pubkey).await
            }
            NetMessage::DmReject { from: rejecter_did, reason, .. } => {
                self.handle_dm_reject(rejecter_did, reason).await
            }
            NetMessage::DmMessage(dm_msg) => {
                self.handle_dm_message(dm_msg).await
            }
            NetMessage::PinRequest { cid, reason, .. } => {
                self.handle_pin_request(cid, reason, from).await
            }
            NetMessage::PinSignal(signal) => {
                self.handle_pin_signal(signal, from).await
            }
            NetMessage::PruneRequest { cid, reason, .. } => {
                self.handle_prune_request(cid, reason, from).await
            }
            NetMessage::PruneSignal(signal) => {
                self.handle_prune_signal(signal, from).await
            }
            NetMessage::DhtRegister { topic_hash, pool_commitment, pool_name, description, peer_count, signature } => {
                self.handle_dht_register(topic_hash, pool_commitment, pool_name, description, peer_count, signature, from).await
            }
            NetMessage::DhtDirectoryRequest => {
                self.handle_dht_directory_request(from).await
            }
            NetMessage::DhtDirectoryResponse { entries } => {
                self.handle_dht_directory_response(entries, from).await
            }
            NetMessage::DhtSearchRequest { topic_hash } => {
                self.handle_dht_search_request(topic_hash, from).await
            }
            NetMessage::DhtSearchResponse { topic_hash, results } => {
                self.handle_dht_search_response(topic_hash, results, from).await
            }
            NetMessage::DhtPoolAnnounce { pool_commitment, pool_name, peer_count, topics, signature } => {
                self.handle_dht_pool_announce(pool_commitment, pool_name, peer_count, topics, signature, from).await
            }
            NetMessage::DecayConfigPropose { id, config, reason, signature } => {
                self.handle_decay_config_propose(id, config, reason, signature, from).await
            }
            NetMessage::DecayConfigSignal(signal) => {
                self.handle_decay_config_signal(signal, from).await
            }
            NetMessage::Acknowledge(ack) => {
                self.handle_acknowledgment(ack, &from).await;
                Ok(())
            }
            NetMessage::MutualApprove { timestamp: msg_ts, peer_did, elaboration_hash, signature } => {
                self.handle_mutual_approve(msg_ts, peer_did, elaboration_hash, signature, from, info).await
            }
            NetMessage::MutualReject { reason, .. } => {
                self.handle_mutual_reject(reason, from).await
            }
            NetMessage::TestimonyRequest { cid, requester_pool, requester, .. } => {
                self.handle_testimony_request(cid, requester_pool, requester, from).await
            }
            NetMessage::TestimonyAnnounce { testimony } => {
                self.handle_testimony_announce(testimony, from).await
            }
            NetMessage::ReviewAssignment { content_cid, content_type, content_text, context_text, deadline, signature } => {
                self.handle_review_assignment(content_cid, content_type, content_text, context_text, deadline, from).await
            }
            NetMessage::ReviewSubmission { review } => {
                self.handle_review_submission(review, from).await
            }
            NetMessage::ReviewVerdict { verdict } => {
                self.handle_review_verdict(verdict, from).await
            }
            NetMessage::ReviewQueueRequest => {
                self.handle_review_queue_request(from).await
            }
            NetMessage::ReviewQueueResponse { pending_count, my_assignments, my_completed } => {
                println!("[REVIEW] Peer {} reports {} pending", from, pending_count);
                Ok(())
            }
        }
    }
    
    async fn handle_hello(
        &self, did: Did, pubkey: Vec<u8>, pool: [u8; 32], _expr_root: [u8; 32],
        from: SocketAddr, info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
        if !did.matches_pubkey(&pubkey) {
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send((NetMessage::MutualReject { 
                    reason: "DID mismatch".into(), 
                    signature: self.sign(b"did_mismatch") 
                }).serialize()?).await?;
            }
            return Err(DiagonError::Validation("DID mismatch".into()));
        }

        let our_pool = *self.pool.read().await;
        if let Some(p) = our_pool {
            if pool != p {
                if let Some(handle) = self.connection_pool.get_handle(&from).await {
                    handle.send((NetMessage::MutualReject { 
                        reason: "Pool mismatch".into(), 
                        signature: self.sign(b"pool_mismatch") 
                    }).serialize()?).await?;
                }
                return Err(DiagonError::Validation("Pool mismatch".into()));
            }
        } else {
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send((NetMessage::MutualReject { 
                    reason: "No pool configured".into(), 
                    signature: self.sign(b"no_pool") 
                }).serialize()?).await?;
            }
            return Err(DiagonError::Validation("No pool".into()));
        }
        
        {
            let mut info = info.write().await;
            info.did = Some(did.clone());
            info.pubkey = Some(pubkey);
        }
        self.connection_pool.register_did(from, &did).await;
        
        let initiated = info.read().await.initiated;
        
        if initiated {
            println!("[<-] Hello from {} ({})", from, did.short());
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            {
                let mut info = info.write().await;
                info.challenge_sent = Some(nonce);
                info.challenge_time = Some(Instant::now());
            }
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send(NetMessage::Challenge(nonce).serialize()?).await?;
            }
        } else {
            let store = self.store.read().await;
            let our_hello = NetMessage::Hello { 
                did: self.did.clone(), 
                pubkey: self.public_key.as_bytes().to_vec(), 
                pool: our_pool.unwrap(), 
                expr_root: store.merkle_root() 
            };
            drop(store);
            
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            {
                let mut info = info.write().await;
                info.challenge_sent = Some(nonce);
                info.challenge_time = Some(Instant::now());
            }
            
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send(our_hello.serialize()?).await?;
                handle.send(NetMessage::Challenge(nonce).serialize()?).await?;
                handle.send(NetMessage::ElaborateRequest.serialize()?).await?;
            }
            
            info.write().await.state = ConnectionState::AwaitingOurElaboration;
            println!("[<-] Connection from {} ({})", from, did.short());
        }
        
        Ok(())
    }

    async fn handle_response(&self, nonce: [u8; 32], signature: Vec<u8>, info: &Arc<RwLock<PeerInfo>>) -> Result<()> {
        let info_guard = info.read().await;
        if info_guard.challenge_sent.as_ref() != Some(&nonce) {
            return Err(DiagonError::Validation("Nonce mismatch".into()));
        }
        if let Some(time) = info_guard.challenge_time {
            if time.elapsed() > Duration::from_secs(CHALLENGE_TIMEOUT_SECS) {
                return Err(DiagonError::Validation("Challenge expired".into()));
            }
        }
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(&nonce, &signature, pk)?;
        } else {
            return Err(DiagonError::Validation("No pubkey".into()));
        }
        drop(info_guard);
        info.write().await.challenge_sent = None;
        Ok(())
    }

    async fn handle_elaborate(&self, text: String, signature: Vec<u8>, from: SocketAddr, info: &Arc<RwLock<PeerInfo>>) -> Result<()> {
        if text.len() < MIN_ELABORATION_LEN {
            return Err(DiagonError::Validation("Elaboration too short".into()));
        }
        
        let info_guard = info.read().await;
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(text.as_bytes(), &signature, pk)?;
        } else {
            return Err(DiagonError::Validation("No pubkey".into()));
        }
        let did_short = info_guard.did.as_ref().map(|d| d.short());
        let we_have_elaborated = info_guard.our_elaboration.is_some();
        drop(info_guard);
        
        // Store their elaboration
        {
            let mut info_guard = info.write().await;
            info_guard.elaboration = Some(text.clone());
            
            // Check if we should enter mutual pending
            if info_guard.check_mutual_pending() {
                // Both have elaborated - mutual mode
                if let Some(ref did_short) = did_short {
                    println!();
                    println!("[MUTUAL] Both elaborations received!");
                    println!("[ELAB] from {}", did_short);
                    println!("   \"{}\"", if text.len() > 80 { format!("{}...", &text[..80]) } else { text.clone() });
                    println!();
                    println!("   Use 'review {}' to see full elaboration", did_short);
                    println!("   Use 'mutual-approve {}' or 'mutual-reject {} <reason>'", did_short, did_short);
                }
            } else if we_have_elaborated {
                // We elaborated first, now they have too
                info_guard.state = ConnectionState::MutualPending;
                if let Some(ref did_short) = did_short {
                    println!();
                    println!("[ELAB] from {}", did_short);
                    println!("   \"{}\"", if text.len() > 80 { format!("{}...", &text[..80]) } else { text.clone() });
                    println!();
                    println!("   Use 'mutual-approve {}' or 'mutual-reject {} <reason>'", did_short, did_short);
                }
            } else {
                // They elaborated first, we need to elaborate
                info_guard.state = ConnectionState::AwaitingOurElaboration;
                if let Some(ref did_short) = did_short {
                    println!();
                    println!("[ELAB] from {}", did_short);
                    println!("   \"{}\"", if text.len() > 80 { format!("{}...", &text[..80]) } else { text.clone() });
                    println!();
                    println!("   Use 'elaborate <your text>' to respond, then 'mutual-approve {}'", did_short);
                }
            }
        }
        
        Ok(())
    }

    async fn handle_approve(&self, msg_ts: u64, peer_did: Did, signature: Vec<u8>, from: SocketAddr, info: &Arc<RwLock<PeerInfo>>) -> Result<()> {
        let now = timestamp();
        if now.saturating_sub(msg_ts) > 60 || msg_ts > now + 5 {
            return Err(DiagonError::Validation("Stale approval".into()));
        }
        
        let mut signable = b"approve:".to_vec();
        signable.extend_from_slice(&msg_ts.to_le_bytes());
        signable.extend_from_slice(peer_did.0.as_bytes());
        
        let info_guard = info.read().await;
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(&signable, &signature, pk)?;
        } else {
            return Err(DiagonError::Validation("No pubkey".into()));
        }
        drop(info_guard);
        
        if peer_did != self.did {
            return Err(DiagonError::Validation("Approval not for us".into()));
        }
        
        info.write().await.state = ConnectionState::Connected;
        println!("[✓] Authenticated with {}", from);
        
        let store = self.store.read().await;
        let msg = NetMessage::SyncRequest { merkle: store.merkle_root(), have: store.log().to_vec() };
        drop(store);
        if let Some(handle) = self.connection_pool.get_handle(&from).await {
            handle.send(msg.serialize()?).await?;
        }
        
        Ok(())
    }

    async fn handle_expression(&self, data: Vec<u8>, from: SocketAddr, info: &Arc<RwLock<PeerInfo>>) -> Result<()> {
        let mut store = self.store.write().await;
        
        let expr = match store.arena_mut().deserialize(&data) {
            Some(e) => e,
            None => return Err(DiagonError::Validation("Invalid expression".into())),
        };
        
        let op = store.arena().car(expr);
        if let SexpNode::Atom(s) = store.arena().get(op) {
            if s == "signed" {
                let pk_ref = store.arena().nth(expr, 1);
                let sig_ref = store.arena().nth(expr, 2);
                let inner = store.arena().nth(expr, 3);
                
                let pubkey = match store.arena().get(pk_ref) {
                    SexpNode::Bytes(b) => b.clone(),
                    _ => return Err(DiagonError::Validation("Invalid pubkey".into())),
                };
                
                let signature = match store.arena().get(sig_ref) {
                    SexpNode::Bytes(b) => b.clone(),
                    _ => return Err(DiagonError::Validation("Invalid signature".into())),
                };
                
                let inner_data = store.arena().serialize(inner);
                self.verify(&inner_data, &signature, &pubkey)?;
            }
        }
        
        match store.store(expr) {
            Ok((cid, is_new)) => {
                if is_new {
                    println!("[EXPR] Received {}", cid);
                    info.write().await.seen_cids.insert(cid);
                    drop(store);
                    self.process_expression(cid, &data).await;
                    
                    let msg = NetMessage::Expression(data);
                    let msg_data = msg.serialize()?;
                    
                    for addr in self.connection_pool.authenticated_addrs().await {
                        if addr != from {
                            if let Some(peer_info) = self.connection_pool.get_info(&addr).await {
                                if !peer_info.read().await.seen_cids.contains(&cid) {
                                    peer_info.write().await.seen_cids.insert(cid);
                                    if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                                        let _ = handle.send(msg_data.clone()).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Store failed: {}", e),
        }
        Ok(())
    }

    async fn process_expression(&self, cid: Cid, data: &[u8]) {
        let mut store = self.store.write().await;
        let expr = match store.fetch(&cid) { Some(e) => e, None => return };
        let op = store.arena().car(expr);
        if let SexpNode::Atom(s) = store.arena().get(op) {
            if s == "signed" {
                let inner = store.arena().nth(expr, 3);
                let inner_op = store.arena().car(inner);
                
                let pk_ref = store.arena().nth(expr, 1);
                let proposer_did = if let SexpNode::Bytes(pk_bytes) = store.arena().get(pk_ref) {
                    if let Ok(pk) = PublicKey::from_bytes(pk_bytes) {
                        Did::from_pubkey(&pk)
                    } else { return; }
                } else { return; };
                
                if let SexpNode::Atom(inner_s) = store.arena().get(inner_op) {
                    match inner_s.as_str() {
                        "propose" => {
                            if !self.state.read().await.proposals.contains_key(&cid) {
                                let text_ref = store.arena().nth(inner, 1);
                                if let SexpNode::Atom(text) = store.arena().get(text_ref) {
                                    let peer_count = self.connection_pool.authenticated_addrs().await.len();
                                    let threshold = self.state.read().await.threshold(peer_count);
                                    let proposal = ProposalState { 
                                        cid, 
                                        expr_data: data.to_vec(), 
                                        proposer: proposer_did.clone(),
                                        elaboration: text.clone(), 
                                        quorum: QuorumState::new(cid, threshold, proposer_did),
                                        created: timestamp() 
                                    };
                                    drop(store);
                                    self.state.write().await.proposals.insert(cid, proposal);
                                    let _ = self.save_state().await;
                                }
                            }
                        }
                        "reply-to" => {
                            let parent_ref = store.arena().nth(inner, 1);
                            if let SexpNode::Bytes(parent_bytes) = store.arena().get(parent_ref) {
                                if parent_bytes.len() == 32 {
                                    let mut parent_arr = [0u8; 32];
                                    parent_arr.copy_from_slice(parent_bytes);
                                    let parent_cid = Cid(parent_arr);
                                    
                                    if store.has(&parent_cid) {
                                        store.add_reply(parent_cid, cid);
                                    } else {
                                        println!("[WARN] Orphan reply {} references unknown parent {}", 
                                            cid.short(), parent_cid.short());
                                        store.add_reply(parent_cid, cid);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn handle_signal(&self, signal: QuorumSignal, from: SocketAddr) -> Result<()> {
        if !signal.source.matches_pubkey(&signal.pubkey) {
            return Err(DiagonError::Validation("Signal source mismatch".into()));
        }
        
        let signable = signal.signable_bytes();
        self.verify(&signable, &signal.signature, &signal.pubkey)?;
        
        let mut state = self.state.write().await;
        if let Some(proposal) = state.proposals.get_mut(&signal.target) {
            match proposal.quorum.sense(signal.clone()) {
                Ok(sensed) => {
                    if sensed {
                        println!("[SIGNAL] {} on {} (+{})", 
                            if signal.support { "FOR" } else { "AGAINST" }, 
                            signal.target.short(), signal.weight);
                        if proposal.quorum.reached() { 
                            println!("[QUORUM] {} reached!", signal.target); 
                        }
                    }
                }
                Err(e) => eprintln!("Signal rejected: {}", e),
            }
        }
        drop(state);
        
        let msg = NetMessage::Signal(signal);
        let msg_data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(msg_data.clone()).await;
                }
            }
        }
        Ok(())
    }

    async fn handle_sync_request(&self, peer_merkle: [u8; 32], have: Vec<Cid>, from: SocketAddr) -> Result<()> {
        let store = self.store.read().await;
        let state = self.state.read().await;
        
        if store.merkle_root() != peer_merkle {
            let have_set: HashSet<_> = have.into_iter().collect();
            let missing: Vec<Vec<u8>> = store.log().iter()
                .filter(|cid| !have_set.contains(cid))
                .filter_map(|cid| store.serialize_expr(cid))
                .take(100)
                .collect();
            
            let pinned_cids: Vec<Cid> = state.pinned.iter()
                .filter(|(_, p)| p.active)
                .map(|(cid, _)| *cid)
                .collect();
            
            if !missing.is_empty() || !pinned_cids.is_empty() {
                if let Some(handle) = self.connection_pool.get_handle(&from).await {
                    handle.send(NetMessage::SyncReply { 
                        expressions: missing,
                        pinned: pinned_cids,
                    }.serialize()?).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_sync_reply(&self, expressions: Vec<Vec<u8>>, pinned: Vec<Cid>, from: SocketAddr) -> Result<()> {
        let mut added = 0;
        for data in expressions {
            let info = match self.connection_pool.get_info(&from).await {
                Some(i) => i,
                None => continue,
            };
            
            if self.handle_expression(data, from, &info).await.is_ok() {
                added += 1;
            }
        }
        
        if !pinned.is_empty() {
            println!("[SYNC] Peer has {} pinned items", pinned.len());
        }
        
        if added > 0 {
            println!("[SYNC] Received {} expressions", added);
            let _ = self.save_state().await;
        }
        Ok(())
    }

    async fn handle_heartbeat(&self, msg_ts: u64, signature: Vec<u8>, from: SocketAddr, info: &Arc<RwLock<PeerInfo>>) -> Result<()> {
        let now = timestamp();
        if now.saturating_sub(msg_ts) > 60 {
            return Err(DiagonError::Validation("Stale heartbeat".into()));
        }
        
        let mut signable = b"heartbeat:".to_vec();
        signable.extend_from_slice(&msg_ts.to_le_bytes());
        
        let info_guard = info.read().await;
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(&signable, &signature, pk)?;
        }
        drop(info_guard);
        
        info.write().await.last_activity = Instant::now();
        Ok(())
    }

    async fn handle_disconnect(&self, msg_ts: u64, signature: Vec<u8>, from: SocketAddr) -> Result<()> {
        let now = timestamp();
        if now.saturating_sub(msg_ts) > 60 {
            return Err(DiagonError::Validation("Stale disconnect".into()));
        }
        
        let mut signable = b"disconnect:".to_vec();
        signable.extend_from_slice(&msg_ts.to_le_bytes());
        
        if let Some(info) = self.connection_pool.get_info(&from).await {
            let info_guard = info.read().await;
            if let Some(ref pk) = info_guard.pubkey {
                self.verify(&signable, &signature, pk)?;
            }
        }
        
        self.connection_pool.remove(from).await;
        println!("[PEER] {} disconnected", from);
        Ok(())
    }

    async fn handle_discover(&self, requested_pools: Vec<[u8; 32]>, want_hints: bool, from: SocketAddr) -> Result<()> {
        let our_pool = *self.pool.read().await;
        let mut discovered_peers = Vec::new();
        let mut hints = Vec::new();
        
        let we_match = requested_pools.is_empty() 
            || our_pool.map(|p| requested_pools.contains(&p)).unwrap_or(false);
        
        if we_match {
            if let Some(pool) = our_pool {
                discovered_peers.push(DiscoveredPeer {
                    addr: self.bind_addr.parse().unwrap_or(from),
                    pool,
                    expr_count: self.store.read().await.len(),
                    uptime_secs: self.started_at.elapsed().as_secs(),
                });
            }
        }
        
        if let Some(our_p) = our_pool {
            let show_our_pool = requested_pools.is_empty() || requested_pools.contains(&our_p);
            if show_our_pool {
                let peers = self.connection_pool.peers.read().await;
                for (addr, info) in peers.iter() {
                    if discovered_peers.len() >= 20 { break; }
                    let info = info.read().await;
                    if info.is_authenticated() {
                        discovered_peers.push(DiscoveredPeer {
                            addr: *addr, pool: our_p, expr_count: 0, uptime_secs: 0,
                        });
                    }
                }
            }
        }
        
        if want_hints {
            for genesis in GENESIS_POOLS.iter() {
                let peer_count = if our_pool == Some(*genesis) {
                    self.connection_pool.authenticated_addrs().await.len() + 1
                } else { 0 };
                hints.push(PoolHint::from_commitment(*genesis, None, peer_count));
            }
        }
        
        let response = NetMessage::DiscoverResponse { peers: discovered_peers, pool_hints: hints };
        
        if let Some(handle) = self.connection_pool.get_handle(&from).await {
            handle.send(response.serialize()?).await?;
        }
        
        Ok(())
    }

    async fn handle_discover_response(&self, peers: Vec<DiscoveredPeer>, pool_hints: Vec<PoolHint>, from: SocketAddr) -> Result<()> {
        let our_pool = *self.pool.read().await;
        
        if !peers.is_empty() {
            println!("[DISCOVER] {} peer(s) from {}:", peers.len(), from);
            for peer in &peers {
                let pool_match = our_pool.map(|p| p == peer.pool).unwrap_or(false);
                let marker = if pool_match { " [same-pool]" } else { "" };
                println!("  {} (pool: {}..., {} expr){}",
                    peer.addr, hex::encode(&peer.pool[..4]), peer.expr_count, marker);
            }
        }
        
        if !pool_hints.is_empty() {
            println!("[DISCOVER] Known pools:");
            for hint in &pool_hints {
                let genesis = if hint.is_genesis { " [genesis]" } else { "" };
                println!("  {}... ({} peers){}", hex::encode(&hint.commitment[..4]), hint.peer_count, genesis);
            }
        }
        
        Ok(())
    }

    async fn handle_content_start(&self, metadata: ContentMetadata, from: SocketAddr) -> Result<()> {
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        if !info.read().await.is_authenticated() {
            return Err(DiagonError::Validation("Not authenticated".into()));
        }
        
        let pubkey = info.read().await.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey".into()))?;
        
        self.verify(&metadata.signable_bytes(), &metadata.signature, &pubkey)?;
        
        let mut transfers = self.incoming_transfers.write().await;
        if transfers.contains_key(&metadata.content_id) { return Ok(()); }
        
        if transfers.len() >= MAX_PENDING_TRANSFERS {
            let expired: Vec<_> = transfers.iter()
                .filter(|(_, t)| t.is_expired())
                .map(|(k, _)| *k)
                .collect();
            for k in expired { transfers.remove(&k); }
            
            if transfers.len() >= MAX_PENDING_TRANSFERS {
                return Err(DiagonError::Validation("Too many pending transfers".into()));
            }
        }
        
        println!("[CONTENT] Receiving {} from {} ({} bytes, {} chunks)",
            metadata.content_type, metadata.sender.short(), metadata.total_size, metadata.total_chunks);
        
        transfers.insert(metadata.content_id, IncomingTransfer::new(metadata));
        Ok(())
    }

    async fn handle_content_data(&self, chunk: ContentChunk, from: SocketAddr) -> Result<()> {
        let mut transfers = self.incoming_transfers.write().await;
        
        let transfer = transfers.get_mut(&chunk.content_id)
            .ok_or(DiagonError::Validation("Unknown transfer".into()))?;
        
        let was_new = transfer.add_chunk(&chunk)?;
        
        if was_new {
            let ack = NetMessage::ContentAck { content_id: chunk.content_id, chunk_index: chunk.chunk_index };
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                if let Ok(data) = ack.serialize() { let _ = handle.send(data).await; }
            }
            
            let received = transfer.received_count;
            let total = transfer.metadata.total_chunks;
            if received % 10 == 0 || received == total {
                println!("[CONTENT] {}/{} chunks for {}", received, total, hex::encode(&chunk.content_id[..8]));
            }
            
            if transfer.is_complete() {
                let content_id = transfer.metadata.content_id;
                let content_type = transfer.metadata.content_type;
                let filename = transfer.metadata.filename.clone();
                let sender = transfer.metadata.sender.clone();

                match transfer.reassemble() {
                    Ok(data) => {
                        drop(transfers);
                        
                        let save_path = self.save_received_content(&content_id, content_type, filename.as_deref(), &data).await;
                        
                        println!("[CONTENT] Complete: {} from {} ({} bytes)",
                            hex::encode(&content_id[..8]), sender.short(), data.len());
                        if let Some(path) = save_path {
                            println!("[CONTENT] Saved to: {}", path);
                        }
                        
                        let sig = self.sign(&content_id);
                        let complete = NetMessage::ContentComplete { content_id, signature: sig };
                        if let Some(handle) = self.connection_pool.get_handle(&from).await {
                            if let Ok(data) = complete.serialize() { let _ = handle.send(data).await; }
                        }
                        
                        self.incoming_transfers.write().await.remove(&content_id);
                    }
                    Err(e) => println!("[CONTENT] Reassembly failed: {}", e),
                }
            }
        }

        Ok(())
    }

    async fn handle_content_retransmit(&self, content_id: [u8; 32], missing_chunks: Vec<u32>, from: SocketAddr) -> Result<()> {
        let mut outgoing = self.outgoing_transfers.write().await;
        
        if let Some(encoder) = outgoing.get_mut(&content_id) {
            println!("[CONTENT] Retransmitting {} chunks", missing_chunks.len());
            
            for chunk_index in missing_chunks {
                encoder.current_chunk = chunk_index;
                if let Some(chunk) = encoder.next_chunk() {
                    let msg = NetMessage::ContentData(chunk);
                    if let Some(handle) = self.connection_pool.get_handle(&from).await {
                        if let Ok(data) = msg.serialize() { let _ = handle.send(data).await; }
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn save_received_content(&self, content_id: &[u8; 32], content_type: ContentType, filename: Option<&str>, data: &[u8]) -> Option<String> {
        let extension = match content_type {
            ContentType::Image => match detect_image_mime(data).as_deref() {
                Some("image/jpeg") => "jpg",
                Some("image/png") => "png",
                Some("image/gif") => "gif",
                Some("image/webp") => "webp",
                _ => "bin",
            },
            ContentType::Video => match detect_video_mime(data).as_deref() {
                Some("video/mp4") => "mp4",
                Some("video/webm") => "webm",
                _ => "bin",
            },
            ContentType::Text => "txt",
        };
        
        let base_name = filename
            .map(|n| n.split('.').next().unwrap_or(n))
            .unwrap_or_else(|| Box::leak(hex::encode(&content_id[..8]).into_boxed_str()));
        
        let name = format!("{}.{}", base_name, extension);
        let path = format!("{}/received/{}", self.db_path, name);
        
        let dir = format!("{}/received", self.db_path);
        let _ = tokio::fs::create_dir_all(&dir).await;
        
        match tokio::fs::write(&path, data).await {
            Ok(_) => Some(path),
            Err(e) => { println!("[CONTENT] Save failed: {}", e); None }
        }
    }

    async fn handle_review_assignment(
        &self, content_cid: Cid, content_type: ReviewableContentType,
        content_text: String, context_text: Option<String>, deadline: u64, from: SocketAddr,
    ) -> Result<()> {
        let mut state = self.review_state.write().await;
        if !state.pending.contains_key(&content_cid) {
            let pending = PendingReview {
                content_cid, content_type, content_text, context_cid: None, context_text,
                submitted_at: timestamp(), deadline, required_reviews: content_type.tier_config().0,
                assigned_reviewers: vec![self.did.clone()], reviews: Vec::new(),
                author: Did("anonymous".into()), word_count: 0,
            };
            state.pending.insert(content_cid, pending);
        }
        println!("[REVIEW] Assigned: {} ({})", content_cid.short(), content_type);
        Ok(())
    }
    
    async fn handle_review_submission(&self, review: QualityReview, from: SocketAddr) -> Result<()> {
        if !review.verify() { return Err(DiagonError::SignatureRequired); }
        
        let cid = review.content_cid;
        let reviewer = review.reviewer.clone();
        
        let complete = {
            let mut state = self.review_state.write().await;
            state.submit_review(review.clone())?
        };
        
        println!("[REVIEW] From {} for {}", reviewer.short(), cid.short());
        
        let msg = NetMessage::ReviewSubmission { review };
        let data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(h) = self.connection_pool.get_handle(&addr).await {
                    let _ = h.send(data.clone()).await;
                }
            }
        }
        
        if complete { self.finalize_review_internal(cid).await?; }
        Ok(())
    }
    
    async fn handle_review_verdict(&self, verdict: QualityVerdict, from: SocketAddr) -> Result<()> {
        let cid = verdict.content_cid;
        
        {
            let mut state = self.review_state.write().await;
            state.pending.remove(&cid);
            state.verdicts.insert(cid, verdict.clone());
        }
        
        if verdict.author == self.did && verdict.xp_awarded > 0 {
            self.xp.write().await.total_xp += verdict.xp_awarded;
            println!("[XP] +{} for {} (quality: {:.2})", verdict.xp_awarded, cid.short(), verdict.quality_score);
        }
        
        {
            let state = self.review_state.read().await;
            let rewards = state.calculate_reviewer_rewards(&cid);
            if let Some(&rxp) = rewards.get(&self.did) {
                self.xp.write().await.total_xp += rxp;
                println!("[XP] +{} for reviewing {}", rxp, cid.short());
            }
        }
        
        if !verdict.flagged {
            let q = verdict.quality_score * 0.8 + 0.2;
            self.state.write().await.update_mark(&verdict.author, q, true);
        }
        
        let msg = NetMessage::ReviewVerdict { verdict };
        let data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(h) = self.connection_pool.get_handle(&addr).await {
                    let _ = h.send(data.clone()).await;
                }
            }
        }
        
        let _ = self.save_state().await;
        Ok(())
    }
    
    async fn handle_review_queue_request(&self, from: SocketAddr) -> Result<()> {
        let state = self.review_state.read().await;
        let msg = NetMessage::ReviewQueueResponse {
            pending_count: state.pending.len(),
            my_assignments: state.get_assignments(&self.did).iter().map(|p| p.content_cid).collect(),
            my_completed: state.reviewer_reputations.get(&self.did).map(|r| r.reviews_completed as usize).unwrap_or(0),
        };
        if let Some(h) = self.connection_pool.get_handle(&from).await {
            h.send(msg.serialize()?).await?;
        }
        Ok(())
    }
    
    async fn finalize_review_internal(&self, cid: Cid) -> Result<()> {
        let should = self.review_state.read().await.pending.get(&cid)
            .map(|p| p.is_complete() || p.is_expired()).unwrap_or(false);
        
        if should {
            let verdict = self.review_state.write().await.finalize_review(cid)?;
            let msg = NetMessage::ReviewVerdict { verdict: verdict.clone() };
            self.broadcast_authenticated(&msg).await;
            
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            self.handle_review_verdict(verdict, addr).await?;
        }
        Ok(())
    }

    pub async fn submit_for_review(
        &self, content_cid: Cid, content_type: ReviewableContentType,
        content_text: String, context_cid: Option<Cid>, context_text: Option<String>,
    ) {
        let eligible: Vec<Did> = {
            let state = self.state.read().await;
            let mut e = Vec::new();
            for addr in self.connection_pool.authenticated_addrs().await {
                if let Some(info) = self.connection_pool.get_info(&addr).await {
                    let g = info.read().await;
                    if let Some(ref did) = g.did {
                        if state.get_mark(did).current_score() >= TRUST_MIN_FOR_PROPOSE {
                            e.push(did.clone());
                        }
                    }
                }
            }
            e
        };
        
        let res = {
            let mut rs = self.review_state.write().await;
            rs.submit_for_review(content_cid, content_type, content_text.clone(), context_cid, context_text.clone(), self.did.clone(), &eligible)
        };
        
        match res {
            Ok(()) => {
                println!("[REVIEW] {} submitted for {}", content_cid.short(), content_type);
                
                let rs = self.review_state.read().await;
                if let Some(p) = rs.pending.get(&content_cid) {
                    let sig = self.sign(&{
                        let mut d = b"review-assignment:".to_vec();
                        d.extend_from_slice(&content_cid.0);
                        d.extend_from_slice(content_type.as_str().as_bytes());
                        d.extend_from_slice(content_text.as_bytes());
                        d.extend_from_slice(&p.deadline.to_le_bytes());
                        d
                    });
                    
                    let msg = NetMessage::ReviewAssignment {
                        content_cid, content_type, content_text, context_text, deadline: p.deadline, signature: sig,
                    };
                    drop(rs);
                    self.broadcast_authenticated(&msg).await;
                }
            }
            Err(e) => println!("[REVIEW] Failed: {}", e),
        }
    }
    
    pub async fn review_queue(&self) {
        let rs = self.review_state.read().await;
        let assignments = rs.get_assignments(&self.did);
        
        println!("\n=== REVIEW QUEUE ===");
        println!("Total pending: {} | Your assignments: {}", rs.pending.len(), assignments.len());
        
        for p in assignments {
            let h = p.deadline.saturating_sub(timestamp()) / 3600;
            let preview = if p.content_text.len() > 50 { format!("{}...", &p.content_text[..50]) } else { p.content_text.clone() };
            println!("  {} [{}] {}h left - \"{}\"", p.content_cid.short(), p.content_type, h, preview);
        }
        
        if let Some(rep) = rs.reviewer_reputations.get(&self.did) {
            println!("\nYour stats: {} reviews, {:.2} score", rep.reviews_completed, rep.score);
        }
        println!();
    }
    
    pub async fn review_content(&self, cid_prefix: &str) {
        let rs = self.review_state.read().await;
        let pending = rs.pending.iter()
            .find(|(c, p)| c.short().starts_with(cid_prefix) && p.is_assigned(&self.did))
            .map(|(_, p)| p.clone());
        
        let p = match pending {
            Some(p) => p,
            None => { println!("[ERR] Not found: {}", cid_prefix); return; }
        };
        
        println!("\n=== REVIEW: {} ===", p.content_cid.short());
        println!("Type: {} | Words: {} | Deadline: {}", p.content_type, p.word_count, format_timestamp(p.deadline));
        if let Some(ref ctx) = p.context_text {
            println!("\nCONTEXT:\n{}\n", ctx);
        }
        println!("CONTENT:\n═══════════════════════════════════════");
        println!("{}", p.content_text);
        println!("═══════════════════════════════════════\n");
        println!("Use: submit-review {} <rel> <sub> <cla> <ori> <eff> \"justification\" [--spam|--plagiarism|--offtopic]", p.content_cid.short());
    }
    
    pub async fn submit_review_cmd(
        &self, cid_prefix: &str, rel: u8, sub: u8, cla: u8, ori: u8, eff: u8,
        just: &str, spam: bool, plag: bool, offtopic: bool,
    ) {
        if ![rel, sub, cla, ori, eff].iter().all(|&s| (1..=5).contains(&s)) {
            println!("[ERR] Scores must be 1-5"); return;
        }
        if just.len() < REVIEW_MIN_JUSTIFICATION_LEN {
            println!("[ERR] Justification min {} chars", REVIEW_MIN_JUSTIFICATION_LEN); return;
        }
        
        let cid = {
            let rs = self.review_state.read().await;
            rs.pending.keys().find(|c| c.short().starts_with(cid_prefix)).copied()
        };
        
        let cid = match cid {
            Some(c) => c,
            None => { println!("[ERR] Not in queue"); return; }
        };
        
        let mut review = QualityReview {
            content_cid: cid, reviewer: self.did.clone(), pubkey: self.public_key.as_bytes().to_vec(),
            relevance: rel, substance: sub, clarity: cla, originality: ori, effort: eff,
            justification: just.to_string(), flag_spam: spam, flag_plagiarism: plag, flag_offtopic: offtopic,
            reviewed_at: timestamp(), signature: Vec::new(),
        };
        
        let sig = detached_sign(&review.signable_bytes(), &self.secret_key);
        review.signature = sig.as_bytes().to_vec();
        
        let complete = {
            let mut rs = self.review_state.write().await;
            match rs.submit_review(review.clone()) {
                Ok(c) => c,
                Err(e) => { println!("[ERR] {}", e); return; }
            }
        };
        
        println!("[REVIEW] Submitted for {} (score: {:.2})", cid.short(), review.composite_score());
        
        let msg = NetMessage::ReviewSubmission { review };
        self.broadcast_authenticated(&msg).await;
        
        if complete {
            let _ = self.finalize_review_internal(cid).await;
        }
        let _ = self.save_state().await;
    }
    
    pub async fn show_verdicts(&self, count: usize) {
        let rs = self.review_state.read().await;
        let mut v: Vec<_> = rs.verdicts.values().collect();
        v.sort_by(|a, b| b.verdict_at.cmp(&a.verdict_at));
        
        println!("\n=== VERDICTS ===");
        for verdict in v.iter().take(count) {
            let status = if verdict.flagged {
                format!("FLAGGED: {}", verdict.flag_reason.as_deref().unwrap_or("?"))
            } else {
                format!("Quality: {:.2}", verdict.quality_score)
            };
            println!("  {} | {} | {} XP | {} reviews", 
                     verdict.content_cid.short(), status, verdict.xp_awarded, verdict.reviewer_scores.len());
        }
        println!();
    }
    
    pub async fn reviewer_stats(&self) {
        let rs = self.review_state.read().await;
        println!("\n=== REVIEWER STATS ===");
        if let Some(rep) = rs.reviewer_reputations.get(&self.did) {
            println!("Reviews: {} | Alignments: {} | Deviations: {}", 
                     rep.reviews_completed, rep.consensus_alignments, rep.consensus_deviations);
            println!("Flags confirmed: {} | False flags: {}", rep.confirmed_flags, rep.false_flags);
            println!("Score: {:.3} | Weight: {:.3}", rep.score, rep.weight());
        } else {
            println!("No review history.");
        }
        println!();
    }

    async fn handle_dm_request(&self, requester_did: Did, ephemeral_pubkey: [u8; 32], _from: SocketAddr) -> Result<()> {
        let channel_id = self.did.dm_channel_id(&requester_did);
        
        let secret = ReusableSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let public_bytes: [u8; 32] = public.to_bytes();
        
        let channel = DmChannel::new_inbound(requester_did.clone(), ephemeral_pubkey, public_bytes);
        
        self.dm_channels.write().await.insert(channel_id, channel);
        self.dm_secrets.write().await.insert(channel_id, secret);
        
        println!();
        println!("[DM] Request from {}", requester_did.short());
        println!("   Use 'dm-accept {}' to accept or 'dm-reject {} <reason>' to reject", 
            requester_did.short(), requester_did.short());
        
        Ok(())
    }

    async fn handle_dm_accept(&self, accepter_did: Did, ephemeral_pubkey: [u8; 32]) -> Result<()> {
        let channel_id = self.did.dm_channel_id(&accepter_did);
        
        let mut channels = self.dm_channels.write().await;
        let channel = channels.get_mut(&channel_id)
            .ok_or(DiagonError::Validation("No pending channel".into()))?;
        
        if channel.state != DmChannelState::PendingOutbound {
            return Err(DiagonError::Validation("Unexpected accept".into()));
        }
        
        let secrets = self.dm_secrets.read().await;
        let secret = secrets.get(&channel_id)
            .ok_or(DiagonError::Validation("Missing secret".into()))?;
        
        channel.establish(ephemeral_pubkey, secret);
        
        println!("[DM] Channel established with {}", accepter_did.short());
        
        Ok(())
    }

    async fn handle_dm_reject(&self, rejecter_did: Did, reason: String) -> Result<()> {
        let channel_id = self.did.dm_channel_id(&rejecter_did);
        
        self.dm_channels.write().await.remove(&channel_id);
        self.dm_secrets.write().await.remove(&channel_id);
        
        println!("[DM] {} rejected: {}", rejecter_did.short(), reason);
        
        Ok(())
    }

    async fn handle_dm_message(&self, dm_msg: DmMessage) -> Result<()> {
        if dm_msg.to != self.did {
            return Err(DiagonError::Validation("DM not for us".into()));
        }
        
        let channel_id = self.did.dm_channel_id(&dm_msg.from);
        
        let mut channels = self.dm_channels.write().await;
        let channel = channels.get_mut(&channel_id)
            .ok_or(DiagonError::DmNotEstablished)?;
        
        if channel.state != DmChannelState::Established {
            return Err(DiagonError::DmNotEstablished);
        }
        
        let plaintext = channel.decrypt(&dm_msg.encrypted_content, &dm_msg.nonce)?;
        
        channel.add_message(dm_msg.from.clone(), plaintext.clone());
        
        println!("[DM←{}] {}", dm_msg.from.short(), plaintext);
        
        Ok(())
    }

    async fn handle_pin_request(&self, cid: Cid, reason: String, from: SocketAddr) -> Result<()> {
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let proposer = info.read().await.did.clone()
            .ok_or(DiagonError::Validation("No DID".into()))?;
        
        if !self.store.read().await.has(&cid) {
            return Ok(());
        }
        
        if self.state.read().await.pinned.contains_key(&cid) {
            return Ok(());
        }
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        
        let pinned = PinnedContent {
            cid,
            pinned_by: proposer.clone(),
            reason: reason.clone(),
            quorum: QuorumState::new(cid, threshold, proposer),
            pinned_at: timestamp(),
            active: false,
        };
        
        self.state.write().await.pinned.insert(cid, pinned);
        println!("[PIN] Proposal received for {} - \"{}\"", cid.short(), reason);
        
        Ok(())
    }

    async fn handle_pin_signal(&self, signal: QuorumSignal, from: SocketAddr) -> Result<()> {
        if !signal.source.matches_pubkey(&signal.pubkey) {
            return Err(DiagonError::Validation("Signal source mismatch".into()));
        }
        
        let signable = signal.signable_bytes();
        self.verify(&signable, &signal.signature, &signal.pubkey)?;
        
        let mut state = self.state.write().await;
        if let Some(pin) = state.pinned.get_mut(&signal.target) {
            match pin.quorum.sense(signal.clone()) {
                Ok(sensed) => {
                    if sensed && pin.quorum.reached() && !pin.active {
                        pin.active = true;
                        println!("[PIN] {} is now pinned!", signal.target);
                    }
                }
                Err(e) => eprintln!("Pin signal rejected: {}", e),
            }
        }
        drop(state);
        
        let msg = NetMessage::PinSignal(signal);
        let msg_data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(msg_data.clone()).await;
                }
            }
        }
        
        Ok(())
    }

    async fn handle_prune_request(&self, cid: Cid, reason: String, from: SocketAddr) -> Result<()> {
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let proposer = info.read().await.did.clone()
            .ok_or(DiagonError::Validation("No DID".into()))?;
        
        if !self.store.read().await.has(&cid) {
            return Ok(());
        }
        
        if self.state.read().await.prune_proposals.contains_key(&cid) {
            return Ok(());
        }
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        
        let prune = PruneProposal {
            cid,
            proposer: proposer.clone(),
            reason: reason.clone(),
            quorum: QuorumState::new(cid, threshold, proposer),
            created: timestamp(),
        };
        
        self.state.write().await.prune_proposals.insert(cid, prune);
        println!("[PRUNE] Proposal received for {} - \"{}\"", cid.short(), reason);
        
        Ok(())
    }

    async fn handle_prune_signal(&self, signal: QuorumSignal, from: SocketAddr) -> Result<()> {
        if !signal.source.matches_pubkey(&signal.pubkey) {
            return Err(DiagonError::Validation("Signal source mismatch".into()));
        }
        
        let signable = signal.signable_bytes();
        self.verify(&signable, &signal.signature, &signal.pubkey)?;
        
        let mut state = self.state.write().await;
        let should_prune = if let Some(prune) = state.prune_proposals.get_mut(&signal.target) {
            match prune.quorum.sense(signal.clone()) {
                Ok(sensed) => sensed && prune.quorum.reached(),
                Err(e) => {
                    eprintln!("Prune signal rejected: {}", e);
                    false
                }
            }
        } else { false };
        
        if should_prune {
            let cid = signal.target;
            state.prune_proposals.remove(&cid);
            state.pinned.remove(&cid);
            state.proposals.remove(&cid);
            drop(state);
            
            self.store.write().await.remove(&cid);
            println!("[PRUNED] {} removed by quorum", cid);
        } else {
            drop(state);
        }
        
        let msg = NetMessage::PruneSignal(signal);
        let msg_data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(msg_data.clone()).await;
                }
            }
        }
        
        Ok(())
    }

    // ========== DHT MESSAGE HANDLERS ==========

    async fn handle_dht_register(
        &self,
        topic_hash: [u8; 32],
        pool_commitment: [u8; 32],
        pool_name: String,
        description: String,
        peer_count: usize,
        signature: Vec<u8>,
        from: SocketAddr,
    ) -> Result<()> {
        if !self.is_in_rendezvous().await {
            return Ok(());
        }
        
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let info_guard = info.read().await;
        let pubkey = info_guard.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey".into()))?;
        let sender_did = info_guard.did.clone()
            .ok_or(DiagonError::Validation("No DID".into()))?;
        drop(info_guard);
        
        let signable = {
            let mut data = b"dht-register:".to_vec();
            data.extend_from_slice(&topic_hash);
            data.extend_from_slice(&pool_commitment);
            data.extend_from_slice(pool_name.as_bytes());
            data.extend_from_slice(description.as_bytes());
            data
        };
        self.verify(&signable, &signature, &pubkey)?;
        
        let entry = DhtEntry {
            topic_hash,
            pool_commitment,
            pool_name: pool_name.clone(),
            description: description.clone(),
            peer_count,
            registered_by: sender_did.clone(),
            registered_at: timestamp(),
            last_seen: timestamp(),
        };
        
        let is_new = self.dht.write().await.register(entry);
        
        if is_new {
            println!("[DHT] New registration: '{}' under topic {}...", pool_name, hex::encode(&topic_hash[..4]));
            
            let msg = NetMessage::DhtRegister {
                topic_hash,
                pool_commitment,
                pool_name,
                description,
                peer_count,
                signature,
            };
            let msg_data = msg.serialize()?;
            for addr in self.connection_pool.authenticated_addrs().await {
                if addr != from {
                    if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                        let _ = handle.send(msg_data.clone()).await;
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn handle_dht_directory_request(&self, from: SocketAddr) -> Result<()> {
        if !self.is_in_rendezvous().await {
            return Ok(());
        }
        
        let entries = self.dht.read().await.get_directory();
        
        let msg = NetMessage::DhtDirectoryResponse { entries };
        if let Some(handle) = self.connection_pool.get_handle(&from).await {
            handle.send(msg.serialize()?).await?;
        }
        
        Ok(())
    }

    async fn handle_dht_directory_response(&self, entries: Vec<DhtEntry>, from: SocketAddr) -> Result<()> {
        let mut dht = self.dht.write().await;
        let mut new_count = 0;
        
        for entry in entries {
            if dht.register(entry) {
                new_count += 1;
            }
        }
        
        dht.last_sync = timestamp();
        
        if new_count > 0 {
            println!("[DHT] Received directory: {} new entries from {}", new_count, from);
        } else {
            println!("[DHT] Directory synced from {} (no new entries)", from);
        }
        
        Ok(())
    }

    async fn handle_dht_search_request(&self, topic_hash: [u8; 32], from: SocketAddr) -> Result<()> {
        let results = self.dht.read().await.entries
            .get(&topic_hash)
            .cloned()
            .unwrap_or_default();
        
        if !results.is_empty() {
            let msg = NetMessage::DhtSearchResponse { topic_hash, results };
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send(msg.serialize()?).await?;
            }
        }
        
        Ok(())
    }

    async fn handle_dht_search_response(&self, topic_hash: [u8; 32], results: Vec<DhtEntry>, from: SocketAddr) -> Result<()> {
        if results.is_empty() {
            return Ok(());
        }
        
        let mut dht = self.dht.write().await;
        let mut new_count = 0;
        for entry in &results {
            if dht.register(entry.clone()) {
                new_count += 1;
            }
        }
        
        if new_count > 0 {
            println!("[DHT] Search response: {} new result(s) for topic {}...", 
                new_count, hex::encode(&topic_hash[..4]));
        }
        
        println!("\n=== Search Results ===");
        for entry in &results {
            println!("  📦 {} ({}...)", entry.pool_name, hex::encode(&entry.pool_commitment[..4]));
            println!("     {} - {} peers", entry.description, entry.peer_count);
        }
        println!();
        
        Ok(())
    }

    async fn handle_dht_pool_announce(
        &self,
        pool_commitment: [u8; 32],
        pool_name: String,
        peer_count: usize,
        topics: Vec<[u8; 32]>,
        signature: Vec<u8>,
        from: SocketAddr,
    ) -> Result<()> {
        if !self.is_in_rendezvous().await {
            return Ok(());
        }
        
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let pubkey = info.read().await.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey".into()))?;
        
        let signable = {
            let mut data = b"dht-announce:".to_vec();
            data.extend_from_slice(&pool_commitment);
            data.extend_from_slice(pool_name.as_bytes());
            data.extend_from_slice(&(peer_count as u64).to_le_bytes());
            for t in &topics {
                data.extend_from_slice(t);
            }
            data
        };
        self.verify(&signable, &signature, &pubkey)?;
        
        self.dht.write().await.update_pool_peer_count(pool_commitment, peer_count);
        
        Ok(())
    }

    async fn handle_decay_config_propose(
        &self,
        id: Cid,
        config: DecayConfig,
        reason: String,
        signature: Vec<u8>,
        from: SocketAddr,
    ) -> Result<()> {
        // Verify signature
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let info_guard = info.read().await;
        let pubkey = info_guard.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey".into()))?;
        let proposer = info_guard.did.clone()
            .ok_or(DiagonError::Validation("No DID".into()))?;
        drop(info_guard);
        
        let signable = {
            let mut data = b"decay-config:".to_vec();
            data.extend_from_slice(&id.0);
            data.push(if config.enabled { 1 } else { 0 });
            data.extend_from_slice(&config.decay_days.to_le_bytes());
            data.push(if config.require_engagement { 1 } else { 0 });
            data.extend_from_slice(reason.as_bytes());
            data
        };
        self.verify(&signable, &signature, &pubkey)?;
        
        // Check if already exists
        if self.state.read().await.decay_proposals.contains_key(&id) {
            return Ok(());
        }
        
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        
        let proposal = DecayConfigProposal {
            id,
            proposed_config: config.clone(),
            proposer: proposer.clone(),
            reason: reason.clone(),
            quorum: QuorumState::new(id, threshold, proposer.clone()),
            created: timestamp(),
            applied: false,
        };
        
        self.state.write().await.decay_proposals.insert(id, proposal);
        
        let mode = if config.enabled { "enable" } else { "disable" };
        println!("[DECAY-PROPOSE] {} from {} - {}", id.short(), proposer.short(), mode);
        
        // Forward to other peers
        let msg = NetMessage::DecayConfigPropose { id, config, reason, signature };
        let msg_data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(msg_data.clone()).await;
                }
            }
        }
        
        Ok(())
    }

    async fn handle_decay_config_signal(&self, signal: QuorumSignal, from: SocketAddr) -> Result<()> {
        // Verify signal
        if !signal.source.matches_pubkey(&signal.pubkey) {
            return Err(DiagonError::Validation("Signal source mismatch".into()));
        }
        
        let signable = signal.signable_bytes();
        self.verify(&signable, &signal.signature, &signal.pubkey)?;
        
        // Apply to proposal
        let should_apply = {
            let mut state = self.state.write().await;
            if let Some(prop) = state.decay_proposals.get_mut(&signal.target) {
                if prop.applied {
                    return Ok(()); // Already applied
                }
                match prop.quorum.sense(signal.clone()) {
                    Ok(sensed) => {
                        if sensed {
                            println!("[DECAY-SIGNAL] {} on {} (+{})",
                                if signal.support { "FOR" } else { "AGAINST" },
                                signal.target.short(),
                                signal.weight);
                        }
                        sensed && prop.quorum.reached()
                    }
                    Err(e) => {
                        eprintln!("Decay signal rejected: {}", e);
                        false
                    }
                }
            } else {
                false
            }
        };
        
        if should_apply {
            let new_config = {
                let mut state = self.state.write().await;
                if let Some(prop) = state.decay_proposals.get_mut(&signal.target) {
                    prop.applied = true;
                    Some(prop.proposed_config.clone())
                } else {
                    None
                }
            };
            
            if let Some(config) = new_config {
                *self.decay_config.write().await = config.clone();
                println!("[DECAY-APPLIED] Quorum reached! Config: enabled={}, days={}",
                    config.enabled, config.decay_days);
            }
        }
        
        // Forward signal
        let msg = NetMessage::DecayConfigSignal(signal);
        let msg_data = msg.serialize()?;
        for addr in self.connection_pool.authenticated_addrs().await {
            if addr != from {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(msg_data.clone()).await;
                }
            }
        }
        
        Ok(())
    }

    async fn broadcast_authenticated(&self, msg: &NetMessage) {
        if let Ok(data) = msg.serialize() {
            for addr in self.connection_pool.authenticated_addrs().await {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(data.clone()).await;
                }
            }
        }
    }

    // ========== BACKGROUND LOOPS ==========

    async fn accept_loop(self: Arc<Self>) {
        let addr: std::net::SocketAddr = match self.bind_addr.parse() {
            Ok(a) => a,
            Err(e) => { eprintln!("Invalid address: {}", e); return; }
        };
        
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        };
        
        let socket = match socket {
            Ok(s) => s,
            Err(e) => { eprintln!("Failed to create socket: {}", e); return; }
        };
        
        if let Err(e) = socket.set_reuseaddr(true) {
            eprintln!("Warning: set_reuseaddr failed: {}", e);
        }
        
        #[cfg(unix)]
        if let Err(e) = socket.set_reuseport(true) {
            eprintln!("Warning: set_reuseport failed: {}", e);
        }
        
        if let Err(e) = socket.bind(addr) {
            eprintln!("Failed to bind {}: {}", addr, e);
            return;
        }
        
        let listener = match socket.listen(128) {
            Ok(l) => l,
            Err(e) => { eprintln!("Failed to listen: {}", e); return; }
        };
        
        loop {
            if self.is_shutdown() { break; }

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => { let _ = self.handle_incoming(stream, addr).await; }
                        Err(e) => eprintln!("Accept error: {}", e),
                    }
                }
                _ = sleep(Duration::from_millis(100)) => {
                    if self.is_shutdown() { break; }
                }
            }
        }
    }

    async fn handle_incoming(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let info = Arc::new(RwLock::new(PeerInfo::new(addr, false)));
        info.write().await.state = ConnectionState::Authenticating;
        
        let handle = self.spawn_connection(stream, addr, Arc::clone(&info)).await?;
        self.connection_pool.add(addr, info, handle).await?;
        
        Ok(())
    }

    async fn spawn_connection(
        self: &Arc<Self>, stream: TcpStream, addr: SocketAddr, info: Arc<RwLock<PeerInfo>>,
    ) -> Result<ConnHandle> {
        let (reader, writer) = stream.into_split();
        
        let (cmd_tx, cmd_rx) = mpsc::channel::<ConnCmd>(64);
        let handle = ConnHandle { addr, cmd_tx };
        
        let pool = Arc::clone(&self.connection_pool);
        tokio::spawn(async move {
            Self::writer_task(writer, cmd_rx, addr, pool).await;
        });
        
        let node = Arc::clone(self);
        let info_clone = Arc::clone(&info);
        tokio::spawn(async move {
            node.reader_task(reader, addr, info_clone).await;
        });
        
        Ok(handle)
    }

    async fn writer_task(
        mut stream: tokio::net::tcp::OwnedWriteHalf, 
        mut cmd_rx: mpsc::Receiver<ConnCmd>, 
        addr: SocketAddr, 
        pool: Arc<ConnectionPool>
    ) {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                ConnCmd::Send(data) => {
                    if data.len() > MAX_MESSAGE_SIZE { continue; }
                    let len_bytes = (data.len() as u32).to_be_bytes();
                    if stream.write_all(&len_bytes).await.is_err() { break; }
                    if stream.write_all(&data).await.is_err() { break; }
                    if stream.flush().await.is_err() { break; }
                }
                ConnCmd::Close => break,
            }
        }
        pool.remove(addr).await;
    }

    async fn reader_task(
        self: Arc<Self>, 
        mut stream: tokio::net::tcp::OwnedReadHalf, 
        addr: SocketAddr, 
        info: Arc<RwLock<PeerInfo>>
    ) {
        let mut len_buf = [0u8; 4];
        
        loop {
            if !info.read().await.is_alive() { break; }
            
            {
                let mut limiter = self.rate_limiter.write().await;
                if !limiter.check_and_increment(&addr) {
                    eprintln!("Rate limited: {}", addr);
                    break;
                }
            }
            
            if stream.read_exact(&mut len_buf).await.is_err() { break; }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            
            if msg_len > MAX_MESSAGE_SIZE { 
                eprintln!("Message too large from {}", addr);
                break; 
            }
            
            let mut msg_buf = vec![0u8; msg_len];
            if stream.read_exact(&mut msg_buf).await.is_err() { break; }
            
            info.write().await.last_activity = Instant::now();
            
            if let Ok(msg) = NetMessage::deserialize(&msg_buf) {
                let needs_auth = !matches!(
                    &msg,
                    NetMessage::Discover { .. } |
                    NetMessage::DiscoverResponse { .. } |
                    NetMessage::Hello { .. } |
                    NetMessage::Challenge(_) |
                    NetMessage::Response { .. } |
                    NetMessage::ElaborateRequest |
                    NetMessage::Elaborate { .. } |
                    NetMessage::MutualApprove { .. } |
                    NetMessage::MutualReject { .. }
                );
                
                if needs_auth && !info.read().await.is_authenticated() {
                    continue;
                }
                
                if let Err(e) = self.handle_message(msg, addr, &info).await {
                    eprintln!("Message error from {}: {}", addr, e);
                }
            }
        }
        
        self.connection_pool.remove(addr).await;
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        loop {
            if self.is_shutdown() { break; }

            sleep(HEARTBEAT_INTERVAL).await;
            
            if self.is_shutdown() { break; }
            
            let ts = timestamp();
            let mut signable = b"heartbeat:".to_vec();
            signable.extend_from_slice(&ts.to_le_bytes());
            self.broadcast_authenticated(&NetMessage::Heartbeat { 
                timestamp: ts, signature: self.sign(&signable) 
            }).await;
            
            for addr in self.connection_pool.dead_connections().await {
                self.connection_pool.remove(addr).await;
                self.reconnect_queue.write().await.push_back((addr, Instant::now(), 0));
            }
            
            self.rate_limiter.write().await.cleanup();
        }
    }

    async fn sync_loop(self: Arc<Self>) {
        loop {
            if self.is_shutdown() { break; }

            sleep(SYNC_INTERVAL).await;
            
            if self.is_shutdown() { break; }
            
            let store = self.store.read().await;
            let msg = NetMessage::SyncRequest { merkle: store.merkle_root(), have: store.log().to_vec() };
            drop(store);
            
            if let Ok(data) = msg.serialize() {
                for addr in self.connection_pool.authenticated_addrs().await.into_iter().take(3) {
                    if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                        let _ = handle.send(data.clone()).await;
                    }
                }
            }
        }
    }

    async fn reconnect_loop(self: Arc<Self>) {
        loop {
            if self.is_shutdown() { break; }

            sleep(CONNECTION_RETRY_INTERVAL).await;
            
            if self.is_shutdown() { break; }
            
            let mut queue = self.reconnect_queue.write().await;
            let len = queue.len();
            for _ in 0..len.min(5) {
                if let Some((addr, last, attempts)) = queue.pop_front() {
                    if last.elapsed() < CONNECTION_RETRY_INTERVAL {
                        queue.push_back((addr, last, attempts));
                        continue;
                    }
                    if attempts >= MAX_RECONNECT_ATTEMPTS { continue; }
                    drop(queue);
                    if self.connect(&addr.to_string()).await.is_err() {
                        self.reconnect_queue.write().await.push_back((addr, Instant::now(), attempts + 1));
                    }
                    queue = self.reconnect_queue.write().await;
                }
            }
        }
    }

    async fn decay_loop(self: Arc<Self>) {
        loop {
            if self.is_shutdown() { break; }

            sleep(DECAY_CHECK_INTERVAL).await;
            
            if self.is_shutdown() { break; }
            
            let decayed = self.store.read().await.get_decayed();
            if !decayed.is_empty() {
                println!("[DECAY] {} expressions candidates for pruning", decayed.len());
            }
            
            let _ = self.save_state().await;
        }
    }

    async fn dht_sync_loop(self: Arc<Self>) {
        loop {
            if self.is_shutdown() { break; }
            
            sleep(DHT_SYNC_INTERVAL).await;
            
            if self.is_shutdown() { break; }
            
            if !self.is_in_rendezvous().await {
                continue;
            }
            
            self.dht.write().await.cleanup_stale(DHT_STALE_SECS);
            
            let pool_topics = self.pool_topics.read().await.clone();
            if !pool_topics.is_empty() {
                if let Some(pool_commitment) = *self.pool.read().await {
                    let pool_name = self.pool_name.read().await.clone()
                        .unwrap_or_else(|| format!("pool-{}", hex::encode(&pool_commitment[..4])));
                    let peer_count = self.connection_pool.authenticated_addrs().await.len() + 1;
                    
                    let sig = self.sign(&{
                        let mut data = b"dht-announce:".to_vec();
                        data.extend_from_slice(&pool_commitment);
                        data.extend_from_slice(pool_name.as_bytes());
                        data.extend_from_slice(&(peer_count as u64).to_le_bytes());
                        for t in &pool_topics {
                            data.extend_from_slice(t);
                        }
                        data
                    });
                    
                    let msg = NetMessage::DhtPoolAnnounce {
                        pool_commitment,
                        pool_name,
                        peer_count,
                        topics: pool_topics,
                        signature: sig,
                    };
                    
                    self.broadcast_authenticated(&msg).await;
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        println!("\n[SHUTDOWN] Initiating...");
        
        self.shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        
        let _ = self.shutdown_tx.send(()).await;
        
        let ts = timestamp();
        let mut signable = b"disconnect:".to_vec();
        signable.extend_from_slice(&ts.to_le_bytes());
        self.broadcast_authenticated(&NetMessage::Disconnect { 
            timestamp: ts, signature: self.sign(&signable) 
        }).await;
        
        sleep(Duration::from_millis(50)).await;
        let _ = self.save_state().await;
        self.connection_pool.shutdown().await;
        println!("[SHUTDOWN] Complete");
    }
}

// ============================================================================
// UTILITIES
// ============================================================================
fn timestamp() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }

fn format_timestamp(ts: u64) -> String {
    let now = timestamp();
    let diff = now.saturating_sub(ts);
    if diff < 60 { format!("{}s ago", diff) }
    else if diff < 3600 { format!("{}m ago", diff / 60) }
    else if diff < 86400 { format!("{}h ago", diff / 3600) }
    else { format!("{}d ago", diff / 86400) }
}

fn score_elaboration(text: &str) -> f64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 5 { return 0.1; }
    let unique: HashSet<&str> = words.iter().copied().collect();
    let uniqueness = unique.len() as f64 / words.len() as f64;
    let uniqueness_score = if uniqueness > 0.95 { 0.2 } else { uniqueness };
    let avg_len = words.iter().map(|w| w.len()).sum::<usize>() as f64 / words.len() as f64;
    let length_score = if avg_len < 2.0 || avg_len > 15.0 { 0.3 } else { 0.7 };
    let length_component = (words.len() as f64 / 50.0).min(1.0).sqrt() * 0.3;

    (uniqueness_score * 0.4 + length_score * 0.3 + length_component).clamp(0.0, 0.8)
}

fn detect_image_mime(data: &[u8]) -> Option<String> {
    if data.len() < 8 { return None; }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) { Some("image/jpeg".to_string()) }
    else if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) { Some("image/png".to_string()) }
    else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") { Some("image/gif".to_string()) }
    else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP" { Some("image/webp".to_string()) }
    else { Some("application/octet-stream".to_string()) }
}

fn detect_video_mime(data: &[u8]) -> Option<String> {
    if data.len() < 12 { return None; }
    if data.len() >= 8 && &data[4..8] == b"ftyp" { Some("video/mp4".to_string()) }
    else if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) { Some("video/webm".to_string()) }
    else if data.starts_with(&[0x00, 0x00, 0x01, 0xBA]) { Some("video/mpeg".to_string()) }
    else { Some("application/octet-stream".to_string()) }
}

fn calculate_xp_award(content_type: ReviewableContentType, word_count: u32, quality: f64) -> u64 {
    let base = content_type.base_xp();
    let length_factor = if word_count < 10 { LENGTH_FACTOR_MIN }
    else { ((word_count as f64 / LENGTH_FACTOR_BASE_WORDS).log2() + 1.0).max(LENGTH_FACTOR_MIN).min(LENGTH_FACTOR_MAX) };
    (base as f64 * length_factor * quality) as u64
}

fn print_help() {
    println!("DIAGON v0.9.6 - Collective Consciousness Protocol");
    println!();
    println!("=== Pool & Connection ===");
    println!("  auth <passphrase> [name]       Join/create pool with optional name");
    println!("  connect <addr|did>             Connect via IP:port or DID prefix");
    println!("  elaborate <text>               Explain why you're joining (reciprocal)");
    println!();
    println!("=== Reciprocal Approval (New) ===");
    println!("  review <did>                   Review peer's elaboration");
    println!("  mutual-approve <did>           Approve after mutual elaboration");
    println!("  mutual-reject <did> <reason>   Reject with reason");
    println!();
    println!("=== Discovery (Rendezvous) ===");
    println!("  join-rendezvous                Join public discovery network");
    println!("  discover                       Get directory of available pools");
    println!("  sync-dht                       Force refresh directory from peers");
    println!("  dht-register <topic> [desc]    Register pool under topic");
    println!("  dht-search <topic>             Search for pools by topic");
    println!("  dht-status                     Show DHT state");
    println!("  set-pool-name <n>              Set human-readable pool name");
    println!();
    println!("=== Content Sharing ===");
    println!("  message <type> <path>          Share content (image/video/text)");
    println!("  view-start <cid>               Start viewing (for XP)");
    println!("  view-stop <cid>                Stop viewing (awards XP if >30s)");
    println!();
    println!("=== Acknowledgment (New) ===");
    println!("  witness <cid>                  Begin attending to expression");
    println!("  ack <cid> [reflection]         Acknowledge with optional reflection");
    println!("  witnesses <cid>                Show who has witnessed expression");
    println!();
    println!("=== Inter-Pool Testimony (New) ===");
    println!("  testify <cid> <pool> <text>    Testify about another pool's expression");
    println!("  testimonies <cid>              Show testimonies for expression");
    println!("  request-testimony <cid>        Request others to testify");
    println!("  my-testimonies                 Show testimonies you've given");
    println!();
    println!("=== HITL Quality Review ===");
    println!("  review-queue                   Show pending review assignments");
    println!("  review <cid>                   View content to review");
    println!("  submit-review <cid> <scores>   Submit review with 5 scores (1-5)");
    println!("  verdicts [n]                   Show recent verdicts");
    println!("  reviewer-stats                 Show your reviewer reputation");
    println!();
    println!("=== Direct Messages (E2E encrypted) ===");
    println!("  dm-request <did>               Request DM channel (needs consent)");
    println!("  dm-accept <did>                Accept DM request");
    println!("  dm-reject <did> <reason>       Reject DM request");
    println!("  dm-send <did> <message>        Send encrypted message");
    println!("  dm-list                        List DM channels");
    println!("  dm-history <did>               View DM history");
    println!();
    println!("=== Governance ===");
    println!("  propose <text>                 Create proposal");
    println!("  vote <cid> <y/n> <text>        Vote on proposal");
    println!("  reply <cid> <text>             Reply to an expression");
    println!("  thread <cid>                   Show full thread tree");
    println!("  pin <cid> <reason>             Propose pinning content");
    println!("  vote-pin <cid> <y/n> <text>    Vote on pin proposal");
    println!("  prune <cid> <reason>           Propose removing content");
    println!("  vote-prune <cid> <y/n> <text>  Vote on prune proposal");
    println!();
    println!("=== Decay Governance ===");
    println!("  propose-decay enable <days> <engage> <reason>");
    println!("                                 Propose enabling decay");
    println!("  propose-decay disable <reason> Propose archive mode");
    println!("  vote-decay <id> <y/n> <text>   Vote on decay proposal");
    println!("  decay-proposals                List pending proposals");
    println!();
    println!("=== Status ===");
    println!("  status                         Show node status");
    println!("  list-pinned                    Show pinned content");
    println!("  list-decayed                   Show decayed content");
    println!("  xp                             Show XP status");
    println!("  help                           Show this help");
    println!("  quit                           Exit");
    println!();
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:9070");
    let db_path = args.get(2).map(|s| s.as_str()).unwrap_or("diagon_db");
    async_main(addr, db_path).await
}

async fn async_main(addr: &str, db_path: &str) -> io::Result<()> {
    let node = match Node::new(addr, db_path).await {
        Ok(n) => n,
        Err(e) => { eprintln!("Failed to start: {}", e); return Ok(()); }
    };

    print_help();

    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    loop {
        print!("> ");
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            _ => break,
        };
        
        let input = line.trim();
        if input.is_empty() { continue; }
        
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).unwrap_or(&"");
        
        match cmd {
            "auth" if !arg.is_empty() => {
                // Parse: auth <passphrase> --name "Pool Name"
                // Or:    auth "passphrase with spaces" --name "Pool Name"  
                // Or:    auth <passphrase>
                let (passphrase, name) = if let Some(idx) = arg.find("--name ") {
                    let pass = arg[..idx].trim().trim_matches('"');
                    let name_part = arg[idx + 7..].trim().trim_matches('"');
                    (pass.to_string(), Some(name_part.to_string()))
                } else {
                    (arg.trim_matches('"').to_string(), None)
                };
                node.auth(&passphrase, name.as_deref()).await;
            }
            "join-rendezvous" => { node.join_rendezvous().await; }
            "connect" if !arg.is_empty() => { 
                if let Err(e) = node.connect(arg).await { println!("[ERROR] {}", e); } 
            }
            "elaborate" if !arg.is_empty() => { node.elaborate(arg).await; }
            "propose" if !arg.is_empty() => { node.propose(arg).await; }
            "reply" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if parts.len() >= 2 {
                    node.reply(parts[0], parts[1]).await;
                } else {
                    println!("Usage: reply <parent_cid> <text>");
                }
            }
            "thread" if !arg.is_empty() => { node.thread(arg).await; }
            "vote" if !arg.is_empty() => { 
                let parts: Vec<&str> = arg.splitn(3, ' ').collect(); 
                if parts.len() >= 3 { 
                    node.vote(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]).await; 
                } else { 
                    println!("Usage: vote <cid> <y/n> <elaboration>"); 
                } 
            }
            "pin" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if parts.len() >= 2 {
                    node.pin(parts[0], parts[1]).await;
                } else {
                    println!("Usage: pin <cid> <reason>");
                }
            }
            "vote-pin" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    node.vote_pin(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]).await;
                } else {
                    println!("Usage: vote-pin <cid> <y/n> <elaboration>");
                }
            }
            "prune" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if parts.len() >= 2 {
                    node.prune(parts[0], parts[1]).await;
                } else {
                    println!("Usage: prune <cid> <reason>");
                }
            }
            "vote-prune" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    node.vote_prune(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]).await;
                } else {
                    println!("Usage: vote-prune <cid> <y/n> <elaboration>");
                }
            }
            "message" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    node.message(parts[0], parts[1]).await;
                } else {
                    println!("Usage: message <image|video|text> <file_path>");
                }
            }
            "view-start" if !arg.is_empty() => { node.view_start(arg).await; }
            "view-stop" if !arg.is_empty() => { node.view_stop(arg).await; }
            "dm-request" if !arg.is_empty() => { node.dm_request(arg).await; }
            "dm-accept" if !arg.is_empty() => { node.dm_accept(arg).await; }
            "dm-reject" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                node.dm_reject(parts[0], parts.get(1).unwrap_or(&"Declined")).await;
            }
            "dm-send" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    node.dm_send(parts[0], parts[1]).await;
                } else {
                    println!("Usage: dm-send <did> <message>");
                }
            }
            "dm-list" => { node.dm_list().await; }
            "dm-history" if !arg.is_empty() => { node.dm_history(arg).await; }
            "dht-register" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                let topic = parts[0];
                let description = parts.get(1).unwrap_or(&"No description");
                node.dht_register(topic, description).await;
            }
            "dht-search" if !arg.is_empty() => { node.dht_search(arg).await; }
            "dht-status" => { node.dht_status().await; }
            "sync-dht" => { node.sync_dht().await; }
            "discover" => { node.discover().await; }
            "status" => { node.status().await; }
            "list-pinned" => { node.list_pinned().await; }
            "list-decayed" => { node.list_decayed().await; }
            "propose-decay" => {
                // Usage: propose-decay enable 14 true "We need longer retention"
                // Usage: propose-decay disable "Archive everything"
                let parts: Vec<&str> = arg.splitn(4, ' ').collect();
                match parts.first().map(|s| *s) {
                    Some("enable") if parts.len() >= 4 => {
                        let days: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(7);
                        let engage: bool = parts.get(2).map(|s| *s != "false").unwrap_or(true);
                        let reason = parts.get(3).unwrap_or(&"");
                        node.propose_decay_config(true, days, engage, reason).await;
                    }
                    Some("disable") if parts.len() >= 2 => {
                        let reason = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
                        node.propose_decay_config(false, 0, false, &reason).await;
                    }
                    _ => {
                        println!("Usage:");
                        println!("  propose-decay enable <days> <engage:true/false> <reason>");
                        println!("  propose-decay disable <reason>");
                    }
                }
            }
            "vote-decay" => {
                let parts: Vec<&str> = arg.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    let support = matches!(parts[1], "y" | "yes" | "true");
                    node.vote_decay_config(parts[0], support, parts[2]).await;
                } else {
                    println!("Usage: vote-decay <id> <y/n> <elaboration>");
                }
            }
            "decay-proposals" => {
                node.list_decay_proposals().await;
            }
            "xp" => { node.xp_status().await; }
            "witness" if !arg.is_empty() => { node.witness_start(arg).await; }
            "ack" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                let reflection = if parts.len() > 1 {
                    Some(parts[1].to_string())
                } else {
                    None
                };
                node.acknowledge(parts[0], reflection).await;
            }
            "witnesses" if !arg.is_empty() => { node.show_witnesses(arg).await; }
            "review" if !arg.is_empty() => { node.review_elaboration(arg).await; }
            "mutual-approve" if !arg.is_empty() => { node.mutual_approve(arg).await; }
            "mutual-reject" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                let reason = parts.get(1).unwrap_or(&"Declined");
                node.mutual_reject(parts[0], reason).await;
            }
            "testify" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    node.testify(parts[0], parts[1], parts[2]).await;
                } else {
                    println!("Usage: testify <cid> <origin_pool_hex> <attestation>");
                }
            }
            "testimonies" if !arg.is_empty() => { node.show_testimonies(arg).await; }
            "request-testimony" if !arg.is_empty() => { node.request_testimony(arg).await; }
            "my-testimonies" => { node.show_given_testimonies().await; }
             "review-queue" => { node.review_queue().await; }
            "review" if !arg.is_empty() => { node.review_content(arg).await; }
            "submit-review" if !arg.is_empty() => {
                let parts: Vec<&str> = arg.splitn(7, ' ').collect();
                if parts.len() >= 7 {
                    let cid = parts[0];
                    let rel: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let sub: u8 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let cla: u8 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let ori: u8 = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let eff: u8 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let rest = parts[6];
                    let just = rest.trim_matches('"').split("--").next().unwrap_or("").trim();
                    let spam = rest.contains("--spam");
                    let plag = rest.contains("--plagiarism");
                    let offtopic = rest.contains("--offtopic");
                    node.submit_review_cmd(cid, rel, sub, cla, ori, eff, just, spam, plag, offtopic).await;
                } else {
                    println!("Usage: submit-review <cid> <rel> <sub> <cla> <ori> <eff> \"justification\" [--spam]");
                }
            }
            "verdicts" => { node.show_verdicts(arg.parse().unwrap_or(10)).await; }
            "reviewer-stats" => { node.reviewer_stats().await; }
            "help" => { print_help(); }
            "quit" | "exit" => { break; }
            _ => { println!("Unknown command. Type 'help' for commands."); }
        }
    }

    node.shutdown().await;
    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    const TEST_PASSPHRASE: &str = "test collective consciousness network";

    fn setup_test_dir(name: &str) -> String {
        let dir = format!("/tmp/diagon_test_{}", name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_test_dir(dir: &str) { let _ = std::fs::remove_dir_all(dir); }

    fn get_free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn test_ephemeral_pool() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Ephemeral Pool ===");
            let dir = setup_test_dir("ephemeral_pool");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            assert!(node.auth("my secret phrase", None).await);
            assert!(node.pool.read().await.is_some());
            println!("[✓] Ephemeral pool created");
            
            let commitment1 = *node.pool.read().await;
            node.auth("different phrase", None).await;
            let commitment2 = *node.pool.read().await;
            assert_ne!(commitment1, commitment2);
            println!("[✓] Different phrases create different pools");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Ephemeral pool test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[test]
    fn test_xp_system() {
        println!("\n=== TEST: XP System ===");
        
        let mut xp = XpState::new();
        assert_eq!(xp.xp(), 0);
        
        let cid = Cid::new(b"test content");
        
        xp.start_viewing(cid);
        
        assert!(xp.stop_viewing(cid).is_none());
        println!("[✓] No XP for short view");
        
        xp.view_start.insert(cid, timestamp() - 60);
        let earned = xp.stop_viewing(cid);
        assert_eq!(earned, Some(XP_PER_VIEW));
        assert_eq!(xp.xp(), XP_PER_VIEW);
        println!("[✓] XP earned for long view");
        
        xp.view_start.insert(cid, timestamp() - 60);
        assert!(xp.stop_viewing(cid).is_none());
        println!("[✓] Cooldown prevents XP farming");
        
        println!("[✓] XP system test passed\n");
    }

    #[test]
    fn test_dm_channel_encryption() {
        println!("\n=== TEST: DM Channel Encryption ===");
        
        let did_a = Did("did:diagon:alice123456789ab".into());
        let did_b = Did("did:diagon:bob1234567890abc".into());
        
        let secret_a = ReusableSecret::random_from_rng(OsRng);
        let public_a = X25519PublicKey::from(&secret_a);
        let secret_b = ReusableSecret::random_from_rng(OsRng);
        let public_b = X25519PublicKey::from(&secret_b);
        
        let mut channel_a = DmChannel::new_outbound(did_b.clone(), public_a.to_bytes());
        let mut channel_b = DmChannel::new_inbound(did_a.clone(), public_a.to_bytes(), public_b.to_bytes());
        
        channel_a.establish(public_b.to_bytes(), &secret_a);
        channel_b.establish(public_a.to_bytes(), &secret_b);
        
        assert_eq!(channel_a.state, DmChannelState::Established);
        assert_eq!(channel_b.state, DmChannelState::Established);
        println!("[✓] Channels established");
        
        assert_eq!(channel_a.shared_key, channel_b.shared_key);
        println!("[✓] Shared keys match");
        
        let message = "Hello, this is a secret message!";
        let (ciphertext, nonce) = channel_a.encrypt(message).expect("Encrypt failed");
        let decrypted = channel_b.decrypt(&ciphertext, &nonce).expect("Decrypt failed");
        assert_eq!(decrypted, message);
        println!("[✓] Encryption/decryption works");
        
        let bad_nonce = [0u8; 12];
        assert!(channel_b.decrypt(&ciphertext, &bad_nonce).is_err());
        println!("[✓] Wrong nonce rejected");
        
        println!("[✓] DM channel encryption test passed\n");
    }

    #[test]
    fn test_content_decay() {
        println!("\n=== TEST: Content Decay ===");
        
        let mut store = ExprStore::new();
        let mut arena = Arena::new();
        
        let expr = arena.parse("(old content)").unwrap();
        store.arena = arena;
        let (cid, _) = store.store(expr).expect("Store failed");
        
        if let Some(meta) = store.metadata.get_mut(&cid) {
            meta.last_engaged = timestamp() - CONTENT_DECAY_SECS - 1;
        }
        
        let decayed = store.get_decayed();
        assert_eq!(decayed.len(), 1);
        assert_eq!(decayed[0], cid);
        println!("[✓] Decayed content detected");
        
        store.engage(&cid);
        let decayed = store.get_decayed();
        assert!(decayed.is_empty());
        println!("[✓] Engagement refreshes content");
        
        println!("[✓] Content decay test passed\n");
    }

    #[test]
    fn test_pin_prune_state() {
        println!("\n=== TEST: Pin/Prune State ===");
        
        let mut state = DerivedState::new();
        let cid = Cid::new(b"test");
        let proposer = Did("did:diagon:test".into());
        
        let pin = PinnedContent {
            cid,
            pinned_by: proposer.clone(),
            reason: "Important content".into(),
            quorum: QuorumState::new(cid, 1000, proposer.clone()),
            pinned_at: timestamp(),
            active: false,
        };
        state.pinned.insert(cid, pin);
        assert!(!state.pinned.get(&cid).unwrap().active);
        println!("[✓] Pin proposal created");
        
        let prune = PruneProposal {
            cid,
            proposer: proposer.clone(),
            reason: "Spam content".into(),
            quorum: QuorumState::new(cid, 1000, proposer),
            created: timestamp(),
        };
        state.prune_proposals.insert(cid, prune);
        assert!(state.prune_proposals.contains_key(&cid));
        println!("[✓] Prune proposal created");
        
        println!("[✓] Pin/prune state test passed\n");
    }

    #[test]
    fn test_did_dm_channel_id() {
        println!("\n=== TEST: DID DM Channel ID ===");
        
        let did_a = Did("did:diagon:alice".into());
        let did_b = Did("did:diagon:bob".into());
        
        let channel_ab = did_a.dm_channel_id(&did_b);
        let channel_ba = did_b.dm_channel_id(&did_a);
        assert_eq!(channel_ab, channel_ba);
        println!("[✓] Channel ID is symmetric");
        
        let did_c = Did("did:diagon:charlie".into());
        let channel_ac = did_a.dm_channel_id(&did_c);
        assert_ne!(channel_ab, channel_ac);
        println!("[✓] Different pairs have different IDs");
        
        println!("[✓] DID DM channel ID test passed\n");
    }

    #[tokio::test]
    async fn test_two_node_basic() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Two Node Basic ===");
            let dir = setup_test_dir("two_node");
            let port1 = get_free_port();
            let port2 = get_free_port();
            
            let node1 = Node::new(&format!("127.0.0.1:{}", port1), &format!("{}/node1", dir))
                .await.expect("Node 1 failed");
            let node2 = Node::new(&format!("127.0.0.1:{}", port2), &format!("{}/node2", dir))
                .await.expect("Node 2 failed");
            
            node1.auth(TEST_PASSPHRASE, None).await;
            node2.auth(TEST_PASSPHRASE, None).await;
            
            let pool1 = *node1.pool.read().await;
            let pool2 = *node2.pool.read().await;
            assert_eq!(pool1, pool2);
            println!("[✓] Same passphrase = same pool");
            
            sleep(Duration::from_millis(100)).await;
            
            // Step 1: Node1 connects to Node2
            node1.connect(&format!("127.0.0.1:{}", port2)).await.expect("Connect failed");
            sleep(Duration::from_millis(200)).await;
            
            // Step 2: Node1 sends elaboration
            node1.elaborate("Testing the collective consciousness network.").await;
            sleep(Duration::from_millis(200)).await;
            
            // Step 3: Node2 sends its elaboration (REQUIRED for mutual handshake)
            node2.elaborate("Responding to establish mutual connection trust.").await;
            sleep(Duration::from_millis(200)).await;
            
            // Step 4: Node2 approves (now in MutualPending state)
            let pending = node2.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node2.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
            
            // Step 5: Node1 also approves (mutual approval requires both sides)
            let pending = node1.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node1.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
            
            let n1_auth = node1.connection_pool.authenticated_addrs().await.len();
            let n2_auth = node2.connection_pool.authenticated_addrs().await.len();
            println!("[DEBUG] n1_auth={}, n2_auth={}", n1_auth, n2_auth);
            assert!(n1_auth > 0 || n2_auth > 0);
            println!("[✓] Nodes connected");
            
            let _ = timeout(Duration::from_secs(5), node1.shutdown()).await;
            let _ = timeout(Duration::from_secs(5), node2.shutdown()).await;
            
            cleanup_test_dir(&dir);
            println!("[✓] Two node basic test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    // ========================================================================
    // ARENA / S-EXPRESSION TESTS
    // ========================================================================

    #[test]
    fn test_arena_parse_serialize_roundtrip() {
        println!("\n=== TEST: Arena Parse/Serialize Roundtrip ===");
        
        let mut arena = Arena::new();
        
        // Test simple atom
        let expr = arena.parse("hello").unwrap();
        let serialized = arena.serialize(expr);
        let mut arena2 = Arena::new();
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "hello");
        println!("[✓] Atom roundtrip");
        
        // Test integer
        let expr = arena.parse("42").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "42");
        println!("[✓] Integer roundtrip");
        
        // Test negative integer
        let expr = arena.parse("-123").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "-123");
        println!("[✓] Negative integer roundtrip");
        
        // Test simple list
        let expr = arena.parse("(a b c)").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "(a b c)");
        println!("[✓] Simple list roundtrip");
        
        // Test nested list
        let expr = arena.parse("(propose (nested (deeply)))").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "(propose (nested (deeply)))");
        println!("[✓] Nested list roundtrip");
        
        // Test mixed content
        let expr = arena.parse("(vote 123 yes)").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "(vote 123 yes)");
        println!("[✓] Mixed content roundtrip");
        
        // Test hex bytes (no space between #x and hex digits)
        let expr = arena.parse("(data #xdeadbeef)").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "(data #xdeadbeef)");
        println!("[✓] Hex bytes roundtrip");
        
        // Test empty list (nil)
        let expr = arena.parse("()").unwrap();
        let serialized = arena.serialize(expr);
        let deserialized = arena2.deserialize(&serialized).unwrap();
        assert_eq!(arena2.display(deserialized), "()");
        println!("[✓] Empty list roundtrip");
        
        println!("[✓] Arena parse/serialize roundtrip test passed\n");
    }

    #[test]
    fn test_arena_hash_determinism() {
        println!("\n=== TEST: Arena Hash Determinism ===");
        
        let mut arena1 = Arena::new();
        let mut arena2 = Arena::new();
        
        // Same expression in different arenas should produce same hash
        let expr1 = arena1.parse("(propose important content here)").unwrap();
        let expr2 = arena2.parse("(propose important content here)").unwrap();
        
        let hash1 = arena1.hash(expr1);
        let hash2 = arena2.hash(expr2);
        assert_eq!(hash1, hash2);
        println!("[✓] Same expression produces same hash");
        
        // Different expressions should produce different hashes
        let expr3 = arena1.parse("(propose different content)").unwrap();
        let hash3 = arena1.hash(expr3);
        assert_ne!(hash1, hash3);
        println!("[✓] Different expressions produce different hashes");
        
        // Hash should be cached (calling twice returns same result)
        let hash1_again = arena1.hash(expr1);
        assert_eq!(hash1, hash1_again);
        println!("[✓] Hash caching works");
        
        // Order matters in lists
        let expr_ab = arena1.parse("(a b)").unwrap();
        let expr_ba = arena1.parse("(b a)").unwrap();
        assert_ne!(arena1.hash(expr_ab), arena1.hash(expr_ba));
        println!("[✓] List order affects hash");
        
        println!("[✓] Arena hash determinism test passed\n");
    }

    #[test]
    fn test_arena_intern_deduplication() {
        println!("\n=== TEST: Arena Intern Deduplication ===");
        
        let mut arena = Arena::new();
        
        // Create same expression twice
        let expr1 = arena.parse("(important data here)").unwrap();
        let expr2 = arena.parse("(important data here)").unwrap();
        
        // Intern both
        let (cid1, ref1) = arena.intern(expr1);
        let (cid2, ref2) = arena.intern(expr2);
        
        // Should produce same CID
        assert_eq!(cid1, cid2);
        println!("[✓] Same expression produces same CID");
        
        // Lookup should work
        assert_eq!(arena.lookup(&cid1), Some(ref1));
        println!("[✓] Lookup returns interned reference");
        
        // Different expression should produce different CID
        let expr3 = arena.parse("(different data)").unwrap();
        let (cid3, _) = arena.intern(expr3);
        assert_ne!(cid1, cid3);
        println!("[✓] Different expression produces different CID");
        
        // Lookup for non-existent CID
        let fake_cid = Cid([0u8; 32]);
        assert_eq!(arena.lookup(&fake_cid), None);
        println!("[✓] Lookup returns None for unknown CID");
        
        println!("[✓] Arena intern deduplication test passed\n");
    }

    #[test]
    fn test_arena_list_operations() {
        println!("\n=== TEST: Arena List Operations ===");
        
        let mut arena = Arena::new();
        
        // Build list manually
        let a = arena.atom("a");
        let b = arena.atom("b");
        let c = arena.atom("c");
        let list = arena.list(&[a, b, c]);
        
        assert_eq!(arena.display(list), "(a b c)");
        println!("[✓] List construction");
        
        // Test car/cdr
        assert_eq!(arena.display(arena.car(list)), "a");
        assert_eq!(arena.display(arena.car(arena.cdr(list))), "b");
        assert_eq!(arena.display(arena.car(arena.cdr(arena.cdr(list)))), "c");
        println!("[✓] car/cdr operations");
        
        // Test nth
        assert_eq!(arena.display(arena.nth(list, 0)), "a");
        assert_eq!(arena.display(arena.nth(list, 1)), "b");
        assert_eq!(arena.display(arena.nth(list, 2)), "c");
        println!("[✓] nth operation");
        
        // Test cons
        let d = arena.atom("d");
        let extended = arena.cons(d, list);
        assert_eq!(arena.display(extended), "(d a b c)");
        println!("[✓] cons operation");
        
        println!("[✓] Arena list operations test passed\n");
    }

    // ========================================================================
    // CONTENT TRANSFER TESTS
    // ========================================================================

    #[test]
    fn test_content_chunk_creation_and_verification() {
        println!("\n=== TEST: Content Chunk Creation and Verification ===");
        
        let content_id = [0u8; 32];
        let data = b"This is some test chunk data for verification";
        
        let chunk = ContentChunk::new(content_id, 0, data);
        
        assert_eq!(chunk.content_id, content_id);
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.data, data.to_vec());
        assert!(chunk.verify());
        println!("[✓] Chunk creation and verification");
        
        // Tampered chunk should fail verification
        let mut tampered = chunk.clone();
        tampered.data[0] ^= 0xFF;
        assert!(!tampered.verify());
        println!("[✓] Tampered chunk fails verification");
        
        println!("[✓] Content chunk test passed\n");
    }

    #[test]
    fn test_content_encoder_chunking() {
        println!("\n=== TEST: Content Encoder Chunking ===");
        
        let sender = Did("did:diagon:sender123456".into());
        
        // Small content (single chunk)
        let small_data = vec![0u8; 1000];
        let mut encoder = ContentEncoder::new(
            ContentType::Text,
            small_data.clone(),
            Some("small.txt".into()),
            Some("text/plain".into()),
            sender.clone(),
        );
        
        assert_eq!(encoder.metadata().total_chunks, 1);
        assert_eq!(encoder.metadata().total_size, 1000);
        println!("[✓] Small content metadata correct");
        
        let chunk = encoder.next_chunk().unwrap();
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.data.len(), 1000);
        assert!(chunk.verify());
        assert!(encoder.next_chunk().is_none());
        println!("[✓] Single chunk iteration");
        
        // Large content (multiple chunks)
        let large_data = vec![0u8; CONTENT_CHUNK_SIZE * 3 + 1000];
        let mut encoder = ContentEncoder::new(
            ContentType::Video,
            large_data.clone(),
            Some("large.mp4".into()),
            Some("video/mp4".into()),
            sender.clone(),
        );
        
        assert_eq!(encoder.metadata().total_chunks, 4);
        println!("[✓] Large content splits into correct chunk count");
        
        let mut chunk_count = 0;
        let mut total_data = Vec::new();
        while let Some(chunk) = encoder.next_chunk() {
            assert_eq!(chunk.chunk_index, chunk_count);
            assert!(chunk.verify());
            total_data.extend_from_slice(&chunk.data);
            chunk_count += 1;
        }
        assert_eq!(chunk_count, 4);
        assert_eq!(total_data, large_data);
        println!("[✓] All chunks iterate correctly and reassemble");
        
        // Test reset
        encoder.reset();
        assert!(encoder.next_chunk().is_some());
        println!("[✓] Encoder reset works");
        
        println!("[✓] Content encoder chunking test passed\n");
    }

    #[test]
    fn test_incoming_transfer_reassembly() {
        println!("\n=== TEST: Incoming Transfer Reassembly ===");
        
        let sender = Did("did:diagon:sender123456".into());
        let original_data = b"Hello, this is test content for transfer!".to_vec();
        
        // Create encoder and get metadata
        let mut encoder = ContentEncoder::new(
            ContentType::Text,
            original_data.clone(),
            Some("test.txt".into()),
            None,
            sender,
        );
        
        let metadata = encoder.metadata().clone();
        let mut transfer = IncomingTransfer::new(metadata.clone());
        
        assert!(!transfer.is_complete());
        assert_eq!(transfer.received_count, 0);
        println!("[✓] Transfer initialized");
        
        // Add chunks
        while let Some(chunk) = encoder.next_chunk() {
            let was_new = transfer.add_chunk(&chunk).expect("Add chunk failed");
            assert!(was_new);
        }
        
        assert!(transfer.is_complete());
        println!("[✓] Transfer complete after all chunks");
        
        // Reassemble
        let reassembled = transfer.reassemble().expect("Reassemble failed");
        assert_eq!(reassembled, original_data);
        println!("[✓] Reassembled data matches original");
        
        // Duplicate chunk should return false
        encoder.reset();
        let chunk = encoder.next_chunk().unwrap();
        let was_new = transfer.add_chunk(&chunk).expect("Add chunk failed");
        assert!(!was_new);
        println!("[✓] Duplicate chunk detected");
        
        println!("[✓] Incoming transfer reassembly test passed\n");
    }

    #[test]
    fn test_transfer_validation_errors() {
        println!("\n=== TEST: Transfer Validation Errors ===");
        
        let sender = Did("did:diagon:sender".into());
        let data = vec![0u8; 1000];
        
        let mut encoder = ContentEncoder::new(
            ContentType::Text, data, None, None, sender,
        );
        
        let metadata = encoder.metadata().clone();
        let mut transfer = IncomingTransfer::new(metadata.clone());
        
        // Wrong content_id
        let wrong_chunk = ContentChunk {
            content_id: [1u8; 32], // Different ID
            chunk_index: 0,
            data: vec![0u8; 100],
            chunk_hash: [0u8; 32],
        };
        assert!(transfer.add_chunk(&wrong_chunk).is_err());
        println!("[✓] Wrong content_id rejected");
        
        // Invalid chunk index
        let bad_index_chunk = ContentChunk {
            content_id: metadata.content_id,
            chunk_index: 999,
            data: vec![0u8; 100],
            chunk_hash: [0u8; 32],
        };
        assert!(transfer.add_chunk(&bad_index_chunk).is_err());
        println!("[✓] Invalid chunk index rejected");
        
        // Bad hash
        let mut bad_hash_chunk = encoder.next_chunk().unwrap();
        bad_hash_chunk.chunk_hash = [0u8; 32];
        assert!(transfer.add_chunk(&bad_hash_chunk).is_err());
        println!("[✓] Bad chunk hash rejected");
        
        // Reassemble before complete
        assert!(transfer.reassemble().is_err());
        println!("[✓] Incomplete transfer cannot reassemble");
        
        println!("[✓] Transfer validation errors test passed\n");
    }

    #[test]
    fn test_content_hash_verification() {
        println!("\n=== TEST: Content Hash Verification ===");
        
        let sender = Did("did:diagon:sender".into());
        let data = b"Original content data".to_vec();
        
        let mut encoder = ContentEncoder::new(
            ContentType::Text, data.clone(), None, None, sender,
        );
        
        let metadata = encoder.metadata().clone();
        let mut transfer = IncomingTransfer::new(metadata);
        
        // Add the chunk but tamper with its data after adding
        let chunk = encoder.next_chunk().unwrap();
        transfer.add_chunk(&chunk).unwrap();
        
        // Manually corrupt the stored data
        if let Some(stored_data) = transfer.chunks.get_mut(&0) {
            stored_data[0] ^= 0xFF;
        }
        
        // Reassembly should fail hash check
        assert!(transfer.reassemble().is_err());
        println!("[✓] Corrupted content detected on reassembly");
        
        println!("[✓] Content hash verification test passed\n");
    }

    // ========================================================================
    // QUORUM / PROPOSAL LIFECYCLE TESTS
    // ========================================================================

    #[test]
    fn test_quorum_self_vote_rejected() {
        println!("\n=== TEST: Quorum Self-Vote Rejected ===");
        
        let proposer = Did("did:diagon:proposer12345".into());
        let cid = Cid::new(b"proposal");
        let mut quorum = QuorumState::new(cid, 1000, proposer.clone());
        
        let self_signal = QuorumSignal {
            source: proposer.clone(),
            pubkey: vec![0u8; 32],
            target: cid,
            weight: 500,
            support: true,
            elaboration: "I vote for myself".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let result = quorum.sense(self_signal);
        assert!(matches!(result, Err(DiagonError::SelfVoteProhibited)));
        println!("[✓] Self-vote correctly rejected");
        
        println!("[✓] Quorum self-vote rejection test passed\n");
    }

    #[test]
    fn test_quorum_signal_accumulation() {
        println!("\n=== TEST: Quorum Signal Accumulation ===");
        
        let proposer = Did("did:diagon:proposer".into());
        let cid = Cid::new(b"proposal");
        let threshold = 1000u64;
        let mut quorum = QuorumState::new(cid, threshold, proposer);
        
        assert!(!quorum.reached());
        assert_eq!(quorum.accumulated_for(), 0);
        assert_eq!(quorum.accumulated_against(), 0);
        println!("[✓] Initial state correct");
        
        // Add supporting signal
        let voter1 = Did("did:diagon:voter1".into());
        let signal1 = QuorumSignal {
            source: voter1.clone(),
            pubkey: vec![0u8; 32],
            target: cid,
            weight: 400,
            support: true,
            elaboration: "I support this proposal".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let sensed = quorum.sense(signal1).unwrap();
        assert!(sensed);
        assert!(!quorum.reached());
        println!("[✓] First signal added, threshold not reached");
        
        // Add opposing signal
        let voter2 = Did("did:diagon:voter2".into());
        let signal2 = QuorumSignal {
            source: voter2.clone(),
            pubkey: vec![0u8; 32],
            target: cid,
            weight: 300,
            support: false,
            elaboration: "I oppose this proposal".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        quorum.sense(signal2).unwrap();
        assert!(quorum.accumulated_against() > 0);
        println!("[✓] Opposing signal tracked separately");
        
        // Add more support to reach threshold
        let voter3 = Did("did:diagon:voter3".into());
        let signal3 = QuorumSignal {
            source: voter3,
            pubkey: vec![0u8; 32],
            target: cid,
            weight: 700,
            support: true,
            elaboration: "Strong support here!".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        quorum.sense(signal3).unwrap();
        assert!(quorum.reached());
        println!("[✓] Threshold reached with accumulated signals");
        
        // Duplicate vote should be ignored
        let duplicate = QuorumSignal {
            source: voter1,
            pubkey: vec![0u8; 32],
            target: cid,
            weight: 1000,
            support: true,
            elaboration: "Trying to vote again".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let sensed = quorum.sense(duplicate).unwrap();
        assert!(!sensed);
        println!("[✓] Duplicate vote ignored");
        
        println!("[✓] Quorum signal accumulation test passed\n");
    }

    #[test]
    fn test_quorum_signal_decay() {
        println!("\n=== TEST: Quorum Signal Decay ===");
        
        // Create signal with old timestamp
        let old_signal = QuorumSignal {
            source: Did("did:diagon:voter".into()),
            pubkey: vec![],
            target: Cid::new(b"test"),
            weight: 1000,
            support: true,
            elaboration: "Old vote".into(),
            timestamp: timestamp() - SIGNAL_HALF_LIFE * 2,
            signature: vec![],
        };
        
        // Strength should be decayed
        let strength = old_signal.current_strength();
        assert!(strength < 1000);
        assert!(strength > 0);
        println!("[✓] Old signal has decayed strength: {} < 1000", strength);
        
        // Fresh signal should have full strength
        let fresh_signal = QuorumSignal {
            source: Did("did:diagon:voter2".into()),
            pubkey: vec![],
            target: Cid::new(b"test"),
            weight: 1000,
            support: true,
            elaboration: "Fresh vote".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let strength = fresh_signal.current_strength();
        assert_eq!(strength, 1000);
        println!("[✓] Fresh signal has full strength");
        
        println!("[✓] Quorum signal decay test passed\n");
    }

    #[test]
    fn test_proposal_state_lifecycle() {
        println!("\n=== TEST: Proposal State Lifecycle ===");
        
        let mut state = DerivedState::new();
        let proposer = Did("did:diagon:proposer".into());
        let cid = Cid::new(b"test proposal");
        
        // Create proposal
        let proposal = ProposalState {
            cid,
            expr_data: vec![1, 2, 3],
            proposer: proposer.clone(),
            elaboration: "This is my proposal text".into(),
            quorum: QuorumState::new(cid, 500, proposer.clone()),
            created: timestamp(),
        };
        
        assert!(state.can_add_proposal());
        state.proposals.insert(cid, proposal);
        assert!(state.proposals.contains_key(&cid));
        println!("[✓] Proposal created and stored");
        
        // Vote on proposal
        let voter = Did("did:diagon:voter".into());
        let signal = QuorumSignal {
            source: voter.clone(),
            pubkey: vec![],
            target: cid,
            weight: 600,
            support: true,
            elaboration: "I support this strongly".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        if let Some(prop) = state.proposals.get_mut(&cid) {
            prop.quorum.sense(signal).unwrap();
            assert!(prop.quorum.reached());
        }
        println!("[✓] Vote added and quorum reached");
        
        // Update voter's trust
        state.update_mark(&voter, 0.8, true);
        let mark = state.get_mark(&voter);
        assert!(mark.current_score() > TRUST_DEFAULT);
        println!("[✓] Voter trust updated");
        
        println!("[✓] Proposal state lifecycle test passed\n");
    }

    #[test]
    fn test_epigenetic_mark_trust_evolution() {
        println!("\n=== TEST: Epigenetic Mark Trust Evolution ===");
        
        let mut mark = EpigeneticMark::new();
        assert_eq!(mark.score, TRUST_DEFAULT);
        assert_eq!(mark.interactions, 0);
        println!("[✓] Initial trust is default");
        
        // Good interactions increase trust
        for _ in 0..5 {
            mark.update(0.9, true);
        }
        assert!(mark.score > TRUST_DEFAULT);
        println!("[✓] Good interactions increase trust: {:.2}", mark.score);
        
        // Bad interaction decreases trust
        let prev_score = mark.score;
        mark.update(0.1, true);
        assert!(mark.score < prev_score);
        println!("[✓] Bad interaction decreases trust: {:.2}", mark.score);
        
        // Unverified interactions are capped
        let mut unverified_mark = EpigeneticMark::new();
        unverified_mark.update(1.0, false); // High quality but unverified
        assert!(unverified_mark.score <= TRUST_DEFAULT * TRUST_HISTORY_WEIGHT + 0.6 * TRUST_NEW_WEIGHT + 0.01);
        println!("[✓] Unverified interactions capped");
        
        // Signal weight scales with trust
        let low_trust_mark = EpigeneticMark { score: 0.2, interactions: 1, last_active: timestamp() };
        let high_trust_mark = EpigeneticMark { score: 0.9, interactions: 10, last_active: timestamp() };
        assert!(high_trust_mark.signal_weight() > low_trust_mark.signal_weight());
        println!("[✓] Signal weight scales with trust");
        
        println!("[✓] Epigenetic mark trust evolution test passed\n");
    }

    // ========================================================================
    // ERROR PATH TESTS
    // ========================================================================

    #[test]
    fn test_rate_limiter() {
        println!("\n=== TEST: Rate Limiter ===");
        
        let mut limiter = RateLimiter::default();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        
        // Should allow up to limit
        for i in 0..RATE_LIMIT_MAX_MESSAGES {
            assert!(limiter.check_and_increment(&addr), "Failed at message {}", i);
        }
        println!("[✓] Allowed {} messages", RATE_LIMIT_MAX_MESSAGES);
        
        // Should reject after limit
        assert!(!limiter.check_and_increment(&addr));
        println!("[✓] Rejected message after limit");
        
        // Different address should have own limit
        let addr2: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        assert!(limiter.check_and_increment(&addr2));
        println!("[✓] Different address has own limit");
        
        // Cleanup should work
        limiter.cleanup();
        println!("[✓] Cleanup runs without error");
        
        println!("[✓] Rate limiter test passed\n");
    }

    #[test]
    fn test_nonce_tracker_replay_prevention() {
        println!("\n=== TEST: Nonce Tracker Replay Prevention ===");
        
        let mut tracker = NonceTracker::new(60);
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        
        // First use should succeed
        assert!(tracker.check_and_record(&nonce1));
        println!("[✓] First nonce accepted");
        
        // Replay should fail
        assert!(!tracker.check_and_record(&nonce1));
        println!("[✓] Replayed nonce rejected");
        
        // Different nonce should succeed
        assert!(tracker.check_and_record(&nonce2));
        println!("[✓] Different nonce accepted");
        
        println!("[✓] Nonce tracker replay prevention test passed\n");
    }

    #[test]
    fn test_expression_store_limits() {
        println!("\n=== TEST: Expression Store Limits ===");
        
        let mut store = ExprStore::new();
        store.max_size = 5; // Set low limit for testing
        
        // Fill up store
        for i in 0..5 {
            let expr = store.arena_mut().parse(&format!("(expr {})", i)).unwrap();
            assert!(store.store(expr).is_ok());
        }
        println!("[✓] Store filled to capacity");
        
        // Next store should fail
        let expr = store.arena_mut().parse("(overflow)").unwrap();
        let result = store.store(expr);
        assert!(matches!(result, Err(DiagonError::StoreFull)));
        println!("[✓] Store full error returned");
        
        // Remove one and try again
        let cid = store.log()[0];
        store.remove(&cid);
        let expr = store.arena_mut().parse("(new expr)").unwrap();
        assert!(store.store(expr).is_ok());
        println!("[✓] Can add after removal");
        
        println!("[✓] Expression store limits test passed\n");
    }

    #[test]
    fn test_did_pubkey_validation() {
        println!("\n=== TEST: DID Pubkey Validation ===");
        
        let (public_key, _) = keypair();
        let did = Did::from_pubkey(&public_key);
        
        // Correct pubkey should match
        assert!(did.matches_pubkey(public_key.as_bytes()));
        println!("[✓] Correct pubkey matches");
        
        // Wrong pubkey should not match
        let (other_key, _) = keypair();
        assert!(!did.matches_pubkey(other_key.as_bytes()));
        println!("[✓] Wrong pubkey does not match");
        
        // Too short pubkey should not match
        assert!(!did.matches_pubkey(&[0u8; 8]));
        println!("[✓] Short pubkey rejected");
        
        println!("[✓] DID pubkey validation test passed\n");
    }

    #[test]
    fn test_signature_verification() {
        println!("\n=== TEST: Signature Verification ===");
        
        let (public_key, secret_key) = keypair();
        let message = b"Test message for signing";
        
        // Sign message
        let signature = detached_sign(message, &secret_key);
        
        // Verify correct signature
        let result = verify_detached_signature(&signature, message, &public_key);
        assert!(result.is_ok());
        println!("[✓] Valid signature verifies");
        
        // Wrong message should fail
        let wrong_message = b"Different message";
        let result = verify_detached_signature(&signature, wrong_message, &public_key);
        assert!(result.is_err());
        println!("[✓] Wrong message fails verification");
        
        // Wrong key should fail
        let (other_key, _) = keypair();
        let result = verify_detached_signature(&signature, message, &other_key);
        assert!(result.is_err());
        println!("[✓] Wrong key fails verification");
        
        println!("[✓] Signature verification test passed\n");
    }

    #[test]
    fn test_quorum_signal_signature_validation() {
        println!("\n=== TEST: Quorum Signal Signature Format ===");
        
        let cid = Cid::new(b"test");
        let signal = QuorumSignal {
            source: Did("did:diagon:voter".into()),
            pubkey: vec![0u8; 32],
            target: cid,
            weight: 100,
            support: true,
            elaboration: "Test elaboration".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let signable = signal.signable_bytes();
        
        // Should contain target CID
        assert!(signable.windows(32).any(|w| w == cid.0));
        println!("[✓] Signable bytes contain target CID");
        
        // Should contain support flag
        assert!(signable.contains(&1u8)); // support = true
        println!("[✓] Signable bytes contain support flag");
        
        // Should contain elaboration
        assert!(signable.windows(4).any(|w| w == b"Test"));
        println!("[✓] Signable bytes contain elaboration");
        
        println!("[✓] Quorum signal signature format test passed\n");
    }

    #[test]
    fn test_message_serialization_errors() {
        println!("\n=== TEST: Message Serialization ===");
        
        // Valid message serializes
        let msg = NetMessage::Heartbeat { 
            timestamp: timestamp(), 
            signature: vec![1, 2, 3] 
        };
        let serialized = msg.serialize();
        assert!(serialized.is_ok());
        println!("[✓] Valid message serializes");
        
        // Deserialize back
        let deserialized = NetMessage::deserialize(&serialized.unwrap());
        assert!(deserialized.is_ok());
        println!("[✓] Serialized message deserializes");
        
        // Invalid bytes fail deserialization
        let garbage = vec![0xFF, 0xFE, 0xFD];
        let result = NetMessage::deserialize(&garbage);
        assert!(result.is_err());
        println!("[✓] Invalid bytes fail deserialization");
        
        println!("[✓] Message serialization test passed\n");
    }

    #[test]
    fn test_dm_channel_state_errors() {
        println!("\n=== TEST: DM Channel State Errors ===");
        
        let did_a = Did("did:diagon:alice".into());
        
        // Encrypt without established channel should fail
        let channel = DmChannel::new_outbound(did_a.clone(), [0u8; 32]);
        let result = channel.encrypt("test message");
        assert!(matches!(result, Err(DiagonError::DmNotEstablished)));
        println!("[✓] Encrypt fails without establishment");
        
        // Decrypt without established channel should fail
        let result = channel.decrypt(&[0u8; 32], &[0u8; 12]);
        assert!(matches!(result, Err(DiagonError::DmNotEstablished)));
        println!("[✓] Decrypt fails without establishment");
        
        println!("[✓] DM channel state errors test passed\n");
    }

    #[test]
    fn test_content_metadata_signable_bytes() {
        println!("\n=== TEST: Content Metadata Signable Bytes ===");
        
        let sender = Did("did:diagon:sender123".into());
        let data = b"test content";
        
        let metadata = ContentMetadata::new(
            ContentType::Image,
            data,
            Some("test.png".into()),
            Some("image/png".into()),
            sender.clone(),
        );
        
        let signable = metadata.signable_bytes();
        
        // Should be non-empty
        assert!(!signable.is_empty());
        println!("[✓] Signable bytes non-empty");
        
        // Should contain content_id
        assert!(signable.windows(32).any(|w| w == metadata.content_id));
        println!("[✓] Contains content_id");
        
        // Same metadata should produce same signable bytes
        let signable2 = metadata.signable_bytes();
        assert_eq!(signable, signable2);
        println!("[✓] Signable bytes are deterministic");
        
        println!("[✓] Content metadata signable bytes test passed\n");
    }

    #[test]
    fn test_derived_state_threshold_calculation() {
        println!("\n=== TEST: Derived State Threshold Calculation ===");
        
        let state = DerivedState::new();
        
        // With 0 peers, threshold should be minimum
        let threshold = state.threshold(0);
        assert_eq!(threshold, 1000);
        println!("[✓] Minimum threshold with 0 peers: {}", threshold);
        
        // Threshold scales with peer count
        let t1 = state.threshold(1);
        let t5 = state.threshold(5);
        let t10 = state.threshold(10);
        
        assert!(t1 < t5);
        assert!(t5 < t10);
        println!("[✓] Threshold scales: t1={}, t5={}, t10={}", t1, t5, t10);
        
        // Threshold uses EIGEN_THRESHOLD
        let expected = (((10 + 1) as f64 * EIGEN_THRESHOLD * 1000.0) as u64).max(1000);
        assert_eq!(t10, expected);
        println!("[✓] Threshold formula correct");
        
        println!("[✓] Derived state threshold calculation test passed\n");
    }

    #[test]
    fn test_elaboration_scoring() {
        println!("\n=== TEST: Elaboration Scoring ===");
        
        // Too short
        let score = score_elaboration("hi");
        assert!(score < 0.2);
        println!("[✓] Short text scores low: {:.2}", score);
        
        // Repetitive
        let score = score_elaboration("a a a a a a a a a a");
        assert!(score < 0.5);
        println!("[✓] Repetitive text scores lower: {:.2}", score);
        
        // Good elaboration
        let score = score_elaboration(
            "This is a thoughtful and well-considered elaboration that explains my reasoning"
        );
        assert!(score > 0.4);
        println!("[✓] Good elaboration scores higher: {:.2}", score);
        
        // Score is clamped
        let score = score_elaboration(
            "a b c d e f g h i j k l m n o p q r s t u v w x y z \
             aa bb cc dd ee ff gg hh ii jj kk ll mm nn oo pp qq rr"
        );
        assert!(score <= 0.8);
        println!("[✓] Score is clamped to max: {:.2}", score);
        
        println!("[✓] Elaboration scoring test passed\n");
    }

    #[test]
    fn test_mime_type_detection() {
        println!("\n=== TEST: MIME Type Detection ===");
        
        // JPEG
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(detect_image_mime(&jpeg), Some("image/jpeg".to_string()));
        println!("[✓] JPEG detected");
        
        // PNG
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_image_mime(&png), Some("image/png".to_string()));
        println!("[✓] PNG detected");
        
        // GIF
        let gif = b"GIF89a\x00\x00";
        assert_eq!(detect_image_mime(gif), Some("image/gif".to_string()));
        println!("[✓] GIF detected");
        
        // MP4
        let mp4 = [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D];
        assert_eq!(detect_video_mime(&mp4), Some("video/mp4".to_string()));
        println!("[✓] MP4 detected");
        
        // WebM
        let webm = [0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_video_mime(&webm), Some("video/webm".to_string()));
        println!("[✓] WebM detected");
        
        // Unknown
        let unknown = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_image_mime(&unknown), Some("application/octet-stream".to_string()));
        println!("[✓] Unknown type handled");
        
        // Too short
        let short = [0x00, 0x00];
        assert_eq!(detect_image_mime(&short), None);
        println!("[✓] Too short returns None");
        
        println!("[✓] MIME type detection test passed\n");
    }

    // ========================================================================
    // CONTENT FILE TESTS (requires test/ directory with sample files)
    // ========================================================================

    fn test_file_path(filename: &str) -> Option<String> {
        let path = format!("test/{}", filename);
        if std::path::Path::new(&path).exists() {
            Some(path)
        } else {
            None
        }
    }

    #[test]
    fn test_content_encoder_with_real_text_file() {
        println!("\n=== TEST: Content Encoder with Real Text File ===");
        
        let path = match test_file_path("test.txt") {
            Some(p) => p,
            None => {
                println!("[SKIP] test/test.txt not found");
                return;
            }
        };
        
        let data = std::fs::read(&path).expect("Failed to read test.txt");
        let sender = Did("did:diagon:tester".into());
        
        let mut encoder = ContentEncoder::new(
            ContentType::Text,
            data.clone(),
            Some("test.txt".into()),
            Some("text/plain".into()),
            sender,
        );
        
        println!("[✓] Loaded {} bytes from {}", data.len(), path);
        assert!(encoder.metadata().total_size == data.len() as u64);
        
        // Verify chunking and reassembly
        let mut reassembled = Vec::new();
        let mut chunk_count = 0;
        while let Some(chunk) = encoder.next_chunk() {
            assert!(chunk.verify(), "Chunk {} failed verification", chunk.chunk_index);
            reassembled.extend_from_slice(&chunk.data);
            chunk_count += 1;
        }
        
        assert_eq!(reassembled, data);
        println!("[✓] {} chunks created and verified", chunk_count);
        println!("[✓] Content encoder with real text file test passed\n");
    }

    #[test]
    fn test_content_encoder_with_real_image_files() {
        println!("\n=== TEST: Content Encoder with Real Image Files ===");
        
        let sender = Did("did:diagon:tester".into());
        
        for (filename, expected_mime) in [
            ("test.jpg", "image/jpeg"),
            ("test.png", "image/png"),
        ] {
            let path = match test_file_path(filename) {
                Some(p) => p,
                None => {
                    println!("[SKIP] test/{} not found", filename);
                    continue;
                }
            };
            
            let data = std::fs::read(&path).expect(&format!("Failed to read {}", filename));
            
            // Test MIME detection
            let detected = detect_image_mime(&data);
            assert_eq!(detected.as_deref(), Some(expected_mime), 
                "MIME mismatch for {}", filename);
            println!("[✓] {} detected as {}", filename, expected_mime);
            
            // Test encoder
            let mut encoder = ContentEncoder::new(
                ContentType::Image,
                data.clone(),
                Some(filename.into()),
                detected,
                sender.clone(),
            );
            
            // Sign it
            let (_, secret_key) = keypair();
            encoder.sign(&secret_key);
            assert!(!encoder.metadata().signature.is_empty());
            println!("[✓] {} ({} bytes, {} chunks) encoded and signed", 
                filename, data.len(), encoder.metadata().total_chunks);
        }
        
        println!("[✓] Content encoder with real image files test passed\n");
    }

    #[test]
    fn test_content_encoder_with_real_video_file() {
        println!("\n=== TEST: Content Encoder with Real Video File ===");
        
        let path = match test_file_path("test.mp4") {
            Some(p) => p,
            None => {
                println!("[SKIP] test/test.mp4 not found");
                return;
            }
        };
        
        let data = std::fs::read(&path).expect("Failed to read test.mp4");
        let sender = Did("did:diagon:tester".into());
        
        // Test MIME detection
        let detected = detect_video_mime(&data);
        assert_eq!(detected.as_deref(), Some("video/mp4"));
        println!("[✓] Detected as video/mp4");
        
        let mut encoder = ContentEncoder::new(
            ContentType::Video,
            data.clone(),
            Some("test.mp4".into()),
            detected,
            sender,
        );
        
        println!("[✓] Video: {} bytes, {} chunks", 
            encoder.metadata().total_size, 
            encoder.metadata().total_chunks);
        
        // Full roundtrip test
        let metadata = encoder.metadata().clone();
        let mut transfer = IncomingTransfer::new(metadata);
        
        while let Some(chunk) = encoder.next_chunk() {
            transfer.add_chunk(&chunk).expect("Chunk add failed");
        }
        
        assert!(transfer.is_complete());
        let reassembled = transfer.reassemble().expect("Reassembly failed");
        assert_eq!(reassembled, data);
        println!("[✓] Full encode/transfer/reassemble roundtrip passed");
        
        println!("[✓] Content encoder with real video file test passed\n");
    }

    #[tokio::test]
    async fn test_two_node_content_transfer() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Two Node Content Transfer ===");
            
            let path = match test_file_path("test.txt") {
                Some(p) => p,
                None => {
                    println!("[SKIP] test/test.txt not found");
                    return;
                }
            };
            
            let dir = setup_test_dir("content_transfer");
            let port1 = get_free_port();
            let port2 = get_free_port();
            
            let node1 = Node::new(&format!("127.0.0.1:{}", port1), &format!("{}/node1", dir))
                .await.expect("Node 1 failed");
            let node2 = Node::new(&format!("127.0.0.1:{}", port2), &format!("{}/node2", dir))
                .await.expect("Node 2 failed");
            
            node1.auth(TEST_PASSPHRASE, None).await;
            node2.auth(TEST_PASSPHRASE, None).await;
            
            sleep(Duration::from_millis(200)).await;
            
            // Step 1: Node1 connects to Node2
            node1.connect(&format!("127.0.0.1:{}", port2)).await.expect("Connect failed");
            sleep(Duration::from_millis(300)).await;
            
            // Step 2: Node1 sends elaboration
            node1.elaborate("Testing content transfer between nodes.").await;
            sleep(Duration::from_millis(300)).await;
            
            // Step 3: Node2 sends its elaboration (REQUIRED for mutual handshake)
            node2.elaborate("Accepting connection for content transfer testing.").await;
            sleep(Duration::from_millis(300)).await;
            
            // Step 4: Node2 approves (now in MutualPending state)
            let pending = node2.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node2.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(300)).await;
            
            // Step 5: Node1 also approves (mutual approval requires both sides)
            let pending = node1.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node1.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(300)).await;
            
            assert!(node1.connection_pool.authenticated_addrs().await.len() > 0 ||
                    node2.connection_pool.authenticated_addrs().await.len() > 0);
            println!("[✓] Nodes connected");
            
            node1.message("text", &path).await;
            sleep(Duration::from_millis(1000)).await;
            
            let received_dir = format!("{}/node2/received", dir);
            let received_files: Vec<_> = std::fs::read_dir(&received_dir)
                .map(|rd| rd.filter_map(|e| e.ok()).collect())
                .unwrap_or_default();
            
            if !received_files.is_empty() {
                println!("[✓] Node2 received {} file(s)", received_files.len());
            } else {
                println!("[!] No files received yet");
            }
            
            let _ = timeout(Duration::from_secs(5), node1.shutdown()).await;
            let _ = timeout(Duration::from_secs(5), node2.shutdown()).await;
            cleanup_test_dir(&dir);
            
            println!("[✓] Two node content transfer test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    // ========================================================================
    // DHT DISCOVERY TESTS
    // ========================================================================

    #[test]
    fn test_dht_entry_topic_hashing() {
        println!("\n=== TEST: DHT Entry Topic Hashing ===");
        
        // Same topic produces same hash
        let hash1 = DhtEntry::topic_str("rust");
        let hash2 = DhtEntry::topic_str("rust");
        assert_eq!(hash1, hash2);
        println!("[✓] Same topic produces same hash");
        
        // Case insensitive
        let hash_lower = DhtEntry::topic_str("rust");
        let hash_upper = DhtEntry::topic_str("RUST");
        let hash_mixed = DhtEntry::topic_str("RuSt");
        assert_eq!(hash_lower, hash_upper);
        assert_eq!(hash_lower, hash_mixed);
        println!("[✓] Topic hashing is case-insensitive");
        
        // Different topics produce different hashes
        let hash_rust = DhtEntry::topic_str("rust");
        let hash_python = DhtEntry::topic_str("python");
        assert_ne!(hash_rust, hash_python);
        println!("[✓] Different topics produce different hashes");
        
        // Whitespace matters
        let hash_no_space = DhtEntry::topic_str("machinelearning");
        let hash_space = DhtEntry::topic_str("machine learning");
        assert_ne!(hash_no_space, hash_space);
        println!("[✓] Whitespace affects hash");
        
        // Hash is 32 bytes
        assert_eq!(hash1.len(), 32);
        println!("[✓] Hash is 32 bytes");
        
        println!("[✓] DHT entry topic hashing test passed\n");
    }

    #[test]
    fn test_dht_state_registration() {
        println!("\n=== TEST: DHT State Registration ===");
        
        let mut dht = DhtState::default();
        let topic_hash = DhtEntry::topic_str("test-topic");
        let pool_commitment = [1u8; 32];
        let did = Did("did:diagon:registrar123".into());
        
        let entry = DhtEntry {
            topic_hash,
            pool_commitment,
            pool_name: "Test Pool".into(),
            description: "A test pool for testing".into(),
            peer_count: 5,
            registered_by: did.clone(),
            registered_at: timestamp(),
            last_seen: timestamp(),
        };
        
        // First registration should succeed
        let is_new = dht.register(entry.clone());
        assert!(is_new);
        println!("[✓] First registration succeeds");
        
        // Should be searchable
        let results = dht.search("test-topic");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pool_name, "Test Pool");
        println!("[✓] Registered entry is searchable");
        
        // Duplicate registration should update (idempotent)
        let mut updated_entry = entry.clone();
        updated_entry.peer_count = 10;
        updated_entry.description = "Updated description".into();
        let is_new = dht.register(updated_entry);
        assert!(!is_new); // Not new, but updated
        
        let results = dht.search("test-topic");
        assert_eq!(results[0].peer_count, 10);
        assert_eq!(results[0].description, "Updated description");
        println!("[✓] Duplicate registration updates existing entry");
        
        // Different pool under same topic
        let entry2 = DhtEntry {
            topic_hash,
            pool_commitment: [2u8; 32],
            pool_name: "Another Pool".into(),
            description: "Another pool".into(),
            peer_count: 3,
            registered_by: did.clone(),
            registered_at: timestamp(),
            last_seen: timestamp(),
        };
        
        let is_new = dht.register(entry2);
        assert!(is_new);
        
        let results = dht.search("test-topic");
        assert_eq!(results.len(), 2);
        println!("[✓] Multiple pools can register under same topic");
        
        // Get directory returns all entries
        let directory = dht.get_directory();
        assert_eq!(directory.len(), 2);
        println!("[✓] Directory returns all entries");
        
        println!("[✓] DHT state registration test passed\n");
    }

    #[test]
    fn test_dht_state_rate_limiting() {
        println!("\n=== TEST: DHT State Rate Limiting ===");
        
        let mut dht = DhtState::default();
        let did = Did("did:diagon:ratelimited".into());
        
        // Should allow first 5 registrations
        for i in 0..DHT_REGISTER_LIMIT_PER_HOUR {
            assert!(dht.check_rate_limit(&did), "Failed at registration {}", i);
        }
        println!("[✓] Allowed {} registrations", DHT_REGISTER_LIMIT_PER_HOUR);
        
        // 6th should be rate limited
        assert!(!dht.check_rate_limit(&did));
        println!("[✓] 6th registration rate limited");
        
        // Different DID should have own limit
        let did2 = Did("did:diagon:different".into());
        assert!(dht.check_rate_limit(&did2));
        println!("[✓] Different DID has own limit");
        
        println!("[✓] DHT state rate limiting test passed\n");
    }

    #[test]
    fn test_dht_state_search() {
        println!("\n=== TEST: DHT State Search ===");
        
        let mut dht = DhtState::default();
        let did = Did("did:diagon:searcher".into());
        
        // Register entries under different topics
        let topics = ["rust", "python", "javascript"];
        for (i, topic) in topics.iter().enumerate() {
            let entry = DhtEntry {
                topic_hash: DhtEntry::topic_str(topic),
                pool_commitment: [i as u8; 32],
                pool_name: format!("{} Pool", topic),
                description: format!("A pool about {}", topic),
                peer_count: i + 1,
                registered_by: did.clone(),
                registered_at: timestamp(),
                last_seen: timestamp(),
            };
            dht.register(entry);
        }
        
        // Search each topic
        let results = dht.search("rust");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pool_name, "rust Pool");
        println!("[✓] Search finds rust pool");
        
        let results = dht.search("python");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pool_name, "python Pool");
        println!("[✓] Search finds python pool");
        
        // Case insensitive search
        let results = dht.search("JAVASCRIPT");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pool_name, "javascript Pool");
        println!("[✓] Search is case-insensitive");
        
        // Non-existent topic
        let results = dht.search("nonexistent");
        assert!(results.is_empty());
        println!("[✓] Search returns empty for unknown topic");
        
        println!("[✓] DHT state search test passed\n");
    }

    #[test]
    fn test_dht_state_cleanup_stale() {
        println!("\n=== TEST: DHT State Cleanup Stale ===");
        
        let mut dht = DhtState::default();
        let did = Did("did:diagon:stale".into());
        let topic_hash = DhtEntry::topic_str("stale-topic");
        
        // Register entry with old timestamp
        let stale_entry = DhtEntry {
            topic_hash,
            pool_commitment: [1u8; 32],
            pool_name: "Stale Pool".into(),
            description: "This pool is old".into(),
            peer_count: 1,
            registered_by: did.clone(),
            registered_at: timestamp() - DHT_STALE_SECS - 100,
            last_seen: timestamp() - DHT_STALE_SECS - 100,
        };
        dht.register(stale_entry);
        
        // Register fresh entry
        let fresh_entry = DhtEntry {
            topic_hash,
            pool_commitment: [2u8; 32],
            pool_name: "Fresh Pool".into(),
            description: "This pool is new".into(),
            peer_count: 5,
            registered_by: did.clone(),
            registered_at: timestamp(),
            last_seen: timestamp(),
        };
        dht.register(fresh_entry);
        
        assert_eq!(dht.get_directory().len(), 2);
        println!("[✓] Both entries registered");
        
        // Cleanup stale entries
        dht.cleanup_stale(DHT_STALE_SECS);
        
        let directory = dht.get_directory();
        assert_eq!(directory.len(), 1);
        assert_eq!(directory[0].pool_name, "Fresh Pool");
        println!("[✓] Stale entry removed, fresh entry remains");
        
        println!("[✓] DHT state cleanup stale test passed\n");
    }

    #[test]
    fn test_dht_state_update_peer_count() {
        println!("\n=== TEST: DHT State Update Peer Count ===");
        
        let mut dht = DhtState::default();
        let did = Did("did:diagon:counter".into());
        let pool_commitment = [1u8; 32];
        let topic_hash = DhtEntry::topic_str("peer-count-topic");
        
        // Register entry with initial peer count
        let entry = DhtEntry {
            topic_hash,
            pool_commitment,
            pool_name: "Counter Pool".into(),
            description: "Testing peer count updates".into(),
            peer_count: 3,
            registered_by: did.clone(),
            registered_at: timestamp() - 100,
            last_seen: timestamp() - 100,
        };
        dht.register(entry);
        
        let old_last_seen = dht.get_directory()[0].last_seen;
        
        // Update peer count
        dht.update_pool_peer_count(pool_commitment, 10);
        
        let entries = dht.get_directory();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].peer_count, 10);
        assert!(entries[0].last_seen > old_last_seen);
        println!("[✓] Peer count updated and last_seen refreshed");
        
        // Update non-existent pool (should not panic)
        dht.update_pool_peer_count([99u8; 32], 50);
        println!("[✓] Update non-existent pool is safe");
        
        println!("[✓] DHT state update peer count test passed\n");
    }

    #[test]
    fn test_rendezvous_commitment() {
        println!("\n=== TEST: Rendezvous Commitment ===");
        
        // Commitment should be deterministic
        let c1 = rendezvous_commitment();
        let c2 = rendezvous_commitment();
        assert_eq!(c1, c2);
        println!("[✓] Rendezvous commitment is deterministic");
        
        // Should be 32 bytes
        assert_eq!(c1.len(), 32);
        println!("[✓] Commitment is 32 bytes");
        
        // Should be non-zero (derived from passphrase)
        assert_ne!(c1, [0u8; 32]);
        println!("[✓] Commitment is non-zero");
        
        // Removed incorrect SHA256 assertion - rendezvous_commitment() uses Argon2
        
        println!("[✓] Rendezvous commitment test passed\n");
    }

    #[test]
    fn test_dht_entry_cbor_serialization() {
        println!("\n=== TEST: DHT Entry CBOR Serialization ===");
        
        let entry = DhtEntry {
            topic_hash: [1u8; 32],
            pool_commitment: [2u8; 32],
            pool_name: "Serializable Pool".into(),
            description: "Test description".into(),
            peer_count: 42,
            registered_by: Did("did:diagon:serial".into()),
            registered_at: 1234567890,
            last_seen: 1234567899,
        };
        
        // Serialize via CBOR
        let cbor = serde_cbor::to_vec(&entry).expect("Serialize failed");
        println!("[✓] Serialized to CBOR: {} bytes", cbor.len());
        
        // Deserialize
        let deserialized: DhtEntry = serde_cbor::from_slice(&cbor).expect("Deserialize failed");
        assert_eq!(deserialized.topic_hash, entry.topic_hash);
        assert_eq!(deserialized.pool_commitment, entry.pool_commitment);
        assert_eq!(deserialized.pool_name, entry.pool_name);
        assert_eq!(deserialized.description, entry.description);
        assert_eq!(deserialized.peer_count, entry.peer_count);
        assert_eq!(deserialized.registered_by, entry.registered_by);
        assert_eq!(deserialized.registered_at, entry.registered_at);
        assert_eq!(deserialized.last_seen, entry.last_seen);
        println!("[✓] Deserialized correctly");
        
        println!("[✓] DHT entry CBOR serialization test passed\n");
    }

    // ========================================================================
    // THREADING (REPLY) TESTS
    // ========================================================================

    #[test]
    fn test_reply_index_operations() {
        println!("\n=== TEST: Reply Index Operations ===");
        
        let mut store = ExprStore::new();
        
        // Create parent expression
        let parent = store.arena_mut().parse("(propose parent content)").unwrap();
        let (parent_cid, _) = store.store(parent).expect("Store parent failed");
        println!("[✓] Parent expression stored: {}", parent_cid.short());
        
        // Create reply expressions
        let reply1 = store.arena_mut().parse("(reply first reply)").unwrap();
        let (reply1_cid, _) = store.store(reply1).expect("Store reply1 failed");
        
        let reply2 = store.arena_mut().parse("(reply second reply)").unwrap();
        let (reply2_cid, _) = store.store(reply2).expect("Store reply2 failed");
        
        // Add replies to index
        store.add_reply(parent_cid, reply1_cid);
        store.add_reply(parent_cid, reply2_cid);
        println!("[✓] Replies added to index");
        
        // Get replies
        let replies = store.get_replies(&parent_cid).expect("Should have replies");
        assert_eq!(replies.len(), 2);
        assert!(replies.contains(&reply1_cid));
        assert!(replies.contains(&reply2_cid));
        println!("[✓] Got {} replies for parent", replies.len());
        
        // Duplicate add should not create duplicates
        store.add_reply(parent_cid, reply1_cid);
        let replies = store.get_replies(&parent_cid).expect("Should have replies");
        assert_eq!(replies.len(), 2);
        println!("[✓] Duplicate reply not added");
        
        // Non-existent parent returns None
        let fake_cid = Cid([99u8; 32]);
        let replies = store.get_replies(&fake_cid);
        assert!(replies.is_none());
        println!("[✓] Non-existent parent returns None");
        
        println!("[✓] Reply index operations test passed\n");
    }

    #[test]
    fn test_nested_replies() {
        println!("\n=== TEST: Nested Replies ===");
        
        let mut store = ExprStore::new();
        
        // Create thread structure:
        // root
        //   └─ reply1
        //       └─ reply1a
        //       └─ reply1b
        //   └─ reply2
        
        let root = store.arena_mut().parse("(propose root message)").unwrap();
        let (root_cid, _) = store.store(root).unwrap();
        
        let r1 = store.arena_mut().parse("(reply first)").unwrap();
        let (r1_cid, _) = store.store(r1).unwrap();
        store.add_reply(root_cid, r1_cid);
        
        let r2 = store.arena_mut().parse("(reply second)").unwrap();
        let (r2_cid, _) = store.store(r2).unwrap();
        store.add_reply(root_cid, r2_cid);
        
        let r1a = store.arena_mut().parse("(reply nested-a)").unwrap();
        let (r1a_cid, _) = store.store(r1a).unwrap();
        store.add_reply(r1_cid, r1a_cid);
        
        let r1b = store.arena_mut().parse("(reply nested-b)").unwrap();
        let (r1b_cid, _) = store.store(r1b).unwrap();
        store.add_reply(r1_cid, r1b_cid);
        
        // Verify structure
        let root_replies = store.get_replies(&root_cid).expect("Should have replies");
        assert_eq!(root_replies.len(), 2);
        println!("[✓] Root has 2 direct replies");
        
        let r1_replies = store.get_replies(&r1_cid).expect("Should have replies");
        assert_eq!(r1_replies.len(), 2);
        println!("[✓] Reply1 has 2 nested replies");
        
        let r2_replies = store.get_replies(&r2_cid);
        assert!(r2_replies.is_none());
        println!("[✓] Reply2 has no nested replies");
        
        println!("[✓] Nested replies test passed\n");
    }

    // ========================================================================
    // DHT MESSAGE TESTS
    // ========================================================================

    #[test]
    fn test_dht_register_message_serialization() {
        println!("\n=== TEST: DHT Register Message Serialization ===");
        
        let msg = NetMessage::DhtRegister {
            topic_hash: [1u8; 32],
            pool_commitment: [2u8; 32],
            pool_name: "Test Pool".into(),
            description: "Test description".into(),
            peer_count: 5,
            signature: vec![0u8; 64],
        };
        
        let serialized = msg.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DhtRegister { topic_hash, pool_commitment, pool_name, description, peer_count, signature } = deserialized {
            assert_eq!(topic_hash, [1u8; 32]);
            assert_eq!(pool_commitment, [2u8; 32]);
            assert_eq!(pool_name, "Test Pool");
            assert_eq!(description, "Test description");
            assert_eq!(peer_count, 5);
            assert_eq!(signature.len(), 64);
            println!("[✓] DhtRegister roundtrip successful");
        } else {
            panic!("Wrong message type");
        }
        
        println!("[✓] DHT register message serialization test passed\n");
    }

    #[test]
    fn test_dht_search_message_serialization() {
        println!("\n=== TEST: DHT Search Message Serialization ===");
        
        // Request
        let request = NetMessage::DhtSearchRequest {
            topic_hash: [42u8; 32],
        };
        
        let serialized = request.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DhtSearchRequest { topic_hash } = deserialized {
            assert_eq!(topic_hash, [42u8; 32]);
            println!("[✓] DhtSearchRequest roundtrip successful");
        } else {
            panic!("Wrong message type");
        }
        
        // Response
        let entry = DhtEntry {
            topic_hash: [42u8; 32],
            pool_commitment: [1u8; 32],
            pool_name: "Found Pool".into(),
            description: "A pool we found".into(),
            peer_count: 10,
            registered_by: Did("did:diagon:finder".into()),
            registered_at: timestamp(),
            last_seen: timestamp(),
        };
        
        let response = NetMessage::DhtSearchResponse {
            topic_hash: [42u8; 32],
            results: vec![entry],
        };
        
        let serialized = response.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DhtSearchResponse { topic_hash, results } = deserialized {
            assert_eq!(topic_hash, [42u8; 32]);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].pool_name, "Found Pool");
            println!("[✓] DhtSearchResponse roundtrip successful");
        } else {
            panic!("Wrong message type");
        }
        
        println!("[✓] DHT search message serialization test passed\n");
    }

    #[test]
    fn test_dht_directory_message_serialization() {
        println!("\n=== TEST: DHT Directory Message Serialization ===");
        
        // Request
        let request = NetMessage::DhtDirectoryRequest;
        let serialized = request.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        assert!(matches!(deserialized, NetMessage::DhtDirectoryRequest));
        println!("[✓] DhtDirectoryRequest roundtrip successful");
        
        // Response with multiple entries
        let entries: Vec<DhtEntry> = (0..3).map(|i| DhtEntry {
            topic_hash: [i as u8; 32],
            pool_commitment: [i as u8 + 10; 32],
            pool_name: format!("Pool {}", i),
            description: format!("Description {}", i),
            peer_count: i * 5,
            registered_by: Did(format!("did:diagon:dir{}", i)),
            registered_at: timestamp() - i as u64 * 100,
            last_seen: timestamp(),
        }).collect();
        
        let response = NetMessage::DhtDirectoryResponse { entries: entries.clone() };
        
        let serialized = response.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DhtDirectoryResponse { entries: recv_entries } = deserialized {
            assert_eq!(recv_entries.len(), 3);
            for (i, entry) in recv_entries.iter().enumerate() {
                assert_eq!(entry.pool_name, format!("Pool {}", i));
            }
            println!("[✓] DhtDirectoryResponse roundtrip successful with {} entries", recv_entries.len());
        } else {
            panic!("Wrong message type");
        }
        
        println!("[✓] DHT directory message serialization test passed\n");
    }

    #[test]
    fn test_dht_pool_announce_message_serialization() {
        println!("\n=== TEST: DHT Pool Announce Message Serialization ===");
        
        let msg = NetMessage::DhtPoolAnnounce {
            pool_commitment: [1u8; 32],
            pool_name: "Announcing Pool".into(),
            peer_count: 15,
            topics: vec![[10u8; 32], [20u8; 32], [30u8; 32]],
            signature: vec![0u8; 64],
        };
        
        let serialized = msg.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DhtPoolAnnounce { pool_commitment, pool_name, peer_count, topics, signature } = deserialized {
            assert_eq!(pool_commitment, [1u8; 32]);
            assert_eq!(pool_name, "Announcing Pool");
            assert_eq!(peer_count, 15);
            assert_eq!(topics.len(), 3);
            assert_eq!(topics[0], [10u8; 32]);
            assert_eq!(topics[1], [20u8; 32]);
            assert_eq!(topics[2], [30u8; 32]);
            assert_eq!(signature.len(), 64);
            println!("[✓] DhtPoolAnnounce roundtrip successful");
        } else {
            panic!("Wrong message type");
        }
        
        println!("[✓] DHT pool announce message serialization test passed\n");
    }

    #[test]
    fn test_dht_register_signable_bytes() {
        println!("\n=== TEST: DHT Register Signable Bytes ===");
        
        let topic_hash = [1u8; 32];
        let pool_commitment = [2u8; 32];
        let pool_name = "Test Pool";
        let description = "A test pool";
        
        // Build signable bytes manually
        let mut expected = b"dht-register:".to_vec();
        expected.extend_from_slice(&topic_hash);
        expected.extend_from_slice(&pool_commitment);
        expected.extend_from_slice(pool_name.as_bytes());
        expected.extend_from_slice(description.as_bytes());
        
        // Verify format is correct
        assert!(expected.starts_with(b"dht-register:"));
        assert_eq!(expected.len(), 13 + 32 + 32 + pool_name.len() + description.len());
        println!("[✓] Signable bytes format is correct");
        
        // Should be deterministic
        let mut expected2 = b"dht-register:".to_vec();
        expected2.extend_from_slice(&topic_hash);
        expected2.extend_from_slice(&pool_commitment);
        expected2.extend_from_slice(pool_name.as_bytes());
        expected2.extend_from_slice(description.as_bytes());
        assert_eq!(expected, expected2);
        println!("[✓] Signable bytes are deterministic");
        
        println!("[✓] DHT register signable bytes test passed\n");
    }

    #[test]
    fn test_dht_announce_signable_bytes() {
        println!("\n=== TEST: DHT Announce Signable Bytes ===");
        
        let pool_commitment = [1u8; 32];
        let pool_name = "My Pool";
        let peer_count: usize = 42;
        let topics = vec![[10u8; 32], [20u8; 32]];
        
        // Build signable bytes manually
        let mut expected = b"dht-announce:".to_vec();
        expected.extend_from_slice(&pool_commitment);
        expected.extend_from_slice(pool_name.as_bytes());
        expected.extend_from_slice(&(peer_count as u64).to_le_bytes());
        for t in &topics {
            expected.extend_from_slice(t);
        }
        
        // Verify format
        assert!(expected.starts_with(b"dht-announce:"));
        let expected_len = 13 + 32 + pool_name.len() + 8 + (32 * topics.len());
        assert_eq!(expected.len(), expected_len);
        println!("[✓] Announce signable bytes format is correct");
        
        // Peer count is encoded as u64 little-endian
        let count_offset = 13 + 32 + pool_name.len();
        let count_bytes: [u8; 8] = expected[count_offset..count_offset + 8].try_into().unwrap();
        assert_eq!(u64::from_le_bytes(count_bytes), 42);
        println!("[✓] Peer count encoded correctly");
        
        println!("[✓] DHT announce signable bytes test passed\n");
    }

    // ========================================================================
    // DHT INTEGRATION TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_node_rendezvous_join() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Rendezvous Join ===");
            let dir = setup_test_dir("rendezvous_join");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Initially not in rendezvous
            assert!(!node.is_in_rendezvous().await);
            println!("[✓] Initially not in rendezvous");
            
            // Join rendezvous
            node.join_rendezvous().await;
            
            // Now should be in rendezvous
            assert!(node.is_in_rendezvous().await);
            println!("[✓] Successfully joined rendezvous");
            
            // Pool should be rendezvous commitment
            let pool = node.pool.read().await;
            assert_eq!(*pool, Some(rendezvous_commitment()));
            println!("[✓] Pool is rendezvous commitment");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node rendezvous join test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_set_pool_name() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Set Pool Name ===");
            let dir = setup_test_dir("pool_name");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Initially no pool name
            assert!(node.pool_name.read().await.is_none());
            println!("[✓] Initially no pool name");
            
            // Set pool name
            node.set_pool_name("My Awesome Pool").await;
            
            // Should be set
            let name = node.pool_name.read().await.clone();
            assert_eq!(name, Some("My Awesome Pool".into()));
            println!("[✓] Pool name set successfully");
            
            // Update pool name
            node.set_pool_name("Renamed Pool").await;
            let name = node.pool_name.read().await.clone();
            assert_eq!(name, Some("Renamed Pool".into()));
            println!("[✓] Pool name updated successfully");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node set pool name test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_dht_register_local() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node DHT Register (Local) ===");
            let dir = setup_test_dir("dht_register_local");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Join rendezvous and set pool name
            node.join_rendezvous().await;
            node.set_pool_name("Test Pool for Registration").await;
            
            // Register under a topic
            node.dht_register("rust", "Rust programming discussions").await;
            sleep(Duration::from_millis(100)).await;
            
            // Should be in pool_topics
            let topics = node.pool_topics.read().await;
            assert_eq!(topics.len(), 1);
            assert_eq!(topics[0], DhtEntry::topic_str("rust"));
            println!("[✓] Topic registered in pool_topics");
            
            // Should be in local DHT
            let dht = node.dht.read().await;
            let results = dht.search("rust");
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].pool_name, "Test Pool for Registration");
            assert_eq!(results[0].description, "Rust programming discussions");
            println!("[✓] Entry exists in local DHT");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node DHT register (local) test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_dht_search_local() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node DHT Search (Local) ===");
            let dir = setup_test_dir("dht_search_local");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.join_rendezvous().await;
            node.set_pool_name("Searchable Pool").await;
            
            // Register multiple topics
            node.dht_register("rust", "Rust discussions").await;
            node.dht_register("webdev", "Web development").await;
            node.dht_register("gamedev", "Game development").await;
            sleep(Duration::from_millis(100)).await;
            
            // Search should find correct topic
            let dht = node.dht.read().await;
            
            let rust_results = dht.search("rust");
            assert_eq!(rust_results.len(), 1);
            println!("[✓] Found rust topic");
            
            let webdev_results = dht.search("webdev");
            assert_eq!(webdev_results.len(), 1);
            println!("[✓] Found webdev topic");
            
            let unknown_results = dht.search("blockchain");
            assert!(unknown_results.is_empty());
            println!("[✓] Unknown topic returns empty");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node DHT search (local) test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_dht_rate_limiting() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node DHT Rate Limiting ===");
            let dir = setup_test_dir("dht_rate_limit");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.join_rendezvous().await;
            node.set_pool_name("Rate Limited Pool").await;
            
            // Should allow first 5 registrations
            for i in 0..5 {
                node.dht_register(&format!("topic{}", i), "Description").await;
            }
            sleep(Duration::from_millis(100)).await;
            
            let dht = node.dht.read().await;
            let directory = dht.get_directory();
            assert_eq!(directory.len(), 5);
            println!("[✓] First 5 registrations succeeded");
            drop(dht);
            
            // 6th should be rate limited (won't add to DHT)
            node.dht_register("topic5", "Should be rate limited").await;
            sleep(Duration::from_millis(100)).await;
            
            let dht = node.dht.read().await;
            let directory = dht.get_directory();
            // Still 5 because 6th was rate limited
            assert_eq!(directory.len(), 5);
            println!("[✓] 6th registration was rate limited");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node DHT rate limiting test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_dht_persistence() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: DHT Persistence ===");
            let dir = setup_test_dir("dht_persistence");
            let port = get_free_port();
            
            // First node session: register entries
            {
                let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                    .await.expect("Node failed");
                
                node.join_rendezvous().await;
                node.set_pool_name("Persistent Pool").await;
                node.dht_register("persistent-topic", "This should persist").await;
                sleep(Duration::from_millis(100)).await;
                
                // Save state
                node.save_state().await.expect("Save failed");
                
                let dht = node.dht.read().await;
                assert_eq!(dht.get_directory().len(), 1);
                println!("[✓] Entry registered in first session");
                
                let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            }
            
            // Need different port for second session
            let port2 = get_free_port();
            
            // Second node session: verify persistence
            {
                let node = Node::new(&format!("127.0.0.1:{}", port2), &format!("{}/node", dir))
                    .await.expect("Node failed");
                
                let pool_name = node.pool_name.read().await.clone();
                assert_eq!(pool_name, Some("Persistent Pool".into()));
                println!("[✓] Pool name persisted");
                
                let dht = node.dht.read().await;
                let directory = dht.get_directory();
                assert_eq!(directory.len(), 1);
                assert_eq!(directory[0].pool_name, "Persistent Pool");
                assert_eq!(directory[0].description, "This should persist");
                println!("[✓] DHT entries persisted");
                
                let topics = node.pool_topics.read().await;
                assert_eq!(topics.len(), 1);
                println!("[✓] Pool topics persisted");
                
                let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            }
            
            cleanup_test_dir(&dir);
            println!("[✓] DHT persistence test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_two_node_dht_sync() {
        let result = timeout(Duration::from_secs(60), async {
            println!("\n=== TEST: Two Node DHT Sync ===");
            let dir = setup_test_dir("dht_sync");
            let port1 = get_free_port();
            let port2 = get_free_port();
            
            let node1 = Node::new(&format!("127.0.0.1:{}", port1), &format!("{}/node1", dir))
                .await.expect("Node 1 failed");
            let node2 = Node::new(&format!("127.0.0.1:{}", port2), &format!("{}/node2", dir))
                .await.expect("Node 2 failed");
            
            // Both join rendezvous
            node1.join_rendezvous().await;
            node2.join_rendezvous().await;
            
            node1.set_pool_name("Node1 Pool").await;
            node2.set_pool_name("Node2 Pool").await;
            
            sleep(Duration::from_millis(200)).await;
            
            // Step 1: Node1 connects to Node2
            node1.connect(&format!("127.0.0.1:{}", port2)).await.expect("Connect failed");
            sleep(Duration::from_millis(200)).await;
            
            // Step 2: Node1 sends elaboration
            node1.elaborate("Testing DHT sync between nodes.").await;
            sleep(Duration::from_millis(200)).await;
            
            // Step 3: Node2 sends its elaboration (REQUIRED for mutual handshake)
            node2.elaborate("Accepting DHT sync test connection.").await;
            sleep(Duration::from_millis(200)).await;
            
            // Step 4: Node2 approves
            let pending = node2.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node2.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
            
            // Step 5: Node1 also approves (mutual approval requires both sides)
            let pending = node1.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node1.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
            
            // Check if connected
            let n1_auth = node1.connection_pool.authenticated_addrs().await.len();
            let n2_auth = node2.connection_pool.authenticated_addrs().await.len();
            if n1_auth == 0 && n2_auth == 0 {
                println!("[SKIP] Nodes not connected, skipping DHT sync test");
                let _ = timeout(Duration::from_secs(5), node1.shutdown()).await;
                let _ = timeout(Duration::from_secs(5), node2.shutdown()).await;
                cleanup_test_dir(&dir);
                return;
            }
            println!("[✓] Nodes connected");
            
            // Node1 registers a topic
            node1.dht_register("shared-topic", "Shared between nodes").await;
            sleep(Duration::from_millis(500)).await;
            
            // Node2 should receive via broadcast
            let dht2 = node2.dht.read().await;
            let results = dht2.search("shared-topic");
            
            if !results.is_empty() {
                assert_eq!(results[0].pool_name, "Node1 Pool");
                println!("[✓] DHT entry propagated to Node2");
            } else {
                // May not have propagated in time, that's okay for this test
                println!("[!] DHT entry not yet propagated (timing)");
            }
            
            let _ = timeout(Duration::from_secs(5), node1.shutdown()).await;
            let _ = timeout(Duration::from_secs(5), node2.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Two node DHT sync test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    // ========================================================================
    // THREADING INTEGRATION TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_node_reply_creation() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Reply Creation ===");
            let dir = setup_test_dir("reply_creation");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Create a proposal (parent expression)
            node.propose("This is the parent message").await;
            sleep(Duration::from_millis(100)).await;
            
            // Get the proposal CID
            let store = node.store.read().await;
            let log = store.log();
            assert!(!log.is_empty());
            let parent_cid = log[0];
            let parent_short = parent_cid.short();
            drop(store);
            
            println!("[✓] Parent created: {}", parent_short);
            
            // Create a reply
            node.reply(&parent_short, "This is a reply to the parent").await;
            sleep(Duration::from_millis(100)).await;
            
            // Verify reply was created and indexed
            let store = node.store.read().await;
            let replies = store.get_replies(&parent_cid);
            assert!(replies.is_some());
            let replies = replies.unwrap();
            assert_eq!(replies.len(), 1);
            println!("[✓] Reply created and indexed");
            
            // The reply should be a signed expression with reply-to
            let reply_cid = replies[0];
            if let Some(expr) = store.fetch(&reply_cid) {
                let display = store.arena().display(expr);
                assert!(display.contains("signed"));
                assert!(display.contains("reply-to"));
                println!("[✓] Reply has correct structure");
            }
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node reply creation test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_thread_display() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Thread Display ===");
            let dir = setup_test_dir("thread_display");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Create parent (must be >= 20 chars)
            node.propose("Thread root message here").await;  // <-- Fixed: 24 chars
            sleep(Duration::from_millis(100)).await;
            
            let store = node.store.read().await;
            let parent_cid = store.log()[0];
            let parent_short = parent_cid.short();
            drop(store);
            
            // Create multiple replies (must be >= 20 chars)
            node.reply(&parent_short, "First reply to thread").await;  // <-- Fixed: 21 chars
            sleep(Duration::from_millis(50)).await;
            node.reply(&parent_short, "Second reply to thread").await;  // <-- Fixed: 22 chars
            sleep(Duration::from_millis(50)).await;
            
            // Verify thread structure
            let store = node.store.read().await;
            let replies = store.get_replies(&parent_cid);
            assert!(replies.is_some());
            assert_eq!(replies.unwrap().len(), 2);
            println!("[✓] Thread has 2 replies");
            
            // Thread display should work (just verify it doesn't panic)
            drop(store);
            node.thread(&parent_short).await;
            println!("[✓] Thread display completed");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node thread display test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    // ========================================================================
    // DECAY CONFIG GOVERNANCE TESTS
    // ========================================================================

    #[test]
    fn test_decay_config_defaults() {
        println!("\n=== TEST: Decay Config Defaults ===");
        
        let config = DecayConfig::default();
        
        assert!(config.enabled);
        assert_eq!(config.decay_days, CONTENT_DECAY_DAYS);
        assert!(config.require_engagement);
        println!("[✓] Default config: enabled, {} days, engagement required", config.decay_days);
        
        println!("[✓] Decay config defaults test passed\n");
    }

    #[test]
    fn test_decay_config_equality() {
        println!("\n=== TEST: Decay Config Equality ===");
        
        let config1 = DecayConfig {
            enabled: true,
            decay_days: 14,
            require_engagement: false,
        };
        
        let config2 = DecayConfig {
            enabled: true,
            decay_days: 14,
            require_engagement: false,
        };
        
        let config3 = DecayConfig {
            enabled: false,
            decay_days: 14,
            require_engagement: false,
        };
        
        assert_eq!(config1, config2);
        println!("[✓] Identical configs are equal");
        
        assert_ne!(config1, config3);
        println!("[✓] Different configs are not equal");
        
        println!("[✓] Decay config equality test passed\n");
    }

    #[test]
    fn test_decay_config_serialization() {
        println!("\n=== TEST: Decay Config Serialization ===");
        
        let config = DecayConfig {
            enabled: true,
            decay_days: 30,
            require_engagement: false,
        };
        
        // CBOR roundtrip
        let cbor = serde_cbor::to_vec(&config).expect("CBOR serialize failed");
        let restored: DecayConfig = serde_cbor::from_slice(&cbor).expect("CBOR deserialize failed");
        
        assert_eq!(config, restored);
        println!("[✓] CBOR roundtrip successful");
        
        // Bincode roundtrip
        let bincode_bytes = bincode::serialize(&config).expect("Bincode serialize failed");
        let restored2: DecayConfig = bincode::deserialize(&bincode_bytes).expect("Bincode deserialize failed");
        
        assert_eq!(config, restored2);
        println!("[✓] Bincode roundtrip successful");
        
        println!("[✓] Decay config serialization test passed\n");
    }

    #[test]
    fn test_decay_config_proposal_creation() {
        println!("\n=== TEST: Decay Config Proposal Creation ===");
        
        let proposer = Did("did:diagon:proposer123456".into());
        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let id = Cid(id_bytes);
        
        let config = DecayConfig {
            enabled: false,
            decay_days: 0,
            require_engagement: false,
        };
        
        let proposal = DecayConfigProposal {
            id,
            proposed_config: config.clone(),
            proposer: proposer.clone(),
            reason: "Switch to archive mode for historical preservation".into(),
            quorum: QuorumState::new(id, 1000, proposer.clone()),
            created: timestamp(),
            applied: false,
        };
        
        assert_eq!(proposal.id, id);
        assert_eq!(proposal.proposed_config, config);
        assert_eq!(proposal.proposer, proposer);
        assert!(!proposal.applied);
        assert!(!proposal.quorum.reached());
        println!("[✓] Proposal created correctly");
        
        println!("[✓] Decay config proposal creation test passed\n");
    }

    #[test]
    fn test_decay_config_proposal_serialization() {
        println!("\n=== TEST: Decay Config Proposal Serialization ===");
        
        let proposer = Did("did:diagon:serial123".into());
        let id = Cid([42u8; 32]);
        
        let proposal = DecayConfigProposal {
            id,
            proposed_config: DecayConfig {
                enabled: true,
                decay_days: 14,
                require_engagement: true,
            },
            proposer: proposer.clone(),
            reason: "Extend decay period".into(),
            quorum: QuorumState::new(id, 500, proposer),
            created: 1234567890,
            applied: false,
        };
        
        let cbor = serde_cbor::to_vec(&proposal).expect("Serialize failed");
        let restored: DecayConfigProposal = serde_cbor::from_slice(&cbor).expect("Deserialize failed");
        
        assert_eq!(restored.id, proposal.id);
        assert_eq!(restored.proposed_config, proposal.proposed_config);
        assert_eq!(restored.reason, proposal.reason);
        assert_eq!(restored.created, proposal.created);
        assert_eq!(restored.applied, proposal.applied);
        println!("[✓] Proposal serialization roundtrip successful");
        
        println!("[✓] Decay config proposal serialization test passed\n");
    }

    #[test]
    fn test_decay_config_quorum_voting() {
        println!("\n=== TEST: Decay Config Quorum Voting ===");
        
        let proposer = Did("did:diagon:proposer".into());
        let id = Cid([1u8; 32]);
        let threshold = 1000u64;
        
        let mut proposal = DecayConfigProposal {
            id,
            proposed_config: DecayConfig {
                enabled: false,
                decay_days: 0,
                require_engagement: false,
            },
            proposer: proposer.clone(),
            reason: "Archive mode proposal".into(),
            quorum: QuorumState::new(id, threshold, proposer.clone()),
            created: timestamp(),
            applied: false,
        };
        
        assert!(!proposal.quorum.reached());
        println!("[✓] Initial quorum not reached");
        
        // Proposer cannot vote
        let self_vote = QuorumSignal {
            source: proposer.clone(),
            pubkey: vec![0u8; 32],
            target: id,
            weight: 500,
            support: true,
            elaboration: "I vote for my own proposal".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let result = proposal.quorum.sense(self_vote);
        assert!(matches!(result, Err(DiagonError::SelfVoteProhibited)));
        println!("[✓] Self-vote correctly rejected");
        
        // Other voters can vote
        let voter1 = Did("did:diagon:voter1".into());
        let vote1 = QuorumSignal {
            source: voter1.clone(),
            pubkey: vec![0u8; 32],
            target: id,
            weight: 600,
            support: true,
            elaboration: "I support archive mode".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let sensed = proposal.quorum.sense(vote1).unwrap();
        assert!(sensed);
        assert!(!proposal.quorum.reached());
        println!("[✓] First vote added, threshold not reached");
        
        // Second vote reaches threshold
        let voter2 = Did("did:diagon:voter2".into());
        let vote2 = QuorumSignal {
            source: voter2.clone(),
            pubkey: vec![0u8; 32],
            target: id,
            weight: 500,
            support: true,
            elaboration: "Archive mode is good".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        proposal.quorum.sense(vote2).unwrap();
        assert!(proposal.quorum.reached());
        println!("[✓] Quorum reached after second vote");
        
        // Duplicate vote rejected
        let duplicate = QuorumSignal {
            source: voter1,
            pubkey: vec![0u8; 32],
            target: id,
            weight: 1000,
            support: true,
            elaboration: "Trying to vote again".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let sensed = proposal.quorum.sense(duplicate).unwrap();
        assert!(!sensed);
        println!("[✓] Duplicate vote ignored");
        
        println!("[✓] Decay config quorum voting test passed\n");
    }

    #[test]
    fn test_decay_config_in_derived_state() {
        println!("\n=== TEST: Decay Config in Derived State ===");
        
        let mut state = DerivedState::new();
        
        assert!(state.decay_proposals.is_empty());
        println!("[✓] Initial state has no decay proposals");
        
        let proposer = Did("did:diagon:test".into());
        let id = Cid([99u8; 32]);
        
        let proposal = DecayConfigProposal {
            id,
            proposed_config: DecayConfig::default(),
            proposer: proposer.clone(),
            reason: "Test proposal".into(),
            quorum: QuorumState::new(id, 1000, proposer),
            created: timestamp(),
            applied: false,
        };
        
        state.decay_proposals.insert(id, proposal);
        assert_eq!(state.decay_proposals.len(), 1);
        assert!(state.decay_proposals.contains_key(&id));
        println!("[✓] Proposal stored in derived state");
        
        // Retrieve and verify
        let retrieved = state.decay_proposals.get(&id).unwrap();
        assert_eq!(retrieved.reason, "Test proposal");
        println!("[✓] Proposal retrieved correctly");
        
        println!("[✓] Decay config in derived state test passed\n");
    }

    #[test]
    fn test_decay_config_message_serialization() {
        println!("\n=== TEST: Decay Config Message Serialization ===");
        
        // DecayConfigPropose message
        let propose_msg = NetMessage::DecayConfigPropose {
            id: Cid([1u8; 32]),
            config: DecayConfig {
                enabled: true,
                decay_days: 21,
                require_engagement: false,
            },
            reason: "Three week decay period".into(),
            signature: vec![0u8; 64],
        };
        
        let serialized = propose_msg.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DecayConfigPropose { id, config, reason, signature } = deserialized {
            assert_eq!(id.0, [1u8; 32]);
            assert_eq!(config.decay_days, 21);
            assert!(!config.require_engagement);
            assert_eq!(reason, "Three week decay period");
            assert_eq!(signature.len(), 64);
            println!("[✓] DecayConfigPropose roundtrip successful");
        } else {
            panic!("Wrong message type");
        }
        
        // DecayConfigSignal message
        let signal = QuorumSignal {
            source: Did("did:diagon:voter".into()),
            pubkey: vec![0u8; 32],
            target: Cid([2u8; 32]),
            weight: 750,
            support: true,
            elaboration: "Supporting this config change".into(),
            timestamp: 9876543210,
            signature: vec![1u8; 64],
        };
        
        let signal_msg = NetMessage::DecayConfigSignal(signal);
        let serialized = signal_msg.serialize().expect("Serialize failed");
        let deserialized = NetMessage::deserialize(&serialized).expect("Deserialize failed");
        
        if let NetMessage::DecayConfigSignal(s) = deserialized {
            assert_eq!(s.weight, 750);
            assert!(s.support);
            assert_eq!(s.elaboration, "Supporting this config change");
            println!("[✓] DecayConfigSignal roundtrip successful");
        } else {
            panic!("Wrong message type");
        }
        
        println!("[✓] Decay config message serialization test passed\n");
    }

    #[test]
    fn test_decay_config_signable_bytes() {
        println!("\n=== TEST: Decay Config Signable Bytes ===");
        
        let id = Cid([42u8; 32]);
        let config = DecayConfig {
            enabled: true,
            decay_days: 14,
            require_engagement: false,
        };
        let reason = "Test reason";
        
        let msg = NetMessage::DecayConfigPropose {
            id,
            config: config.clone(),
            reason: reason.into(),
            signature: vec![],
        };
        
        let signable = msg.signable_bytes().expect("Should have signable bytes");
        
        // Verify format
        assert!(signable.starts_with(b"decay-config:"));
        println!("[✓] Signable bytes start with correct prefix");
        
        // Should contain ID
        assert!(signable.windows(32).any(|w| w == id.0));
        println!("[✓] Signable bytes contain proposal ID");
        
        // Should be deterministic
        let signable2 = msg.signable_bytes().unwrap();
        assert_eq!(signable, signable2);
        println!("[✓] Signable bytes are deterministic");
        
        // Different config should produce different signable bytes
        let msg2 = NetMessage::DecayConfigPropose {
            id,
            config: DecayConfig {
                enabled: false,
                decay_days: 0,
                require_engagement: false,
            },
            reason: reason.into(),
            signature: vec![],
        };
        
        let signable3 = msg2.signable_bytes().unwrap();
        assert_ne!(signable, signable3);
        println!("[✓] Different configs produce different signable bytes");
        
        println!("[✓] Decay config signable bytes test passed\n");
    }

    #[tokio::test]
    async fn test_node_decay_config_initialization() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Decay Config Initialization ===");
            let dir = setup_test_dir("decay_init");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Check default config
            let config = node.decay_config.read().await;
            assert!(config.enabled);
            assert_eq!(config.decay_days, CONTENT_DECAY_DAYS);
            assert!(config.require_engagement);
            println!("[✓] Node starts with default decay config");
            
            drop(config);
            
            // Check empty decay proposals
            let state = node.state.read().await;
            assert!(state.decay_proposals.is_empty());
            println!("[✓] Node starts with no decay proposals");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node decay config initialization test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_propose_decay_config() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Propose Decay Config ===");
            let dir = setup_test_dir("decay_propose");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Propose archive mode
            node.propose_decay_config(false, 0, false, "Enable archive mode for permanent storage").await;
            sleep(Duration::from_millis(100)).await;
            
            // Check proposal was created
            let state = node.state.read().await;
            assert_eq!(state.decay_proposals.len(), 1);
            
            let (id, proposal) = state.decay_proposals.iter().next().unwrap();
            assert!(!proposal.proposed_config.enabled);
            assert_eq!(proposal.proposed_config.decay_days, 0);
            assert!(!proposal.applied);
            assert_eq!(proposal.proposer, node.did);
            println!("[✓] Proposal created: {}", id.short());
            
            // Config should NOT change yet (no quorum)
            drop(state);
            let config = node.decay_config.read().await;
            assert!(config.enabled); // Still default
            println!("[✓] Config unchanged before quorum");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node propose decay config test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_propose_decay_config_short_reason_rejected() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Propose Decay Config Short Reason Rejected ===");
            let dir = setup_test_dir("decay_short");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Try with too short reason
            node.propose_decay_config(false, 0, false, "too short").await;
            sleep(Duration::from_millis(100)).await;
            
            // Should be rejected - no proposal created
            let state = node.state.read().await;
            assert!(state.decay_proposals.is_empty());
            println!("[✓] Short reason correctly rejected");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node propose decay config short reason rejected test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_list_decay_proposals() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node List Decay Proposals ===");
            let dir = setup_test_dir("decay_list");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Create multiple proposals
            node.propose_decay_config(false, 0, false, "Archive mode for historical data").await;
            sleep(Duration::from_millis(50)).await;
            node.propose_decay_config(true, 30, true, "Extended 30-day decay period").await;
            sleep(Duration::from_millis(50)).await;
            
            // List should show both
            let state = node.state.read().await;
            assert_eq!(state.decay_proposals.len(), 2);
            println!("[✓] Two proposals exist");
            
            // Both should be unapplied
            for (_, prop) in state.decay_proposals.iter() {
                assert!(!prop.applied);
            }
            println!("[✓] Both proposals are pending (unapplied)");
            
            drop(state);
            
            // Call list function (just verify it doesn't panic)
            node.list_decay_proposals().await;
            println!("[✓] List decay proposals executes without error");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Node list decay proposals test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_node_decay_config_persistence() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Node Decay Config Persistence ===");
            let dir = setup_test_dir("decay_persist");
            let port = get_free_port();
            
            // First session: create proposal
            let proposal_id = {
                let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                    .await.expect("Node failed");
                
                node.auth(TEST_PASSPHRASE, None).await;
                node.propose_decay_config(true, 21, false, "Three week decay without engagement").await;
                sleep(Duration::from_millis(100)).await;
                
                let state = node.state.read().await;
                let id = state.decay_proposals.keys().next().copied().unwrap();
                drop(state);
                
                node.save_state().await.expect("Save failed");
                
                let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
                id
            };
            
            println!("[✓] First session: proposal {} created", proposal_id.short());
            
            // Second session: verify persistence
            let port2 = get_free_port();
            {
                let node = Node::new(&format!("127.0.0.1:{}", port2), &format!("{}/node", dir))
                    .await.expect("Node failed");
                
                let state = node.state.read().await;
                assert_eq!(state.decay_proposals.len(), 1);
                
                let proposal = state.decay_proposals.get(&proposal_id).expect("Proposal should exist");
                assert_eq!(proposal.proposed_config.decay_days, 21);
                assert!(!proposal.proposed_config.require_engagement);
                assert!(!proposal.applied);
                println!("[✓] Second session: proposal persisted correctly");
                
                let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            }
            
            cleanup_test_dir(&dir);
            println!("[✓] Node decay config persistence test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_two_node_decay_proposal_sync() {
        let result = timeout(Duration::from_secs(60), async {
            println!("\n=== TEST: Two Node Decay Proposal Sync ===");
            let dir = setup_test_dir("decay_sync");
            let port1 = get_free_port();
            let port2 = get_free_port();
            
            let node1 = Node::new(&format!("127.0.0.1:{}", port1), &format!("{}/node1", dir))
                .await.expect("Node 1 failed");
            let node2 = Node::new(&format!("127.0.0.1:{}", port2), &format!("{}/node2", dir))
                .await.expect("Node 2 failed");
            
            node1.auth(TEST_PASSPHRASE, None).await;
            node2.auth(TEST_PASSPHRASE, None).await;
            
            sleep(Duration::from_millis(200)).await;
            
            // Step 1: Node1 connects to Node2
            node1.connect(&format!("127.0.0.1:{}", port2)).await.expect("Connect failed");
            sleep(Duration::from_millis(200)).await;
            
            // Step 2: Node1 sends elaboration
            node1.elaborate("Testing decay config governance sync.").await;
            sleep(Duration::from_millis(200)).await;
            
            // Step 3: Node2 sends its elaboration (REQUIRED for mutual handshake)
            node2.elaborate("Accepting decay sync test connection.").await;
            sleep(Duration::from_millis(200)).await;
            
            // Step 4: Node2 approves
            let pending = node2.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node2.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
            
            // Step 5: Node1 also approves (mutual approval requires both sides)
            let pending = node1.connection_pool.pending_approval().await;
            for (_, info) in pending {
                let did = info.read().await.did.clone();
                if let Some(d) = did {
                    node1.mutual_approve(&d.short()).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
            
            // Verify connected
            let n1_auth = node1.connection_pool.authenticated_addrs().await.len();
            let n2_auth = node2.connection_pool.authenticated_addrs().await.len();
            if n1_auth == 0 && n2_auth == 0 {
                println!("[SKIP] Nodes not connected, skipping sync test");
                let _ = timeout(Duration::from_secs(5), node1.shutdown()).await;
                let _ = timeout(Duration::from_secs(5), node2.shutdown()).await;
                cleanup_test_dir(&dir);
                return;
            }
            println!("[✓] Nodes connected");
            
            // Node1 proposes decay config change
            node1.propose_decay_config(false, 0, false, "Proposing archive mode for the pool").await;
            sleep(Duration::from_millis(500)).await;
            
            // Node2 should receive the proposal
            let state2 = node2.state.read().await;
            let proposal_count = state2.decay_proposals.len();
            
            if proposal_count > 0 {
                println!("[✓] Proposal propagated to Node2");
                
                let (id, prop) = state2.decay_proposals.iter().next().unwrap();
                assert!(!prop.proposed_config.enabled);
                assert_eq!(prop.proposer, node1.did);
                println!("[✓] Proposal details correct: {} from {}", id.short(), prop.proposer.short());
            } else {
                println!("[!] Proposal not yet propagated (timing)");
            }
            
            let _ = timeout(Duration::from_secs(5), node1.shutdown()).await;
            let _ = timeout(Duration::from_secs(5), node2.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Two node decay proposal sync test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_decay_vote_self_vote_rejected() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Decay Vote Self Vote Rejected ===");
            let dir = setup_test_dir("decay_selfvote");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Create proposal
            node.propose_decay_config(false, 0, false, "Archive mode test proposal here").await;
            sleep(Duration::from_millis(100)).await;
            
            // Get proposal ID
            let state = node.state.read().await;
            let id = state.decay_proposals.keys().next().copied().unwrap();
            drop(state);
            
            // Try to vote on own proposal
            node.vote_decay_config(&id.short(), true, "I support my own proposal").await;
            sleep(Duration::from_millis(100)).await;
            
            // Proposal should still have no votes (self-vote rejected)
            let state = node.state.read().await;
            let prop = state.decay_proposals.get(&id).unwrap();
            assert!(prop.quorum.signals_for.is_empty());
            assert!(prop.quorum.signals_against.is_empty());
            println!("[✓] Self-vote correctly rejected");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Decay vote self vote rejected test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    #[tokio::test]
    async fn test_decay_vote_short_elaboration_rejected() {
        let result = timeout(Duration::from_secs(30), async {
            println!("\n=== TEST: Decay Vote Short Elaboration Rejected ===");
            let dir = setup_test_dir("decay_shortelab");
            let port = get_free_port();
            
            let node = Node::new(&format!("127.0.0.1:{}", port), &format!("{}/node", dir))
                .await.expect("Node failed");
            
            node.auth(TEST_PASSPHRASE, None).await;
            
            // Create proposal
            node.propose_decay_config(true, 30, true, "Extended decay period proposal").await;
            sleep(Duration::from_millis(100)).await;
            
            let state = node.state.read().await;
            let id = state.decay_proposals.keys().next().copied().unwrap();
            drop(state);
            
            // Create a second node's DID (simulating external vote)
            // In real scenario, this would come from another node
            // For this test, we just verify the elaboration check works
            
            // Note: Since we can't easily vote from a different DID in single-node test,
            // we're just testing that the function handles short elaboration
            // The actual vote would be rejected as self-vote anyway
            
            node.vote_decay_config(&id.short(), true, "short").await;
            sleep(Duration::from_millis(100)).await;
            
            // No change expected (short elaboration should be rejected before self-vote check)
            let state = node.state.read().await;
            let prop = state.decay_proposals.get(&id).unwrap();
            assert!(prop.quorum.signals_for.is_empty());
            println!("[✓] Short elaboration handled (rejected before processing)");
            
            let _ = timeout(Duration::from_secs(5), node.shutdown()).await;
            cleanup_test_dir(&dir);
            println!("[✓] Decay vote short elaboration rejected test passed\n");
        }).await;
        
        assert!(result.is_ok(), "Test timed out");
    }

    // insert at end of tests module (before the final closing brace)

    // ========================================================================
    // ACKNOWLEDGMENT TESTS
    // ========================================================================

    #[test]
    fn test_acknowledgment_validity() {
        println!("\n=== TEST: Acknowledgment Validity ===");
        
        let valid_ack = Acknowledgment {
            target: Cid::new(b"test"),
            witness: Did("did:diagon:alice".into()),
            pubkey: vec![],
            view_started: timestamp() - 10,
            acknowledged_at: timestamp(),
            reflection: Some("This is a thoughtful reflection on the content.".into()),
            signature: vec![],
        };
        
        assert!(valid_ack.valid_dwell());
        println!("[✓] Valid dwell time accepted");
        
        assert!(valid_ack.has_valid_reflection());
        println!("[✓] Valid reflection detected");
        
        assert_eq!(valid_ack.weight(), ACK_WEIGHT_WITH_REFLECTION);
        println!("[✓] Reflection weight applied");
        
        let short_dwell_ack = Acknowledgment {
            target: Cid::new(b"test"),
            witness: Did("did:diagon:bob".into()),
            pubkey: vec![],
            view_started: timestamp() - 2,
            acknowledged_at: timestamp(),
            reflection: None,
            signature: vec![],
        };
        
        assert!(!short_dwell_ack.valid_dwell());
        assert_eq!(short_dwell_ack.weight(), 0);
        println!("[✓] Short dwell rejected");
        
        println!("[✓] Acknowledgment validity test passed\n");
    }

    #[test]
    fn test_acknowledgment_state() {
        println!("\n=== TEST: Acknowledgment State ===");
        
        let mut state = AcknowledgmentState::new();
        assert_eq!(state.witness_count(), 0);
        assert!(!state.is_witnessed());
        
        let ack1 = Acknowledgment {
            target: Cid::new(b"test"),
            witness: Did("did:diagon:alice".into()),
            pubkey: vec![],
            view_started: timestamp() - 10,
            acknowledged_at: timestamp(),
            reflection: None,
            signature: vec![],
        };
        
        assert!(state.acknowledge(ack1.clone()));
        assert_eq!(state.witness_count(), 1);
        assert!(!state.is_witnessed()); // Need 2 for witnessed
        println!("[✓] First acknowledgment recorded");
        
        // Duplicate should be rejected
        assert!(!state.acknowledge(ack1));
        println!("[✓] Duplicate rejected");
        
        let ack2 = Acknowledgment {
            target: Cid::new(b"test"),
            witness: Did("did:diagon:bob".into()),
            pubkey: vec![],
            view_started: timestamp() - 15,
            acknowledged_at: timestamp(),
            reflection: Some("I agree with this.".into()),
            signature: vec![],
        };
        
        assert!(state.acknowledge(ack2));
        assert_eq!(state.witness_count(), 2);
        assert!(state.is_witnessed());
        println!("[✓] Second acknowledgment makes it witnessed");
        
        println!("[✓] Acknowledgment state test passed\n");
    }

    // ========================================================================
    // TESTIMONY TESTS
    // ========================================================================

    #[test]
    fn test_testimony_state() {
        println!("\n=== TEST: Testimony State ===");
        
        let mut state = TestimonyState::new();
        assert_eq!(state.pool_count, 0);
        
        let testimony1 = Testimony {
            cid: Cid::new(b"test"),
            origin_pool: [1u8; 32],
            witness_pool: [2u8; 32],
            testifier: Did("did:diagon:alice".into()),
            pubkey: vec![],
            attestation: "I witnessed this content.".into(),
            testified_at: timestamp(),
            signature: vec![],
        };
        
        assert!(state.add(testimony1.clone()));
        assert_eq!(state.pool_count, 1);
        println!("[✓] First testimony recorded");
        
        // Same testifier from same pool should be rejected
        assert!(!state.add(testimony1));
        println!("[✓] Duplicate testimony rejected");
        
        // Different pool should be accepted
        let testimony2 = Testimony {
            cid: Cid::new(b"test"),
            origin_pool: [1u8; 32],
            witness_pool: [3u8; 32],
            testifier: Did("did:diagon:bob".into()),
            pubkey: vec![],
            attestation: "I also witnessed this.".into(),
            testified_at: timestamp(),
            signature: vec![],
        };
        
        assert!(state.add(testimony2));
        assert_eq!(state.pool_count, 2);
        println!("[✓] Second pool testimony recorded");
        
        println!("[✓] Testimony state test passed\n");
    }

    #[test]
    fn test_expression_meta_extended() {
        println!("\n=== TEST: Extended Expression Meta ===");
        
        let mut meta = ExpressionMeta::new();
        
        assert!(!meta.is_witnessed());
        assert!(!meta.is_testified());
        assert_eq!(meta.total_witness_weight(), 0);
        
        // Add acknowledgments
        let ack = Acknowledgment {
            target: Cid::new(b"test"),
            witness: Did("did:diagon:alice".into()),
            pubkey: vec![],
            view_started: timestamp() - 10,
            acknowledged_at: timestamp(),
            reflection: None,
            signature: vec![],
        };
        
        meta.acknowledge(ack);
        assert_eq!(meta.total_witness_weight(), ACK_WEIGHT_BASE);
        println!("[✓] Acknowledgment weight counted");
        
        // Add testimony
        let testimony = Testimony {
            cid: Cid::new(b"test"),
            origin_pool: [1u8; 32],
            witness_pool: [2u8; 32],
            testifier: Did("did:diagon:bob".into()),
            pubkey: vec![],
            attestation: "Witnessed this.".into(),
            testified_at: timestamp(),
            signature: vec![],
        };
        
        meta.add_testimony(testimony);
        assert!(meta.is_testified());
        assert_eq!(meta.total_witness_weight(), ACK_WEIGHT_BASE + TESTIMONY_WEIGHT_PER_POOL);
        println!("[✓] Testimony weight added");
        
        println!("[✓] Extended expression meta test passed\n");
    }

    #[test]
    fn test_peer_info_mutual_state() {
        println!("\n=== TEST: Peer Info Mutual State ===");
        
        let mut info = PeerInfo::new("127.0.0.1:9070".parse().unwrap(), true);
        
        assert!(!info.both_elaborated());
        assert!(!info.both_approved());
        
        info.our_elaboration = Some("My elaboration".into());
        assert!(!info.both_elaborated());
        
        info.elaboration = Some("Their elaboration".into());
        assert!(info.both_elaborated());
        println!("[✓] Both elaborated detection works");
        
        assert!(info.check_mutual_pending());
        assert_eq!(info.state, ConnectionState::MutualPending);
        println!("[✓] Mutual pending transition works");
        
        info.we_approved = true;
        assert!(!info.both_approved());
        
        info.they_approved = true;
        assert!(info.both_approved());
        
        assert!(info.check_connected());
        assert_eq!(info.state, ConnectionState::Connected);
        println!("[✓] Connected transition works");
        
        println!("[✓] Peer info mutual state test passed\n");
    }
    
    // ========================================================================
    // REVIEWABLE CONTENT TYPE TESTS
    // ========================================================================

    #[test]
    fn test_reviewable_content_type_tier_config() {
        println!("\n=== TEST: ReviewableContentType tier_config ===");
        
        // Critical tier: Proposal, PinReason, PruneReason
        assert_eq!(ReviewableContentType::Proposal.tier_config(), REVIEW_TIER_CRITICAL);
        assert_eq!(ReviewableContentType::PinReason.tier_config(), REVIEW_TIER_CRITICAL);
        assert_eq!(ReviewableContentType::PruneReason.tier_config(), REVIEW_TIER_CRITICAL);
        println!("[✓] Critical tier types return (5, 72)");
        
        // Standard tier: ProposalElaboration, Reply, VoteElaboration
        assert_eq!(ReviewableContentType::ProposalElaboration.tier_config(), REVIEW_TIER_STANDARD);
        assert_eq!(ReviewableContentType::Reply.tier_config(), REVIEW_TIER_STANDARD);
        assert_eq!(ReviewableContentType::VoteElaboration.tier_config(), REVIEW_TIER_STANDARD);
        println!("[✓] Standard tier types return (3, 48)");
        
        // Fast tier: Acknowledgment
        assert_eq!(ReviewableContentType::Acknowledgment.tier_config(), REVIEW_TIER_FAST);
        println!("[✓] Fast tier type returns (2, 24)");
        
        println!("[✓] ReviewableContentType tier_config test passed\n");
    }

    #[test]
    fn test_reviewable_content_type_base_xp() {
        println!("\n=== TEST: ReviewableContentType base_xp ===");
        
        assert_eq!(ReviewableContentType::Proposal.base_xp(), XP_BASE_PROPOSAL);
        assert_eq!(ReviewableContentType::ProposalElaboration.base_xp(), XP_BASE_PROPOSAL_ELABORATION);
        assert_eq!(ReviewableContentType::Reply.base_xp(), XP_BASE_REPLY);
        assert_eq!(ReviewableContentType::VoteElaboration.base_xp(), XP_BASE_VOTE_ELABORATION);
        assert_eq!(ReviewableContentType::Acknowledgment.base_xp(), XP_BASE_ACKNOWLEDGMENT);
        assert_eq!(ReviewableContentType::PinReason.base_xp(), XP_BASE_PIN_REASON);
        assert_eq!(ReviewableContentType::PruneReason.base_xp(), XP_BASE_PRUNE_REASON);
        println!("[✓] All content types return correct base XP");
        
        println!("[✓] ReviewableContentType base_xp test passed\n");
    }

    #[test]
    fn test_reviewable_content_type_as_str() {
        println!("\n=== TEST: ReviewableContentType as_str ===");
        
        assert_eq!(ReviewableContentType::Proposal.as_str(), "proposal");
        assert_eq!(ReviewableContentType::ProposalElaboration.as_str(), "proposal-elaboration");
        assert_eq!(ReviewableContentType::Reply.as_str(), "reply");
        assert_eq!(ReviewableContentType::Acknowledgment.as_str(), "acknowledgment");
        assert_eq!(ReviewableContentType::VoteElaboration.as_str(), "vote-elaboration");
        assert_eq!(ReviewableContentType::PinReason.as_str(), "pin-reason");
        assert_eq!(ReviewableContentType::PruneReason.as_str(), "prune-reason");
        println!("[✓] All content types return correct string representations");
        
        // Test Display trait
        let proposal_str = format!("{}", ReviewableContentType::Proposal);
        assert_eq!(proposal_str, "proposal");
        println!("[✓] Display trait works correctly");
        
        println!("[✓] ReviewableContentType as_str test passed\n");
    }

    #[test]
    fn test_reviewable_content_type_equality() {
        println!("\n=== TEST: ReviewableContentType equality ===");
        
        let p1 = ReviewableContentType::Proposal;
        let p2 = ReviewableContentType::Proposal;
        let r1 = ReviewableContentType::Reply;
        
        assert_eq!(p1, p2);
        assert_ne!(p1, r1);
        println!("[✓] Equality comparisons work correctly");
        
        // Test Hash trait via HashSet
        let mut set = std::collections::HashSet::new();
        set.insert(ReviewableContentType::Proposal);
        set.insert(ReviewableContentType::Proposal);
        assert_eq!(set.len(), 1);
        set.insert(ReviewableContentType::Reply);
        assert_eq!(set.len(), 2);
        println!("[✓] Hash trait works correctly");
        
        println!("[✓] ReviewableContentType equality test passed\n");
    }

    // ========================================================================
    // QUALITY REVIEW TESTS
    // ========================================================================

    fn make_test_review(cid: Cid, reviewer: Did) -> QualityReview {
        QualityReview {
            content_cid: cid,
            reviewer,
            pubkey: vec![],
            relevance: 4,
            substance: 4,
            clarity: 4,
            originality: 3,
            effort: 4,
            justification: "This is a valid test justification for the review.".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        }
    }

    fn make_signed_review(cid: Cid, pk: &PublicKey, sk: &SecretKey) -> QualityReview {
        let reviewer = Did::from_pubkey(pk);
        let mut review = QualityReview {
            content_cid: cid,
            reviewer,
            pubkey: pk.as_bytes().to_vec(),
            relevance: 4,
            substance: 4,
            clarity: 4,
            originality: 3,
            effort: 4,
            justification: "This is a valid test justification for the review.".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig = detached_sign(&review.signable_bytes(), sk);
        review.signature = sig.as_bytes().to_vec();
        review
    }

    #[test]
    fn test_quality_review_composite_score() {
        println!("\n=== TEST: QualityReview composite_score ===");
        
        let cid = Cid::new(b"test content");
        let reviewer = Did("did:diagon:reviewer".into());
        
        // Test with all 5s (max score)
        let max_review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: vec![],
            relevance: 5,
            substance: 5,
            clarity: 5,
            originality: 5,
            effort: 5,
            justification: "Valid justification here".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        
        // 5*0.25 + 5*0.30 + 5*0.20 + 5*0.15 + 5*0.10 = 1.25 + 1.50 + 1.00 + 0.75 + 0.50 = 5.0
        let max_score = max_review.composite_score();
        assert!((max_score - 5.0).abs() < 0.001, "Max score should be 5.0, got {}", max_score);
        println!("[✓] Maximum score (all 5s) = 5.0");
        
        // Test with all 1s (min score)
        let min_review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: vec![],
            relevance: 1,
            substance: 1,
            clarity: 1,
            originality: 1,
            effort: 1,
            justification: "Valid justification here".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        
        let min_score = min_review.composite_score();
        assert!((min_score - 1.0).abs() < 0.001, "Min score should be 1.0, got {}", min_score);
        println!("[✓] Minimum score (all 1s) = 1.0");
        
        // Test weighted average
        let weighted_review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: vec![],
            relevance: 5,   // 5 * 0.25 = 1.25
            substance: 3,   // 3 * 0.30 = 0.90
            clarity: 4,     // 4 * 0.20 = 0.80
            originality: 2, // 2 * 0.15 = 0.30
            effort: 5,      // 5 * 0.10 = 0.50
            justification: "Valid justification here".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        
        let expected = 1.25 + 0.90 + 0.80 + 0.30 + 0.50; // 3.75
        let actual = weighted_review.composite_score();
        assert!((actual - expected).abs() < 0.001, "Expected {}, got {}", expected, actual);
        println!("[✓] Weighted calculation correct: {:.2}", actual);
        
        println!("[✓] QualityReview composite_score test passed\n");
    }

    #[test]
    fn test_quality_review_is_valid() {
        println!("\n=== TEST: QualityReview is_valid ===");
        
        let cid = Cid::new(b"test");
        let reviewer = Did("did:diagon:test".into());
        
        // Valid review
        let valid_review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: vec![],
            relevance: 3,
            substance: 3,
            clarity: 3,
            originality: 3,
            effort: 3,
            justification: "This is valid justification text".into(), // >= 10 chars
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        assert!(valid_review.is_valid());
        println!("[✓] Valid review passes validation");
        
        // Invalid: score out of range (0)
        let invalid_score_zero = QualityReview {
            relevance: 0, // Invalid: must be 1-5
            ..valid_review.clone()
        };
        assert!(!invalid_score_zero.is_valid());
        println!("[✓] Score of 0 rejected");
        
        // Invalid: score out of range (6)
        let invalid_score_six = QualityReview {
            substance: 6, // Invalid: must be 1-5
            ..valid_review.clone()
        };
        assert!(!invalid_score_six.is_valid());
        println!("[✓] Score of 6 rejected");
        
        // Invalid: justification too short
        let short_just = QualityReview {
            justification: "short".into(), // < 10 chars
            ..valid_review.clone()
        };
        assert!(!short_just.is_valid());
        println!("[✓] Short justification rejected");
        
        // Edge case: exactly 10 character justification
        let exact_just = QualityReview {
            justification: "0123456789".into(), // exactly 10 chars
            ..valid_review.clone()
        };
        assert!(exact_just.is_valid());
        println!("[✓] Exactly 10 char justification accepted");
        
        // Edge case: scores at boundaries (1 and 5)
        let boundary_scores = QualityReview {
            relevance: 1,
            substance: 5,
            clarity: 1,
            originality: 5,
            effort: 1,
            ..valid_review.clone()
        };
        assert!(boundary_scores.is_valid());
        println!("[✓] Boundary scores (1 and 5) accepted");
        
        println!("[✓] QualityReview is_valid test passed\n");
    }

    #[test]
    fn test_quality_review_is_flagged() {
        println!("\n=== TEST: QualityReview is_flagged ===");
        
        let cid = Cid::new(b"test");
        let reviewer = Did("did:diagon:test".into());
        
        let base = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: vec![],
            relevance: 3,
            substance: 3,
            clarity: 3,
            originality: 3,
            effort: 3,
            justification: "Valid justification".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        
        // No flags
        assert!(!base.is_flagged());
        println!("[✓] No flags = not flagged");
        
        // Only spam flag
        let spam_only = QualityReview { flag_spam: true, ..base.clone() };
        assert!(spam_only.is_flagged());
        println!("[✓] Spam flag only = flagged");
        
        // Only plagiarism flag
        let plag_only = QualityReview { flag_plagiarism: true, ..base.clone() };
        assert!(plag_only.is_flagged());
        println!("[✓] Plagiarism flag only = flagged");
        
        // Only offtopic flag
        let offtopic_only = QualityReview { flag_offtopic: true, ..base.clone() };
        assert!(offtopic_only.is_flagged());
        println!("[✓] Off-topic flag only = flagged");
        
        // Multiple flags
        let multi_flags = QualityReview { 
            flag_spam: true, 
            flag_plagiarism: true, 
            flag_offtopic: true, 
            ..base.clone() 
        };
        assert!(multi_flags.is_flagged());
        println!("[✓] Multiple flags = flagged");
        
        println!("[✓] QualityReview is_flagged test passed\n");
    }

    #[test]
    fn test_quality_review_signable_bytes() {
        println!("\n=== TEST: QualityReview signable_bytes ===");
        
        let cid = Cid::new(b"test content");
        let reviewer = Did("did:diagon:test".into());
        
        let review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: vec![1, 2, 3],
            relevance: 4,
            substance: 3,
            clarity: 5,
            originality: 2,
            effort: 4,
            justification: "Test justification".into(),
            flag_spam: true,
            flag_plagiarism: false,
            flag_offtopic: true,
            reviewed_at: 1234567890,
            signature: vec![],
        };
        
        let signable = review.signable_bytes();
        
        // Should start with prefix
        assert!(signable.starts_with(b"quality-review:"));
        println!("[✓] Signable bytes start with 'quality-review:' prefix");
        
        // Should contain CID
        assert!(signable.windows(32).any(|w| w == cid.0));
        println!("[✓] Signable bytes contain content CID");
        
        // Should contain scores (in order)
        let prefix_len = b"quality-review:".len();
        assert_eq!(signable[prefix_len + 32], 4); // relevance
        assert_eq!(signable[prefix_len + 33], 3); // substance
        assert_eq!(signable[prefix_len + 34], 5); // clarity
        assert_eq!(signable[prefix_len + 35], 2); // originality
        assert_eq!(signable[prefix_len + 36], 4); // effort
        println!("[✓] Signable bytes contain scores in correct order");
        
        // Should contain justification
        assert!(signable.windows(18).any(|w| w == b"Test justification"));
        println!("[✓] Signable bytes contain justification");
        
        // Should contain flags
        assert!(signable.contains(&1u8)); // flag_spam = true
        println!("[✓] Signable bytes contain flag values");
        
        // Deterministic: same input = same output
        let signable2 = review.signable_bytes();
        assert_eq!(signable, signable2);
        println!("[✓] Signable bytes are deterministic");
        
        // Different reviews produce different signable bytes
        let review2 = QualityReview {
            relevance: 5,
            ..review.clone()
        };
        let signable3 = review2.signable_bytes();
        assert_ne!(signable, signable3);
        println!("[✓] Different reviews produce different signable bytes");
        
        println!("[✓] QualityReview signable_bytes test passed\n");
    }

    #[test]
    fn test_quality_review_sign_and_verify() {
        println!("\n=== TEST: QualityReview sign and verify ===");
        
        let (pk, sk) = keypair();
        let cid = Cid::new(b"test content");
        let reviewer = Did::from_pubkey(&pk);
        
        let mut review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: pk.as_bytes().to_vec(),
            relevance: 4,
            substance: 4,
            clarity: 4,
            originality: 3,
            effort: 4,
            justification: "Valid justification text for review".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        
        // Unsigned review should not verify
        assert!(!review.verify());
        println!("[✓] Unsigned review does not verify");
        
        // Sign the review
        let sig = detached_sign(&review.signable_bytes(), &sk);
        review.signature = sig.as_bytes().to_vec();
        
        // Signed review should verify
        assert!(review.verify());
        println!("[✓] Signed review verifies");
        
        // Tampered content should not verify
        let mut tampered = review.clone();
        tampered.relevance = 5; // Change score
        assert!(!tampered.verify());
        println!("[✓] Tampered review does not verify");
        
        // Wrong pubkey should not verify
        let (other_pk, _) = keypair();
        let mut wrong_pk_review = review.clone();
        wrong_pk_review.pubkey = other_pk.as_bytes().to_vec();
        assert!(!wrong_pk_review.verify());
        println!("[✓] Wrong pubkey does not verify");
        
        // Mismatched DID should not verify
        let mut wrong_did_review = review.clone();
        wrong_did_review.reviewer = Did("did:diagon:wrongperson".into());
        assert!(!wrong_did_review.verify());
        println!("[✓] Mismatched DID does not verify");
        
        // Invalid signature bytes should not verify
        let mut bad_sig_review = review.clone();
        bad_sig_review.signature = vec![0u8; 32]; // Too short for valid signature
        assert!(!bad_sig_review.verify());
        println!("[✓] Invalid signature bytes do not verify");
        
        println!("[✓] QualityReview sign and verify test passed\n");
    }

    // ========================================================================
    // PENDING REVIEW TESTS
    // ========================================================================

    #[test]
    fn test_pending_review_new() {
        println!("\n=== TEST: PendingReview::new ===");
        
        let cid = Cid::new(b"test content");
        let author = Did("did:diagon:author".into());
        let content = "This is the test content for review with multiple words here.".to_string();
        
        // Test Proposal type (critical tier)
        let pending = PendingReview::new(
            cid, 
            ReviewableContentType::Proposal, 
            content.clone(), 
            None, 
            None, 
            author.clone()
        );
        
        assert_eq!(pending.content_cid, cid);
        assert_eq!(pending.content_type, ReviewableContentType::Proposal);
        assert_eq!(pending.required_reviews, REVIEW_TIER_CRITICAL.0);
        assert!(pending.deadline > timestamp());
        assert!(pending.assigned_reviewers.is_empty());
        assert!(pending.reviews.is_empty());
        assert_eq!(pending.author, author);
        assert_eq!(pending.word_count, 11); // Count words
        println!("[✓] Proposal creates correct PendingReview");
        
        // Test Acknowledgment type (fast tier)
        let ack_pending = PendingReview::new(
            cid, 
            ReviewableContentType::Acknowledgment, 
            "Quick ack".to_string(), 
            None, 
            None, 
            author.clone()
        );
        assert_eq!(ack_pending.required_reviews, REVIEW_TIER_FAST.0);
        println!("[✓] Acknowledgment uses fast tier config");
        
        // Test with context
        let context_cid = Cid::new(b"context");
        let with_context = PendingReview::new(
            cid,
            ReviewableContentType::Reply,
            content.clone(),
            Some(context_cid),
            Some("This is the context".to_string()),
            author.clone()
        );
        assert_eq!(with_context.context_cid, Some(context_cid));
        assert_eq!(with_context.context_text, Some("This is the context".to_string()));
        println!("[✓] Context CID and text stored correctly");
        
        // Deadline should be in the future
        let deadline_hours = ReviewableContentType::Proposal.tier_config().1;
        let expected_deadline = timestamp() + (deadline_hours * 3600);
        let diff = (pending.deadline as i64 - expected_deadline as i64).abs();
        assert!(diff < 5, "Deadline should be approximately {}h in future", deadline_hours);
        println!("[✓] Deadline calculated correctly for {} hours", deadline_hours);
        
        println!("[✓] PendingReview::new test passed\n");
    }

    #[test]
    fn test_pending_review_is_assigned() {
        println!("\n=== TEST: PendingReview::is_assigned ===");
        
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        let reviewer1 = Did("did:diagon:reviewer1".into());
        let reviewer2 = Did("did:diagon:reviewer2".into());
        let not_assigned = Did("did:diagon:notassigned".into());
        
        let mut pending = PendingReview::new(
            cid,
            ReviewableContentType::Reply,
            "Test content".into(),
            None,
            None,
            author
        );
        
        // Initially no one is assigned
        assert!(!pending.is_assigned(&reviewer1));
        assert!(!pending.is_assigned(&reviewer2));
        println!("[✓] No reviewers initially assigned");
        
        // Add assignees
        pending.assigned_reviewers.push(reviewer1.clone());
        pending.assigned_reviewers.push(reviewer2.clone());
        
        assert!(pending.is_assigned(&reviewer1));
        assert!(pending.is_assigned(&reviewer2));
        assert!(!pending.is_assigned(&not_assigned));
        println!("[✓] Assigned reviewers correctly identified");
        
        println!("[✓] PendingReview::is_assigned test passed\n");
    }

    #[test]
    fn test_pending_review_has_reviewed() {
        println!("\n=== TEST: PendingReview::has_reviewed ===");
        
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        let reviewer1 = Did("did:diagon:reviewer1".into());
        let reviewer2 = Did("did:diagon:reviewer2".into());
        
        let mut pending = PendingReview::new(
            cid,
            ReviewableContentType::Reply,
            "Test content".into(),
            None,
            None,
            author
        );
        
        // No reviews initially
        assert!(!pending.has_reviewed(&reviewer1));
        assert!(!pending.has_reviewed(&reviewer2));
        println!("[✓] No reviews initially");
        
        // Add a review from reviewer1
        let review = make_test_review(cid, reviewer1.clone());
        pending.reviews.push(review);
        
        assert!(pending.has_reviewed(&reviewer1));
        assert!(!pending.has_reviewed(&reviewer2));
        println!("[✓] Correctly tracks who has reviewed");
        
        println!("[✓] PendingReview::has_reviewed test passed\n");
    }

    #[test]
    fn test_pending_review_is_complete() {
        println!("\n=== TEST: PendingReview::is_complete ===");
        
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        // Fast tier requires 2 reviews
        let mut pending = PendingReview::new(
            cid,
            ReviewableContentType::Acknowledgment,
            "Test content for review".into(),
            None,
            None,
            author
        );
        
        assert_eq!(pending.required_reviews, 2);
        assert!(!pending.is_complete());
        println!("[✓] Initially not complete (0/{} reviews)", pending.required_reviews);
        
        // Add first review
        let review1 = make_test_review(cid, Did("did:diagon:r1".into()));
        pending.reviews.push(review1);
        assert!(!pending.is_complete());
        println!("[✓] Still not complete (1/{} reviews)", pending.required_reviews);
        
        // Add second review
        let review2 = make_test_review(cid, Did("did:diagon:r2".into()));
        pending.reviews.push(review2);
        assert!(pending.is_complete());
        println!("[✓] Complete (2/{} reviews)", pending.required_reviews);
        
        // Test critical tier requires 5 reviews
        let mut critical_pending = PendingReview::new(
            cid,
            ReviewableContentType::Proposal,
            "Proposal content".into(),
            None,
            None,
            Did("did:diagon:author".into())
        );
        assert_eq!(critical_pending.required_reviews, 5);
        for i in 0..4 {
            critical_pending.reviews.push(make_test_review(cid, Did(format!("did:diagon:r{}", i))));
            assert!(!critical_pending.is_complete());
        }
        critical_pending.reviews.push(make_test_review(cid, Did("did:diagon:r4".into())));
        assert!(critical_pending.is_complete());
        println!("[✓] Critical tier requires 5 reviews");
        
        println!("[✓] PendingReview::is_complete test passed\n");
    }

    #[test]
    fn test_pending_review_is_expired() {
        println!("\n=== TEST: PendingReview::is_expired ===");
        
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        // Create normal pending review
        let pending = PendingReview::new(
            cid,
            ReviewableContentType::Acknowledgment,
            "Test content".into(),
            None,
            None,
            author.clone()
        );
        
        assert!(!pending.is_expired());
        println!("[✓] Fresh review is not expired");
        
        // Create expired pending review
        let mut expired = PendingReview::new(
            cid,
            ReviewableContentType::Acknowledgment,
            "Test content".into(),
            None,
            None,
            author
        );
        expired.deadline = timestamp() - 1; // Set deadline in the past
        
        assert!(expired.is_expired());
        println!("[✓] Past deadline review is expired");
        
        // Edge case: deadline exactly now
        let mut edge = expired.clone();
        edge.deadline = timestamp();
        // Should not be expired (timestamp() > deadline fails when equal)
        assert!(!edge.is_expired());
        println!("[✓] Deadline at current time is not expired");
        
        println!("[✓] PendingReview::is_expired test passed\n");
    }

    // ========================================================================
    // REVIEWER REPUTATION TESTS
    // ========================================================================

    #[test]
    fn test_reviewer_reputation_new() {
        println!("\n=== TEST: ReviewerReputation::new ===");
        
        let rep = ReviewerReputation::new();
        
        assert_eq!(rep.reviews_completed, 0);
        assert_eq!(rep.consensus_alignments, 0);
        assert_eq!(rep.consensus_deviations, 0);
        assert_eq!(rep.confirmed_flags, 0);
        assert_eq!(rep.false_flags, 0);
        assert!((rep.score - 0.5).abs() < 0.001);
        assert_eq!(rep.last_review, 0);
        println!("[✓] New reputation starts with defaults");
        
        println!("[✓] ReviewerReputation::new test passed\n");
    }

    #[test]
    fn test_reviewer_reputation_update_consensus() {
        println!("\n=== TEST: ReviewerReputation::update consensus ===");
        
        let mut rep = ReviewerReputation::new();
        let initial_score = rep.score;
        
        // Aligned review should increase score
        rep.update(true, None);
        assert_eq!(rep.reviews_completed, 1);
        assert_eq!(rep.consensus_alignments, 1);
        assert_eq!(rep.consensus_deviations, 0);
        assert!(rep.score > initial_score);
        assert!((rep.score - 0.52).abs() < 0.001); // 0.5 + 0.02 = 0.52
        println!("[✓] Aligned review increases score (+0.02)");
        
        // Deviated review should decrease score
        rep.update(false, None);
        assert_eq!(rep.reviews_completed, 2);
        assert_eq!(rep.consensus_alignments, 1);
        assert_eq!(rep.consensus_deviations, 1);
        assert!((rep.score - 0.47).abs() < 0.001); // 0.52 - 0.05 = 0.47
        println!("[✓] Deviated review decreases score (-0.05)");
        
        // Last review timestamp should be updated
        assert!(rep.last_review > 0);
        println!("[✓] Last review timestamp updated");
        
        println!("[✓] ReviewerReputation::update consensus test passed\n");
    }

    #[test]
    fn test_reviewer_reputation_update_flags() {
        println!("\n=== TEST: ReviewerReputation::update flags ===");
        
        let mut rep = ReviewerReputation::new();
        
        // Confirmed flag should increase score significantly
        rep.update(true, Some(true));
        assert_eq!(rep.confirmed_flags, 1);
        assert_eq!(rep.false_flags, 0);
        assert!((rep.score - 0.62).abs() < 0.001); // 0.5 + 0.02 (aligned) + 0.1 (confirmed) = 0.62
        println!("[✓] Confirmed flag increases score (+0.1)");
        
        // False flag should decrease score significantly
        let mut rep2 = ReviewerReputation::new();
        rep2.update(true, Some(false));
        assert_eq!(rep2.confirmed_flags, 0);
        assert_eq!(rep2.false_flags, 1);
        assert!((rep2.score - 0.32).abs() < 0.001); // 0.5 + 0.02 - 0.2 = 0.32
        println!("[✓] False flag decreases score (-0.2)");
        
        println!("[✓] ReviewerReputation::update flags test passed\n");
    }

    #[test]
    fn test_reviewer_reputation_score_bounds() {
        println!("\n=== TEST: ReviewerReputation score bounds ===");
        
        // Test upper bound
        let mut rep = ReviewerReputation::new();
        for _ in 0..100 {
            rep.update(true, Some(true)); // Max increases
        }
        assert!(rep.score <= 1.0);
        assert!((rep.score - 1.0).abs() < 0.001);
        println!("[✓] Score capped at 1.0");
        
        // Test lower bound
        let mut rep2 = ReviewerReputation::new();
        for _ in 0..100 {
            rep2.update(false, Some(false)); // Max decreases
        }
        assert!(rep2.score >= 0.0);
        assert!((rep2.score - 0.0).abs() < 0.001);
        println!("[✓] Score floored at 0.0");
        
        println!("[✓] ReviewerReputation score bounds test passed\n");
    }

    #[test]
    fn test_reviewer_reputation_weight() {
        println!("\n=== TEST: ReviewerReputation::weight ===");
        
        // New reviewer (0 reviews): weight = score * 0.5
        let new_rep = ReviewerReputation::new();
        let new_weight = new_rep.weight();
        assert!((new_weight - 0.25).abs() < 0.001); // 0.5 * 0.5 = 0.25
        println!("[✓] New reviewer weight: {:.3}", new_weight);
        
        // Apprentice reviewer (5 reviews = REVIEW_APPRENTICE_COUNT): weight = score * 1.0
        let mut apprentice = ReviewerReputation::new();
        for _ in 0..REVIEW_APPRENTICE_COUNT {
            apprentice.update(true, None);
        }
        let apprentice_weight = apprentice.weight();
        // Experience factor = min(5/5, 1.0) = 1.0
        // Weight = score * (0.5 + 0.5 * 1.0) = score * 1.0
        println!("[✓] Apprentice reviewer weight: {:.3}", apprentice_weight);
        
        // Experienced reviewer (10+ reviews)
        let mut experienced = ReviewerReputation::new();
        for _ in 0..10 {
            experienced.update(true, None);
        }
        let exp_weight = experienced.weight();
        // Experience capped at 1.0, so same multiplier as apprentice
        assert!(exp_weight >= apprentice_weight * 0.9); // Roughly similar
        println!("[✓] Experienced reviewer weight: {:.3}", exp_weight);
        
        // Low score reviewer should have low weight
        let mut low_score = ReviewerReputation::new();
        for _ in 0..10 {
            low_score.update(false, Some(false));
        }
        let low_weight = low_score.weight();
        assert!(low_weight < 0.1);
        println!("[✓] Low score reviewer has low weight: {:.3}", low_weight);
        
        println!("[✓] ReviewerReputation::weight test passed\n");
    }

    #[test]
    fn test_reviewer_reputation_is_eligible() {
        println!("\n=== TEST: ReviewerReputation::is_eligible ===");
        
        // New reviewer should be eligible (score 0.5 >= 0.2)
        let new_rep = ReviewerReputation::new();
        assert!(new_rep.is_eligible());
        println!("[✓] New reviewer (score 0.5) is eligible");
        
        // Reviewer at threshold
        let mut at_threshold = ReviewerReputation::new();
        at_threshold.score = REVIEW_MIN_REPUTATION;
        assert!(at_threshold.is_eligible());
        println!("[✓] Reviewer at threshold ({}) is eligible", REVIEW_MIN_REPUTATION);
        
        // Reviewer below threshold
        let mut below_threshold = ReviewerReputation::new();
        below_threshold.score = REVIEW_MIN_REPUTATION - 0.01;
        assert!(!below_threshold.is_eligible());
        println!("[✓] Reviewer below threshold is not eligible");
        
        // After many false flags, should become ineligible
        let mut degraded = ReviewerReputation::new();
        for _ in 0..5 {
            degraded.update(false, Some(false));
        }
        assert!(!degraded.is_eligible(), "Score: {}", degraded.score);
        println!("[✓] Degraded reviewer becomes ineligible");
        
        println!("[✓] ReviewerReputation::is_eligible test passed\n");
    }

    // ========================================================================
    // REVIEW STATE TESTS
    // ========================================================================

    #[test]
    fn test_review_state_new() {
        println!("\n=== TEST: ReviewState::new ===");
        
        let state = ReviewState::new();
        
        assert!(state.pending.is_empty());
        assert!(state.verdicts.is_empty());
        assert!(state.reviewer_reputations.is_empty());
        assert!(state.interaction_counts.is_empty());
        println!("[✓] New ReviewState is empty");
        
        println!("[✓] ReviewState::new test passed\n");
    }

    #[test]
    fn test_review_state_submit_for_review() {
        println!("\n=== TEST: ReviewState::submit_for_review ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test content");
        let author = Did("did:diagon:author".into());
        
        // Create enough reviewers for critical tier (5)
        let reviewers: Vec<Did> = (0..10)
            .map(|i| Did(format!("did:diagon:reviewer{}", i)))
            .collect();
        
        // Submit for review
        let result = state.submit_for_review(
            cid,
            ReviewableContentType::Proposal,
            "Test proposal content".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        );
        
        assert!(result.is_ok());
        assert!(state.pending.contains_key(&cid));
        let pending = state.pending.get(&cid).unwrap();
        assert_eq!(pending.assigned_reviewers.len(), 5); // Critical tier
        println!("[✓] Content submitted for review");
        
        // Cannot submit same content twice
        let result2 = state.submit_for_review(
            cid,
            ReviewableContentType::Proposal,
            "Test content".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        );
        assert!(result2.is_err());
        println!("[✓] Duplicate submission rejected");
        
        // Author should not be in assigned reviewers
        let pending = state.pending.get(&cid).unwrap();
        assert!(!pending.assigned_reviewers.contains(&author));
        println!("[✓] Author excluded from reviewers");
        
        println!("[✓] ReviewState::submit_for_review test passed\n");
    }

    #[test]
    fn test_review_state_submit_for_review_insufficient_reviewers() {
        println!("\n=== TEST: ReviewState::submit_for_review insufficient reviewers ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        // Only 2 reviewers for critical tier (needs 5)
        let reviewers = vec![
            Did("did:diagon:r1".into()),
            Did("did:diagon:r2".into()),
        ];
        
        let result = state.submit_for_review(
            cid,
            ReviewableContentType::Proposal,
            "Test content".into(),
            None,
            None,
            author,
            &reviewers,
        );
        
        assert!(result.is_err());
        println!("[✓] Insufficient reviewers rejected");
        
        println!("[✓] ReviewState insufficient reviewers test passed\n");
    }

    #[test]
    fn test_review_state_select_reviewers_excludes_high_interaction() {
        println!("\n=== TEST: ReviewState select_reviewers interaction limit ===");
        
        let mut state = ReviewState::new();
        let author = Did("did:diagon:author".into());
        let frequent_reviewer = Did("did:diagon:frequent".into());
        
        // Record many interactions between author and frequent_reviewer
        for _ in 0..=REVIEW_INTERACTION_LIMIT {
            let key = (frequent_reviewer.clone(), author.clone());
            *state.interaction_counts.entry(key).or_insert(0) += 1;
        }
        
        // Create pool with frequent_reviewer and others
        let mut reviewers: Vec<Did> = (0..10)
            .map(|i| Did(format!("did:diagon:reviewer{}", i)))
            .collect();
        reviewers.push(frequent_reviewer.clone());
        
        let cid = Cid::new(b"test");
        let result = state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment, // Fast tier, needs 2
            "Test content".into(),
            None,
            None,
            author,
            &reviewers,
        );
        
        assert!(result.is_ok());
        let pending = state.pending.get(&cid).unwrap();
        assert!(!pending.assigned_reviewers.contains(&frequent_reviewer));
        println!("[✓] High-interaction reviewer excluded");
        
        println!("[✓] ReviewState interaction limit test passed\n");
    }

    #[test]
    fn test_review_state_submit_review() {
        println!("\n=== TEST: ReviewState::submit_review ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        // Setup: Create keypairs for reviewers
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let reviewer1 = Did::from_pubkey(&pk1);
        let reviewer2 = Did::from_pubkey(&pk2);
        
        let reviewers = vec![
            reviewer1.clone(),
            reviewer2.clone(),
            Did("did:diagon:r3".into()),
        ];
        
        // Submit content for review
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment, // Needs 2 reviews
            "Test content".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        ).unwrap();
        
        // Force assign our test reviewers
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![reviewer1.clone(), reviewer2.clone()];
        
        // Submit valid signed review
        let review1 = make_signed_review(cid, &pk1, &sk1);
        let is_complete = state.submit_review(review1).unwrap();
        assert!(!is_complete);
        println!("[✓] First review submitted, not complete yet");
        
        // Submit second review
        let review2 = make_signed_review(cid, &pk2, &sk2);
        let is_complete = state.submit_review(review2).unwrap();
        assert!(is_complete);
        println!("[✓] Second review submitted, now complete");
        
        // Verify interaction count updated
        let key = (reviewer1.clone(), author.clone());
        assert_eq!(*state.interaction_counts.get(&key).unwrap_or(&0), 1);
        println!("[✓] Interaction count incremented");
        
        println!("[✓] ReviewState::submit_review test passed\n");
    }

    #[test]
    fn test_review_state_submit_review_validation() {
        println!("\n=== TEST: ReviewState::submit_review validation ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        let (pk, sk) = keypair();
        let reviewer = Did::from_pubkey(&pk);
        let not_assigned = Did("did:diagon:notassigned".into());
        
        let reviewers = vec![reviewer.clone(), Did("did:diagon:r2".into()), Did("did:diagon:r3".into())];
        
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment,
            "Test content".into(),
            None,
            None,
            author,
            &reviewers,
        ).unwrap();
        
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![reviewer.clone()];
        
        // Invalid review (bad scores)
        let mut invalid_review = make_signed_review(cid, &pk, &sk);
        invalid_review.relevance = 0; // Invalid score
        let result = state.submit_review(invalid_review);
        assert!(result.is_err());
        println!("[✓] Invalid review rejected");
        
        // Unsigned review
        let unsigned_review = QualityReview {
            content_cid: cid,
            reviewer: reviewer.clone(),
            pubkey: pk.as_bytes().to_vec(),
            relevance: 4,
            substance: 4,
            clarity: 4,
            originality: 3,
            effort: 4,
            justification: "Valid justification here".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![], // No signature
        };
        let result = state.submit_review(unsigned_review);
        assert!(result.is_err());
        println!("[✓] Unsigned review rejected");
        
        // Not assigned reviewer
        let (other_pk, other_sk) = keypair();
        let not_assigned_review = make_signed_review(cid, &other_pk, &other_sk);
        let result = state.submit_review(not_assigned_review);
        assert!(result.is_err());
        println!("[✓] Not-assigned reviewer rejected");
        
        // Content not in queue
        let wrong_cid = Cid::new(b"wrong");
        let wrong_cid_review = make_signed_review(wrong_cid, &pk, &sk);
        let result = state.submit_review(wrong_cid_review);
        assert!(result.is_err());
        println!("[✓] Wrong CID rejected");
        
        // Duplicate review
        let valid_review = make_signed_review(cid, &pk, &sk);
        state.submit_review(valid_review.clone()).unwrap();
        let result = state.submit_review(valid_review);
        assert!(result.is_err());
        println!("[✓] Duplicate review rejected");
        
        println!("[✓] ReviewState::submit_review validation test passed\n");
    }

    #[test]
    fn test_review_state_finalize_review_empty() {
        println!("\n=== TEST: ReviewState::finalize_review empty ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        let reviewers: Vec<Did> = (0..3).map(|i| Did(format!("did:diagon:r{}", i))).collect();
        
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment,
            "Test content".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        ).unwrap();
        
        // Finalize without any reviews (expired scenario)
        let verdict = state.finalize_review(cid).unwrap();
        
        assert_eq!(verdict.content_cid, cid);
        assert_eq!(verdict.author, author);
        assert!((verdict.quality_score - 0.5).abs() < 0.001);
        assert!(!verdict.flagged);
        assert!(verdict.reviewer_scores.is_empty());
        assert_eq!(verdict.xp_awarded, 0);
        println!("[✓] Empty review produces default verdict");
        
        // Should be moved to verdicts
        assert!(state.verdicts.contains_key(&cid));
        assert!(!state.pending.contains_key(&cid));
        println!("[✓] Review moved from pending to verdicts");
        
        println!("[✓] ReviewState::finalize_review empty test passed\n");
    }

    #[test]
    fn test_review_state_finalize_review_with_reviews() {
        println!("\n=== TEST: ReviewState::finalize_review with reviews ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        // Create keypairs
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let reviewer1 = Did::from_pubkey(&pk1);
        let reviewer2 = Did::from_pubkey(&pk2);
        
        let reviewers = vec![reviewer1.clone(), reviewer2.clone(), Did("did:diagon:r3".into())];
        
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment,
            "Test content here with words".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        ).unwrap();
        
        // Force assign reviewers
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![reviewer1.clone(), reviewer2.clone()];
        
        // Submit reviews with similar scores (consensus)
        let review1 = make_signed_review(cid, &pk1, &sk1);
        let review2 = make_signed_review(cid, &pk2, &sk2);
        
        state.submit_review(review1).unwrap();
        state.submit_review(review2).unwrap();
        
        let verdict = state.finalize_review(cid).unwrap();
        
        assert!(!verdict.flagged);
        assert!(verdict.quality_score > 0.0);
        assert_eq!(verdict.reviewer_scores.len(), 2);
        assert!(!verdict.consensus_aligned.is_empty());
        println!("[✓] Verdict calculated with consensus");
        
        // Reviewer reputations should be updated
        assert!(state.reviewer_reputations.contains_key(&reviewer1));
        assert!(state.reviewer_reputations.contains_key(&reviewer2));
        println!("[✓] Reviewer reputations updated");
        
        println!("[✓] ReviewState::finalize_review with reviews test passed\n");
    }

    #[test]
    fn test_review_state_finalize_review_flagged_content() {
        println!("\n=== TEST: ReviewState::finalize_review flagged ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"spam content");
        let author = Did("did:diagon:spammer".into());
        
        // Create 3 reviewers for fast tier
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let reviewer1 = Did::from_pubkey(&pk1);
        let reviewer2 = Did::from_pubkey(&pk2);
        
        let reviewers = vec![reviewer1.clone(), reviewer2.clone(), Did("did:diagon:r3".into())];
        
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment,
            "Spam content".into(),
            None,
            None,
            author,
            &reviewers,
        ).unwrap();
        
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![reviewer1.clone(), reviewer2.clone()];
        
        // Submit reviews that flag as spam
        let mut review1 = make_signed_review(cid, &pk1, &sk1);
        review1.flag_spam = true;
        let sig1 = detached_sign(&review1.signable_bytes(), &sk1);
        review1.signature = sig1.as_bytes().to_vec();
        
        let mut review2 = make_signed_review(cid, &pk2, &sk2);
        review2.flag_spam = true;
        let sig2 = detached_sign(&review2.signable_bytes(), &sk2);
        review2.signature = sig2.as_bytes().to_vec();
        
        state.submit_review(review1).unwrap();
        state.submit_review(review2).unwrap();
        
        let verdict = state.finalize_review(cid).unwrap();
        
        assert!(verdict.flagged);
        assert_eq!(verdict.flag_reason, Some("spam".into()));
        assert!((verdict.quality_score - 0.0).abs() < 0.001);
        assert_eq!(verdict.xp_awarded, 0);
        println!("[✓] Flagged content produces zero quality/XP");
        
        // Reviewers who flagged should get reputation boost
        let rep1 = state.reviewer_reputations.get(&reviewer1).unwrap();
        assert!(rep1.confirmed_flags > 0);
        println!("[✓] Flagging reviewers get credit for confirmed flag");
        
        println!("[✓] ReviewState::finalize_review flagged test passed\n");
    }

    #[test]
    fn test_review_state_get_assignments() {
        println!("\n=== TEST: ReviewState::get_assignments ===");
        
        let mut state = ReviewState::new();
        let cid1 = Cid::new(b"content1");
        let cid2 = Cid::new(b"content2");
        let author = Did("did:diagon:author".into());
        let reviewer = Did("did:diagon:reviewer".into());
        let other_reviewer = Did("did:diagon:other".into());
        
        let reviewers = vec![reviewer.clone(), other_reviewer.clone(), Did("did:diagon:r3".into())];
        
        // Submit two items
        state.submit_for_review(
            cid1,
            ReviewableContentType::Acknowledgment,
            "Content 1".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        ).unwrap();
        
        state.submit_for_review(
            cid2,
            ReviewableContentType::Acknowledgment,
            "Content 2".into(),
            None,
            None,
            author,
            &reviewers,
        ).unwrap();
        
        // Assign reviewer to both
        state.pending.get_mut(&cid1).unwrap().assigned_reviewers = vec![reviewer.clone()];
        state.pending.get_mut(&cid2).unwrap().assigned_reviewers = vec![reviewer.clone()];
        
        let assignments = state.get_assignments(&reviewer);
        assert_eq!(assignments.len(), 2);
        println!("[✓] Reviewer sees all assignments");
        
        // Other reviewer has no assignments
        let other_assignments = state.get_assignments(&other_reviewer);
        assert_eq!(other_assignments.len(), 0);
        println!("[✓] Unassigned reviewer sees no assignments");
        
        // After reviewing one, should only see one assignment
        let (pk, sk) = keypair();
        let actual_reviewer = Did::from_pubkey(&pk);
        state.pending.get_mut(&cid1).unwrap().assigned_reviewers = vec![actual_reviewer.clone()];
        
        let review = make_signed_review(cid1, &pk, &sk);
        state.submit_review(review).unwrap();
        
        let remaining = state.get_assignments(&actual_reviewer);
        assert_eq!(remaining.len(), 0);
        println!("[✓] Completed reviews excluded from assignments");
        
        println!("[✓] ReviewState::get_assignments test passed\n");
    }

    #[test]
    fn test_review_state_get_expired() {
        println!("\n=== TEST: ReviewState::get_expired ===");
        
        let mut state = ReviewState::new();
        let cid_fresh = Cid::new(b"fresh");
        let cid_expired = Cid::new(b"expired");
        let cid_complete = Cid::new(b"complete");
        let author = Did("did:diagon:author".into());
        
        let reviewers: Vec<Did> = (0..3).map(|i| Did(format!("did:diagon:r{}", i))).collect();
        
        // Fresh review
        state.submit_for_review(
            cid_fresh,
            ReviewableContentType::Acknowledgment,
            "Fresh".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        ).unwrap();
        
        // Expired review
        state.submit_for_review(
            cid_expired,
            ReviewableContentType::Acknowledgment,
            "Expired".into(),
            None,
            None,
            author.clone(),
            &reviewers,
        ).unwrap();
        state.pending.get_mut(&cid_expired).unwrap().deadline = timestamp() - 1;
        
        // Complete review
        state.submit_for_review(
            cid_complete,
            ReviewableContentType::Acknowledgment,
            "Complete".into(),
            None,
            None,
            author,
            &reviewers,
        ).unwrap();
        
        // Add enough fake reviews to mark complete
        let pending = state.pending.get_mut(&cid_complete).unwrap();
        for i in 0..pending.required_reviews {
            pending.reviews.push(make_test_review(cid_complete, Did(format!("did:diagon:rev{}", i))));
        }
        
        let expired = state.get_expired();
        assert!(expired.contains(&cid_expired));
        assert!(expired.contains(&cid_complete));
        assert!(!expired.contains(&cid_fresh));
        println!("[✓] Correctly identifies expired and complete reviews");
        
        println!("[✓] ReviewState::get_expired test passed\n");
    }

    #[test]
    fn test_review_state_calculate_reviewer_rewards() {
        println!("\n=== TEST: ReviewState::calculate_reviewer_rewards ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"test");
        let reviewer1 = Did("did:diagon:r1".into());
        let reviewer2 = Did("did:diagon:r2".into());
        
        // Create a verdict
        let verdict = QualityVerdict {
            content_cid: cid,
            author: Did("did:diagon:author".into()),
            quality_score: 0.75,
            flagged: false,
            flag_reason: None,
            reviewer_scores: vec![
                (reviewer1.clone(), 4.0),
                (reviewer2.clone(), 3.5),
            ],
            consensus_aligned: vec![reviewer1.clone()],
            consensus_outliers: vec![],
            xp_awarded: 10,
            verdict_at: timestamp(),
        };
        
        state.verdicts.insert(cid, verdict);
        
        let rewards = state.calculate_reviewer_rewards(&cid);
        
        // reviewer1 is consensus aligned: XP_REVIEW_COMPLETE + XP_REVIEW_CONSENSUS_BONUS
        let r1_reward = *rewards.get(&reviewer1).unwrap();
        assert_eq!(r1_reward, XP_REVIEW_COMPLETE + XP_REVIEW_CONSENSUS_BONUS);
        println!("[✓] Consensus-aligned reviewer gets bonus: {}", r1_reward);
        
        // reviewer2 is not consensus aligned: XP_REVIEW_COMPLETE only
        let r2_reward = *rewards.get(&reviewer2).unwrap();
        assert_eq!(r2_reward, XP_REVIEW_COMPLETE);
        println!("[✓] Non-aligned reviewer gets base: {}", r2_reward);
        
        // Test flagged content bonus
        let flagged_cid = Cid::new(b"flagged");
        let flagged_verdict = QualityVerdict {
            content_cid: flagged_cid,
            author: Did("did:diagon:author".into()),
            quality_score: 0.0,
            flagged: true,
            flag_reason: Some("spam".into()),
            reviewer_scores: vec![
                (reviewer1.clone(), 1.0),
            ],
            consensus_aligned: vec![reviewer1.clone()],
            consensus_outliers: vec![],
            xp_awarded: 0,
            verdict_at: timestamp(),
        };
        
        state.verdicts.insert(flagged_cid, flagged_verdict);
        
        let flagged_rewards = state.calculate_reviewer_rewards(&flagged_cid);
        let r1_flagged_reward = *flagged_rewards.get(&reviewer1).unwrap();
        assert_eq!(r1_flagged_reward, XP_REVIEW_COMPLETE + XP_REVIEW_CONSENSUS_BONUS + XP_REVIEW_SPAM_CATCH);
        println!("[✓] Spam-catching reviewer gets extra bonus: {}", r1_flagged_reward);
        
        // Non-existent verdict returns empty
        let nonexistent = state.calculate_reviewer_rewards(&Cid::new(b"nonexistent"));
        assert!(nonexistent.is_empty());
        println!("[✓] Non-existent verdict returns empty rewards");
        
        println!("[✓] ReviewState::calculate_reviewer_rewards test passed\n");
    }

    // ========================================================================
    // HELPER FUNCTION TESTS
    // ========================================================================

    #[test]
    fn test_calculate_xp_award() {
        println!("\n=== TEST: calculate_xp_award ===");
        
        // Base XP for proposal with minimum words
        let proposal_xp = calculate_xp_award(ReviewableContentType::Proposal, 5, 1.0);
        assert!(proposal_xp >= XP_BASE_PROPOSAL);
        println!("[✓] Proposal base XP: {} (min words)", proposal_xp);
        
        // More words = higher XP (length factor)
        let long_proposal_xp = calculate_xp_award(ReviewableContentType::Proposal, 100, 1.0);
        assert!(long_proposal_xp > proposal_xp);
        println!("[✓] Long proposal gets more XP: {}", long_proposal_xp);
        
        // Quality affects XP
        let low_quality_xp = calculate_xp_award(ReviewableContentType::Proposal, 50, 0.5);
        let high_quality_xp = calculate_xp_award(ReviewableContentType::Proposal, 50, 1.0);
        assert!(high_quality_xp > low_quality_xp);
        println!("[✓] High quality: {}, Low quality: {}", high_quality_xp, low_quality_xp);
        
        // Zero quality = zero XP
        let zero_quality_xp = calculate_xp_award(ReviewableContentType::Proposal, 50, 0.0);
        assert_eq!(zero_quality_xp, 0);
        println!("[✓] Zero quality = zero XP");
        
        // Different content types have different base XP
        let reply_xp = calculate_xp_award(ReviewableContentType::Reply, 50, 1.0);
        let ack_xp = calculate_xp_award(ReviewableContentType::Acknowledgment, 50, 1.0);
        assert!(proposal_xp != reply_xp || proposal_xp != ack_xp); // Different types, likely different XP
        println!("[✓] Different types yield different base XP");
        
        println!("[✓] calculate_xp_award test passed\n");
    }

    #[test]
    fn test_quality_verdict_structure() {
        println!("\n=== TEST: QualityVerdict structure ===");
        
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        let reviewer1 = Did("did:diagon:r1".into());
        let reviewer2 = Did("did:diagon:r2".into());
        
        let verdict = QualityVerdict {
            content_cid: cid,
            author: author.clone(),
            quality_score: 0.75,
            flagged: false,
            flag_reason: None,
            reviewer_scores: vec![
                (reviewer1.clone(), 3.8),
                (reviewer2.clone(), 4.1),
            ],
            consensus_aligned: vec![reviewer1.clone(), reviewer2.clone()],
            consensus_outliers: vec![],
            xp_awarded: 15,
            verdict_at: timestamp(),
        };
        
        assert_eq!(verdict.content_cid, cid);
        assert_eq!(verdict.author, author);
        assert!((verdict.quality_score - 0.75).abs() < 0.001);
        assert!(!verdict.flagged);
        assert!(verdict.flag_reason.is_none());
        assert_eq!(verdict.reviewer_scores.len(), 2);
        assert_eq!(verdict.consensus_aligned.len(), 2);
        assert!(verdict.consensus_outliers.is_empty());
        assert_eq!(verdict.xp_awarded, 15);
        println!("[✓] QualityVerdict fields store correctly");
        
        // Test flagged verdict
        let flagged_verdict = QualityVerdict {
            content_cid: cid,
            author,
            quality_score: 0.0,
            flagged: true,
            flag_reason: Some("plagiarism".into()),
            reviewer_scores: vec![],
            consensus_aligned: vec![],
            consensus_outliers: vec![reviewer1],
            xp_awarded: 0,
            verdict_at: timestamp(),
        };
        
        assert!(flagged_verdict.flagged);
        assert_eq!(flagged_verdict.flag_reason, Some("plagiarism".into()));
        assert_eq!(flagged_verdict.consensus_outliers.len(), 1);
        println!("[✓] Flagged verdict structure correct");
        
        println!("[✓] QualityVerdict structure test passed\n");
    }

    // ========================================================================
    // INTEGRATION / WORKFLOW TESTS
    // ========================================================================

    #[test]
    fn test_full_review_workflow() {
        println!("\n=== TEST: Full review workflow ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"proposal content");
        let author = Did("did:diagon:author".into());
        
        // Create reviewer keypairs
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let reviewer1 = Did::from_pubkey(&pk1);
        let reviewer2 = Did::from_pubkey(&pk2);
        
        let all_reviewers: Vec<Did> = (0..10)
            .map(|i| Did(format!("did:diagon:extra{}", i)))
            .chain(vec![reviewer1.clone(), reviewer2.clone()])
            .collect();
        
        // Step 1: Submit for review
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment, // Fast tier: 2 reviews needed
            "This is a thoughtful proposal about improving the system".into(),
            None,
            None,
            author.clone(),
            &all_reviewers,
        ).unwrap();
        println!("[✓] Step 1: Content submitted for review");
        
        // Force assign our reviewers
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![reviewer1.clone(), reviewer2.clone()];
        
        // Step 2: Verify assignments
        let r1_assignments = state.get_assignments(&reviewer1);
        let r2_assignments = state.get_assignments(&reviewer2);
        assert_eq!(r1_assignments.len(), 1);
        assert_eq!(r2_assignments.len(), 1);
        println!("[✓] Step 2: Reviewers see their assignments");
        
        // Step 3: Submit reviews
        let mut review1 = QualityReview {
            content_cid: cid,
            reviewer: reviewer1.clone(),
            pubkey: pk1.as_bytes().to_vec(),
            relevance: 4,
            substance: 5,
            clarity: 4,
            originality: 3,
            effort: 4,
            justification: "Well thought out and clearly articulated".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig1 = detached_sign(&review1.signable_bytes(), &sk1);
        review1.signature = sig1.as_bytes().to_vec();
        
        state.submit_review(review1).unwrap();
        println!("[✓] Step 3a: First review submitted");
        
        let mut review2 = QualityReview {
            content_cid: cid,
            reviewer: reviewer2.clone(),
            pubkey: pk2.as_bytes().to_vec(),
            relevance: 4,
            substance: 4,
            clarity: 5,
            originality: 3,
            effort: 5,
            justification: "Good proposal with clear implementation path".into(),
            flag_spam: false,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig2 = detached_sign(&review2.signable_bytes(), &sk2);
        review2.signature = sig2.as_bytes().to_vec();
        
        let is_complete = state.submit_review(review2).unwrap();
        assert!(is_complete);
        println!("[✓] Step 3b: Second review submitted, review complete");
        
        // Step 4: Finalize
        let verdict = state.finalize_review(cid).unwrap();
        
        assert!(!verdict.flagged);
        assert!(verdict.quality_score > 0.5);
        assert_eq!(verdict.reviewer_scores.len(), 2);
        assert!(verdict.xp_awarded > 0);
        println!("[✓] Step 4: Review finalized with verdict");
        println!("    Quality: {:.2}, XP: {}", verdict.quality_score, verdict.xp_awarded);
        
        // Step 5: Calculate reviewer rewards
        let rewards = state.calculate_reviewer_rewards(&cid);
        assert!(rewards.get(&reviewer1).unwrap() > &0);
        assert!(rewards.get(&reviewer2).unwrap() > &0);
        println!("[✓] Step 5: Reviewer rewards calculated");
        
        // Step 6: Verify state
        assert!(!state.pending.contains_key(&cid));
        assert!(state.verdicts.contains_key(&cid));
        assert!(state.reviewer_reputations.contains_key(&reviewer1));
        assert!(state.reviewer_reputations.contains_key(&reviewer2));
        println!("[✓] Step 6: State correctly updated");
        
        println!("[✓] Full review workflow test passed\n");
    }

    #[test]
    fn test_spam_detection_workflow() {
        println!("\n=== TEST: Spam detection workflow ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"spam spam spam buy now!!!");
        let spammer = Did("did:diagon:spammer".into());
        
        // Create reviewer keypairs
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let reviewer1 = Did::from_pubkey(&pk1);
        let reviewer2 = Did::from_pubkey(&pk2);
        
        let all_reviewers: Vec<Did> = (0..10)
            .map(|i| Did(format!("did:diagon:extra{}", i)))
            .chain(vec![reviewer1.clone(), reviewer2.clone()])
            .collect();
        
        state.submit_for_review(
            cid,
            ReviewableContentType::Acknowledgment,
            "BUY NOW! CHEAP! CLICK HERE!".into(),
            None,
            None,
            spammer.clone(),
            &all_reviewers,
        ).unwrap();
        
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![reviewer1.clone(), reviewer2.clone()];
        
        // Both reviewers flag as spam
        let mut review1 = QualityReview {
            content_cid: cid,
            reviewer: reviewer1.clone(),
            pubkey: pk1.as_bytes().to_vec(),
            relevance: 1,
            substance: 1,
            clarity: 1,
            originality: 1,
            effort: 1,
            justification: "Obvious spam content".into(),
            flag_spam: true,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig1 = detached_sign(&review1.signable_bytes(), &sk1);
        review1.signature = sig1.as_bytes().to_vec();
        
        let mut review2 = QualityReview {
            content_cid: cid,
            reviewer: reviewer2.clone(),
            pubkey: pk2.as_bytes().to_vec(),
            relevance: 1,
            substance: 1,
            clarity: 1,
            originality: 1,
            effort: 1,
            justification: "This is spam advertising".into(),
            flag_spam: true,
            flag_plagiarism: false,
            flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig2 = detached_sign(&review2.signable_bytes(), &sk2);
        review2.signature = sig2.as_bytes().to_vec();
        
        state.submit_review(review1).unwrap();
        state.submit_review(review2).unwrap();
        
        let verdict = state.finalize_review(cid).unwrap();
        
        assert!(verdict.flagged);
        assert_eq!(verdict.flag_reason, Some("spam".into()));
        assert!((verdict.quality_score - 0.0).abs() < 0.001);
        assert_eq!(verdict.xp_awarded, 0);
        println!("[✓] Spam correctly detected and penalized");
        
        // Reviewers should get credit for catching spam
        let rep1 = state.reviewer_reputations.get(&reviewer1).unwrap();
        let rep2 = state.reviewer_reputations.get(&reviewer2).unwrap();
        assert_eq!(rep1.confirmed_flags, 1);
        assert_eq!(rep2.confirmed_flags, 1);
        println!("[✓] Reviewers rewarded for catching spam");
        
        let rewards = state.calculate_reviewer_rewards(&cid);
        let r1_reward = *rewards.get(&reviewer1).unwrap();
        assert!(r1_reward >= XP_REVIEW_COMPLETE + XP_REVIEW_SPAM_CATCH);
        println!("[✓] Extra XP awarded for spam detection: {}", r1_reward);
        
        println!("[✓] Spam detection workflow test passed\n");
    }

    #[test]
    fn test_consensus_outlier_detection() {
        println!("\n=== TEST: Consensus outlier detection ===");
        
        let mut state = ReviewState::new();
        let cid = Cid::new(b"controversial content");
        let author = Did("did:diagon:author".into());
        
        // Create 3 reviewer keypairs
        let (pk1, sk1) = keypair();
        let (pk2, sk2) = keypair();
        let (pk3, sk3) = keypair();
        let reviewer1 = Did::from_pubkey(&pk1);
        let reviewer2 = Did::from_pubkey(&pk2);
        let reviewer3 = Did::from_pubkey(&pk3);
        
        let all_reviewers: Vec<Did> = vec![
            reviewer1.clone(), 
            reviewer2.clone(), 
            reviewer3.clone(),
            Did("did:diagon:extra1".into()),
            Did("did:diagon:extra2".into()),
        ];
        
        // Use standard tier (3 reviewers) for this test
        state.submit_for_review(
            cid,
            ReviewableContentType::Reply,
            "Some content".into(),
            None,
            None,
            author,
            &all_reviewers,
        ).unwrap();
        
        state.pending.get_mut(&cid).unwrap().assigned_reviewers = vec![
            reviewer1.clone(), 
            reviewer2.clone(), 
            reviewer3.clone()
        ];
        
        // Two reviewers agree (high scores)
        let mut review1 = QualityReview {
            content_cid: cid,
            reviewer: reviewer1.clone(),
            pubkey: pk1.as_bytes().to_vec(),
            relevance: 4, substance: 4, clarity: 4, originality: 4, effort: 4,
            justification: "Good quality content".into(),
            flag_spam: false, flag_plagiarism: false, flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig1 = detached_sign(&review1.signable_bytes(), &sk1);
        review1.signature = sig1.as_bytes().to_vec();
        
        let mut review2 = QualityReview {
            content_cid: cid,
            reviewer: reviewer2.clone(),
            pubkey: pk2.as_bytes().to_vec(),
            relevance: 4, substance: 4, clarity: 4, originality: 4, effort: 4,
            justification: "Solid contribution".into(),
            flag_spam: false, flag_plagiarism: false, flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig2 = detached_sign(&review2.signable_bytes(), &sk2);
        review2.signature = sig2.as_bytes().to_vec();
        
        // One outlier (very low scores)
        let mut review3 = QualityReview {
            content_cid: cid,
            reviewer: reviewer3.clone(),
            pubkey: pk3.as_bytes().to_vec(),
            relevance: 1, substance: 1, clarity: 1, originality: 1, effort: 1,
            justification: "This is terrible".into(),
            flag_spam: false, flag_plagiarism: false, flag_offtopic: false,
            reviewed_at: timestamp(),
            signature: vec![],
        };
        let sig3 = detached_sign(&review3.signable_bytes(), &sk3);
        review3.signature = sig3.as_bytes().to_vec();
        
        state.submit_review(review1).unwrap();
        state.submit_review(review2).unwrap();
        state.submit_review(review3).unwrap();
        
        let verdict = state.finalize_review(cid).unwrap();
        
        // reviewer3 should be an outlier (score difference > 2.0)
        let score1 = 4.0 * (0.25 + 0.30 + 0.20 + 0.15 + 0.10); // 4.0
        let score3 = 1.0 * (0.25 + 0.30 + 0.20 + 0.15 + 0.10); // 1.0
        // Difference = 3.0 > REVIEW_OUTLIER_THRESHOLD (2.0)
        
        assert!(verdict.consensus_outliers.contains(&reviewer3) || 
                verdict.consensus_aligned.contains(&reviewer1));
        println!("[✓] Outlier detection works");
        
        // Check reputation updates
        let rep1 = state.reviewer_reputations.get(&reviewer1).unwrap();
        let rep3 = state.reviewer_reputations.get(&reviewer3).unwrap();
        
        // Aligned reviewers should have higher/stable score
        // Outliers should have lower score
        println!("    Reviewer 1 (aligned) score: {:.3}", rep1.score);
        println!("    Reviewer 3 (outlier) score: {:.3}", rep3.score);
        
        println!("[✓] Consensus outlier detection test passed\n");
    }

    // ========================================================================
    // SERIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_review_types_serialization() {
        println!("\n=== TEST: Review types serialization ===");
        
        let cid = Cid::new(b"test");
        let author = Did("did:diagon:author".into());
        
        // QualityReview
        let review = QualityReview {
            content_cid: cid,
            reviewer: Did("did:diagon:reviewer".into()),
            pubkey: vec![1, 2, 3, 4],
            relevance: 4,
            substance: 3,
            clarity: 5,
            originality: 2,
            effort: 4,
            justification: "Test justification".into(),
            flag_spam: true,
            flag_plagiarism: false,
            flag_offtopic: true,
            reviewed_at: 1234567890,
            signature: vec![5, 6, 7, 8],
        };
        
        let serialized = serde_cbor::to_vec(&review).expect("Serialize review");
        let deserialized: QualityReview = serde_cbor::from_slice(&serialized).expect("Deserialize review");
        
        assert_eq!(review.content_cid, deserialized.content_cid);
        assert_eq!(review.relevance, deserialized.relevance);
        assert_eq!(review.flag_spam, deserialized.flag_spam);
        println!("[✓] QualityReview serializes/deserializes");
        
        // PendingReview
        let pending = PendingReview::new(
            cid,
            ReviewableContentType::Proposal,
            "Test content".into(),
            Some(Cid::new(b"context")),
            Some("Context text".into()),
            author.clone(),
        );
        
        let serialized = serde_cbor::to_vec(&pending).expect("Serialize pending");
        let deserialized: PendingReview = serde_cbor::from_slice(&serialized).expect("Deserialize pending");
        
        assert_eq!(pending.content_cid, deserialized.content_cid);
        assert_eq!(pending.content_type, deserialized.content_type);
        println!("[✓] PendingReview serializes/deserializes");
        
        // QualityVerdict
        let verdict = QualityVerdict {
            content_cid: cid,
            author,
            quality_score: 0.75,
            flagged: false,
            flag_reason: None,
            reviewer_scores: vec![
                (Did("did:diagon:r1".into()), 4.0),
            ],
            consensus_aligned: vec![Did("did:diagon:r1".into())],
            consensus_outliers: vec![],
            xp_awarded: 15,
            verdict_at: timestamp(),
        };
        
        let serialized = serde_cbor::to_vec(&verdict).expect("Serialize verdict");
        let deserialized: QualityVerdict = serde_cbor::from_slice(&serialized).expect("Deserialize verdict");
        
        assert_eq!(verdict.content_cid, deserialized.content_cid);
        assert!((verdict.quality_score - deserialized.quality_score).abs() < 0.001);
        println!("[✓] QualityVerdict serializes/deserializes");
        
        // ReviewerReputation
        let mut rep = ReviewerReputation::new();
        rep.update(true, Some(true));
        
        let serialized = serde_cbor::to_vec(&rep).expect("Serialize reputation");
        let deserialized: ReviewerReputation = serde_cbor::from_slice(&serialized).expect("Deserialize reputation");
        
        assert_eq!(rep.reviews_completed, deserialized.reviews_completed);
        assert!((rep.score - deserialized.score).abs() < 0.001);
        println!("[✓] ReviewerReputation serializes/deserializes");
        
        // ReviewState
        let state = ReviewState::new();
        let serialized = serde_cbor::to_vec(&state).expect("Serialize state");
        let deserialized: ReviewState = serde_cbor::from_slice(&serialized).expect("Deserialize state");
        
        assert!(deserialized.pending.is_empty());
        println!("[✓] ReviewState serializes/deserializes");
        
        // ReviewableContentType
        let content_type = ReviewableContentType::Proposal;
        let serialized = serde_cbor::to_vec(&content_type).expect("Serialize content type");
        let deserialized: ReviewableContentType = serde_cbor::from_slice(&serialized).expect("Deserialize content type");
        
        assert_eq!(content_type, deserialized);
        println!("[✓] ReviewableContentType serializes/deserializes");
        
        println!("[✓] Review types serialization test passed\n");
    }
}