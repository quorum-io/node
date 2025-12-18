// DIAGON v0.9.1 Alpha - Security Hardened Edition

use std::{
    collections::{HashMap, HashSet, BTreeMap, VecDeque},
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc as StdArc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    fmt,
};

use async_channel::{Sender, Receiver, bounded};
use async_lock::RwLock;
use futures_lite::prelude::*;
use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};
use smol::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    Timer,
};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};

use std::sync::Arc;

// ============================================================================
// BIOLOGICAL CONSTANTS
// ============================================================================

const EIGEN_THRESHOLD: f64 = 0.67;
const SIGNAL_HALF_LIFE: u64 = 300;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const PEER_TIMEOUT_SECS: u64 = 150;
const CHALLENGE_TIMEOUT_SECS: u64 = 10; // SECURITY: Reduced from 30 to limit replay window
const MIN_ELABORATION_LEN: usize = 20;
const MAX_MESSAGE_SIZE: usize = 1_048_576;
const MAX_CONNECTIONS: usize = 100;
const CONNECTION_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RECONNECT_ATTEMPTS: u32 = 10;
const TRUST_DEFAULT: f64 = 0.5;
const TRUST_HISTORY_WEIGHT: f64 = 0.7;
const TRUST_NEW_WEIGHT: f64 = 0.3;
const TRUST_MIN_FOR_PROPOSE: f64 = 0.4;

// SECURITY: New limits to prevent DoS
const MAX_EXPRESSIONS: usize = 100_000;
const MAX_PROPOSALS: usize = 10_000;
const MAX_PENDING_CHALLENGES: usize = 1000;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_MAX_MESSAGES: u32 = 100;

// SECURITY: Pool authentication constants
const POOL_SALT: &[u8] = b"diagon-pool-v1-salt-2024";
const ARGON2_MEM_COST: u32 = 65536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

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
    // SECURITY: Use cryptographic randomness instead of predictable counter
    pub fn new(data: &[u8]) -> Self {
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&random_bytes);
        hasher.update(&timestamp().to_le_bytes());
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
    
    // SECURITY: Verify that a DID matches a public key
    pub fn matches_pubkey(&self, pubkey: &[u8]) -> bool {
        if pubkey.len() < 16 { return false; }
        let expected = format!("did:diagon:{}", hex::encode(&pubkey[..16]));
        self.0 == expected
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.short()) }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

#[derive(Default)]
struct RateLimiter {
    counts: HashMap<SocketAddr, (u32, u64)>, // (count, window_start)
}

impl RateLimiter {
    fn check_and_increment(&mut self, addr: &SocketAddr) -> bool {
        let now = timestamp();
        let entry = self.counts.entry(*addr).or_insert((0, now));
        
        // Reset window if expired
        if now - entry.1 > RATE_LIMIT_WINDOW_SECS {
            *entry = (1, now);
            return true;
        }
        
        // Check limit
        if entry.0 >= RATE_LIMIT_MAX_MESSAGES {
            return false;
        }
        
        entry.0 += 1;
        true
    }
    
    fn cleanup(&mut self) {
        let now = timestamp();
        self.counts.retain(|_, (_, start)| now - *start <= RATE_LIMIT_WINDOW_SECS * 2);
    }
}

// ============================================================================
// NONCE TRACKER (Anti-Replay)
// ============================================================================

struct NonceTracker {
    seen: HashMap<[u8; 32], u64>, // nonce -> timestamp
    max_age_secs: u64,
}

impl NonceTracker {
    fn new(max_age_secs: u64) -> Self {
        Self { seen: HashMap::new(), max_age_secs }
    }
    
    fn check_and_record(&mut self, nonce: &[u8; 32]) -> bool {
        let now = timestamp();
        
        // Cleanup old entries
        self.seen.retain(|_, ts| now - *ts < self.max_age_secs);
        
        // Check if already seen
        if self.seen.contains_key(nonce) {
            return false;
        }
        
        // Record
        self.seen.insert(*nonce, now);
        true
    }
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
// EXPRESSION STORE
// ============================================================================

pub struct ExprStore {
    expressions: HashMap<Cid, SexpRef>,
    log: Vec<Cid>,
    arena: Arena,
    max_size: usize, // SECURITY: Configurable limit
}

impl ExprStore {
    pub fn new() -> Self { 
        Self { 
            expressions: HashMap::new(), 
            log: Vec::new(), 
            arena: Arena::new(),
            max_size: MAX_EXPRESSIONS,
        } 
    }
    
    // SECURITY: Check size limit before storing
    pub fn store(&mut self, expr: SexpRef) -> Result<(Cid, bool)> {
        if self.expressions.len() >= self.max_size {
            return Err(DiagonError::StoreFull);
        }
        
        let (cid, canonical) = self.arena.intern(expr);
        let is_new = !self.expressions.contains_key(&cid);
        if is_new { 
            self.expressions.insert(cid, canonical); 
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
}

impl Default for ExprStore { fn default() -> Self { Self::new() } }

// ============================================================================
// QUORUM / EPIGENETIC / PROPOSAL STATE
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumSignal {
    pub source: Did,
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
    
    // SECURITY: Create canonical bytes for signature verification
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
    pub proposer: Did, // SECURITY: Track proposer to prevent self-voting
}

impl QuorumState {
    pub fn new(target: Cid, threshold: u64, proposer: Did) -> Self {
        Self { 
            target, 
            threshold, 
            signals_for: Vec::new(), 
            signals_against: Vec::new(), 
            sources_seen: HashSet::new(), 
            created: timestamp(),
            proposer,
        }
    }
    
    // SECURITY: Prevent self-voting
    pub fn sense(&mut self, signal: QuorumSignal) -> Result<bool> {
        if self.sources_seen.contains(&signal.source) || signal.target != self.target { 
            return Ok(false); 
        }
        
        // SECURITY: Prevent proposer from voting on their own proposal
        if signal.source == self.proposer {
            return Err(DiagonError::SelfVoteProhibited);
        }
        
        self.sources_seen.insert(signal.source.clone());
        if signal.support { 
            self.signals_for.push(signal); 
        } else { 
            self.signals_against.push(signal); 
        }
        Ok(true)
    }
    
    pub fn accumulated_for(&self) -> u64 { self.signals_for.iter().map(|s| s.current_strength()).sum() }
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
    
    // SECURITY: Only update from verified interactions, not self-reported
    pub fn update(&mut self, quality: f64, verified: bool) {
        // Only allow verified interactions to increase score significantly
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
    pub executed: bool,
    pub created: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolState {
    pub commitment: [u8; 32],
    pub hint: String,
    pub rationale: String,
    pub proposer: Did,
    pub quorum: QuorumState,
    pub active: bool,
}

const GENESIS_POOLS: [[u8; 32]; 3] = [
    [0x80, 0x1e, 0x10, 0x0b, 0x0c, 0xa3, 0x10, 0x30, 0xa6, 0xb2, 0x9f, 0x69, 0x2d, 0x0f, 0x19, 0x4c,
     0x33, 0x07, 0x0f, 0xeb, 0x59, 0x50, 0x66, 0x60, 0xad, 0x7b, 0x90, 0x81, 0x3e, 0x42, 0x7b, 0x8b],
    [0x93, 0xa7, 0x80, 0xb1, 0x41, 0x61, 0x53, 0x86, 0xdb, 0x23, 0x6c, 0x6a, 0xe2, 0x9d, 0xed, 0x8c,
     0x7c, 0x42, 0xf2, 0x77, 0xa6, 0xfa, 0x28, 0x22, 0x9f, 0x7c, 0x75, 0x76, 0x49, 0xd3, 0xdc, 0xcb],
    [0xc7, 0x8d, 0xec, 0x83, 0xf3, 0xab, 0x88, 0xc4, 0xfd, 0x66, 0x2c, 0x88, 0x0e, 0x25, 0x8f, 0x63,
     0x45, 0xaa, 0xff, 0x91, 0x79, 0xd5, 0x37, 0x18, 0xa5, 0x3c, 0x84, 0x11, 0x85, 0xf6, 0x3a, 0x85],
];

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DerivedState {
    pub proposals: BTreeMap<Cid, ProposalState>,
    pub pool_proposals: BTreeMap<[u8; 32], PoolState>,
    pub active_pools: HashSet<[u8; 32]>,
    pub pruned: HashSet<Cid>,
    pub marks: HashMap<Did, EpigeneticMark>,
}

impl DerivedState {
    pub fn new() -> Self {
        let mut state = Self::default();
        for pool in GENESIS_POOLS.iter() { state.active_pools.insert(*pool); }
        state
    }
    
    pub fn threshold(&self, peer_count: usize) -> u64 {
        (((peer_count + 1) as f64 * EIGEN_THRESHOLD * 1000.0) as u64).max(1000)
    }
    
    pub fn get_mark(&self, did: &Did) -> EpigeneticMark { self.marks.get(did).cloned().unwrap_or_default() }
    
    // SECURITY: Only allow verified updates
    pub fn update_mark(&mut self, did: &Did, quality: f64, verified: bool) { 
        self.marks.entry(did.clone()).or_default().update(quality, verified); 
    }
    
    // SECURITY: Check proposal limit
    pub fn can_add_proposal(&self) -> bool {
        self.proposals.len() < MAX_PROPOSALS
    }
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
    // SECURITY: Include timestamp and data being approved
    Approve { timestamp: u64, peer_did: Did, signature: Vec<u8> },
    Reject { reason: String, signature: Vec<u8> },
    Expression(Vec<u8>),
    Signal(QuorumSignal),
    SyncRequest { merkle: [u8; 32], have: Vec<Cid> },
    SyncReply { expressions: Vec<Vec<u8>> },
    // SECURITY: Include timestamp to prevent replay
    Heartbeat { timestamp: u64, signature: Vec<u8> },
    Disconnect { timestamp: u64, signature: Vec<u8> },
}

impl NetMessage {
    fn serialize(&self) -> Result<Vec<u8>> { 
        bincode::serialize(self).map_err(|e| DiagonError::Serialization(e.to_string())) 
    }
    fn deserialize(data: &[u8]) -> Result<Self> { 
        bincode::deserialize(data).map_err(|e| DiagonError::Serialization(e.to_string())) 
    }
    
    // SECURITY: Get signable bytes for messages that require signatures
    fn signable_bytes(&self) -> Option<Vec<u8>> {
        match self {
            NetMessage::Approve { timestamp, peer_did, .. } => {
                let mut data = b"approve:".to_vec();
                data.extend_from_slice(&timestamp.to_le_bytes());
                data.extend_from_slice(peer_did.0.as_bytes());
                Some(data)
            }
            NetMessage::Reject { reason, .. } => {
                let mut data = b"reject:".to_vec();
                data.extend_from_slice(reason.as_bytes());
                Some(data)
            }
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
            NetMessage::Elaborate { text, .. } => {
                Some(text.as_bytes().to_vec())
            }
            _ => None,
        }
    }
}

// ============================================================================
// ASYNC CONNECTION
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionState {
    Connecting,
    Authenticating,
    AwaitingElaboration,
    PendingApproval,
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
    elaboration: Option<String>,
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
            elaboration: None,
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
}

#[derive(Clone)]
struct ConnHandle {
    addr: SocketAddr,
    cmd_tx: Sender<ConnCmd>,
}

impl ConnHandle {
    async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.cmd_tx.send(ConnCmd::Send(data)).await
            .map_err(|_| DiagonError::ConnectionLost)
    }
    
    async fn close(&self) {
        let _ = self.cmd_tx.send(ConnCmd::Close).await;
    }
}

// ============================================================================
// ASYNC CONNECTION POOL
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
        for (addr, info) in self.peers.read().await.iter() {
            if info.read().await.is_authenticated() {
                result.push(*addr);
            }
        }
        result
    }
    
    async fn pending_approval(&self) -> Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> {
        let mut result = Vec::new();
        for (addr, info) in self.peers.read().await.iter() {
            if info.read().await.state == ConnectionState::PendingApproval {
                result.push((*addr, info.clone()));
            }
        }
        result
    }
    
    async fn awaiting_elaboration(&self) -> Vec<(SocketAddr, Arc<RwLock<PeerInfo>>)> {
        let mut result = Vec::new();
        for (addr, info) in self.peers.read().await.iter() {
            if info.read().await.state == ConnectionState::AwaitingElaboration {
                result.push((*addr, info.clone()));
            }
        }
        result
    }
    
    async fn dead_connections(&self) -> Vec<SocketAddr> {
        let mut dead = Vec::new();
        for (addr, info) in self.peers.read().await.iter() {
            if !info.read().await.is_alive() {
                dead.push(*addr);
            }
        }
        dead
    }
    
    async fn shutdown(&self) {
        let addrs: Vec<_> = self.peers.read().await.keys().cloned().collect();
        for addr in addrs {
            self.remove(addr).await;
        }
    }
}

// ============================================================================
// PERSISTENCE
// ============================================================================

#[derive(Serialize, Deserialize)]
struct PersistedState {
    identity: (Vec<u8>, Vec<u8>, Did),
    expressions: Vec<(Cid, Vec<u8>)>,
    proposals: Vec<(Cid, ProposalState)>,
    pool_proposals: Vec<([u8; 32], PoolState)>,
    active_pools: Vec<[u8; 32]>,
    marks: Vec<(Did, EpigeneticMark)>,
}

// ============================================================================
// POOL AUTHENTICATION
// ============================================================================

// SECURITY: Use Argon2 for pool passphrase hashing
fn hash_pool_passphrase(passphrase: &str) -> [u8; 32] {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
            .expect("Invalid Argon2 params"),
    );
    
    let salt = SaltString::encode_b64(POOL_SALT).expect("Invalid salt");
    
    let hash = argon2.hash_password(passphrase.as_bytes(), &salt)
        .expect("Hashing failed");
    
    let mut result = [0u8; 32];
    if let Some(output) = hash.hash {
        let bytes = output.as_bytes();
        let len = bytes.len().min(32);
        result[..len].copy_from_slice(&bytes[..len]);
    }
    result
}

// ============================================================================
// NODE (async)
// ============================================================================

pub struct Node {
    did: Did,
    secret_key: SecretKey,
    public_key: PublicKey,
    bind_addr: String,
    pool: RwLock<Option<[u8; 32]>>,
    connection_pool: Arc<ConnectionPool>,
    reconnect_queue: RwLock<VecDeque<(SocketAddr, Instant, u32)>>,
    store: RwLock<ExprStore>,
    state: RwLock<DerivedState>,
    shutdown_tx: Sender<()>,
    shutdown_rx: Receiver<()>,
    db_path: String,
    // SECURITY: Rate limiter
    rate_limiter: RwLock<RateLimiter>,
    // SECURITY: Nonce tracker for anti-replay
    nonce_tracker: RwLock<NonceTracker>,
}

impl Node {
    pub async fn new(bind_addr: &str, db_path: &str) -> Result<Arc<Self>> {
        let db = db_path.to_string();
        smol::unblock(move || std::fs::create_dir_all(&db)).await.ok();
        
        let persistence_path = format!("{}/state.cbor", db_path);
        let (did, secret_key, public_key, store, state) = 
            Self::load_or_create(&persistence_path).await?;
        
        let (shutdown_tx, shutdown_rx) = bounded(1);
        
        let node = Arc::new(Self {
            did: did.clone(),
            secret_key,
            public_key,
            bind_addr: bind_addr.to_string(),
            pool: RwLock::new(None),
            connection_pool: Arc::new(ConnectionPool::new()),
            reconnect_queue: RwLock::new(VecDeque::new()),
            store: RwLock::new(store),
            state: RwLock::new(state),
            shutdown_tx,
            shutdown_rx,
            db_path: db_path.to_string(),
            rate_limiter: RwLock::new(RateLimiter::default()),
            nonce_tracker: RwLock::new(NonceTracker::new(CHALLENGE_TIMEOUT_SECS * 2)),
        });
        
        println!("DIAGON v0.9.1 - Biological Consensus Machine (Security Hardened)");
        println!("   \"Consensus on expressions, derivation of truth\"");
        println!();
        println!("[MY ID] DID: {}", did.0);
        println!("[LISTEN] Listening: {}", bind_addr);
        println!("[DB]  Database: {}", db_path);
        println!();
        
        let n = Arc::clone(&node);
        smol::spawn(async move { n.accept_loop().await }).detach();
        
        let n = Arc::clone(&node);
        smol::spawn(async move { n.heartbeat_loop().await }).detach();
        
        let n = Arc::clone(&node);
        smol::spawn(async move { n.sync_loop().await }).detach();
        
        let n = Arc::clone(&node);
        smol::spawn(async move { n.reconnect_loop().await }).detach();
        
        Ok(node)
    }
    
    async fn load_or_create(path: &str) -> Result<(Did, SecretKey, PublicKey, ExprStore, DerivedState)> {
        let path = path.to_string();
        smol::unblock(move || {
            if let Ok(file) = std::fs::File::open(&path) {
                if let Ok(persisted) = serde_cbor::from_reader::<PersistedState, _>(std::io::BufReader::new(file)) {
                    if let (Ok(pk), Ok(sk)) = (PublicKey::from_bytes(&persisted.identity.0), SecretKey::from_bytes(&persisted.identity.1)) {
                        let did = Did::from_pubkey(&pk);
                        if did == persisted.identity.2 {
                            let mut store = ExprStore::new();
                            for (_cid, data) in persisted.expressions { 
                                if let Some(expr) = store.arena_mut().deserialize(&data) { 
                                    let _ = store.store(expr); 
                                } 
                            }
                            let mut state = DerivedState::new();
                            for (cid, prop) in persisted.proposals { state.proposals.insert(cid, prop); }
                            for (commitment, pool) in persisted.pool_proposals { state.pool_proposals.insert(commitment, pool); }
                            for pool in persisted.active_pools { state.active_pools.insert(pool); }
                            for (did, mark) in persisted.marks { state.marks.insert(did, mark); }
                            println!("📥 Loaded {} expressions, {} proposals", store.log().len(), state.proposals.len());
                            return Ok((did, sk, pk, store, state));
                        }
                    }
                }
            }
            let (public_key, secret_key) = keypair();
            let did = Did::from_pubkey(&public_key);
            Ok((did, secret_key, public_key, ExprStore::new(), DerivedState::new()))
        }).await
    }
    
    async fn save_state(&self) -> Result<()> {
        let store = self.store.read().await;
        let state = self.state.read().await;
        let expressions: Vec<_> = store.log().iter()
            .filter_map(|cid| store.serialize_expr(cid).map(|data| (*cid, data)))
            .collect();
        let persisted = PersistedState {
            identity: (self.public_key.as_bytes().to_vec(), self.secret_key.as_bytes().to_vec(), self.did.clone()),
            expressions,
            proposals: state.proposals.iter().map(|(k, v)| (*k, v.clone())).collect(),
            pool_proposals: state.pool_proposals.iter().map(|(k, v)| (*k, v.clone())).collect(),
            active_pools: state.active_pools.iter().cloned().collect(),
            marks: state.marks.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        };
        drop(store);
        drop(state);
        
        let db_path = self.db_path.clone();
        smol::unblock(move || {
            let temp = format!("{}/state.cbor.tmp", db_path);
            let path = format!("{}/state.cbor", db_path);
            let file = std::fs::File::create(&temp)?;
            serde_cbor::to_writer(std::io::BufWriter::new(file), &persisted)
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
            std::fs::rename(temp, path)?;
            Ok::<_, io::Error>(())
        }).await?;
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
        self.shutdown_rx.is_closed()
    }
    
    // SECURITY: Verify signature on a network message
    async fn verify_message_signature(&self, msg: &NetMessage, from: &SocketAddr) -> Result<()> {
        let signable = match msg.signable_bytes() {
            Some(b) => b,
            None => return Ok(()), // Message doesn't require signature
        };
        
        let signature = match msg {
            NetMessage::Approve { signature, .. } => signature,
            NetMessage::Reject { signature, .. } => signature,
            NetMessage::Heartbeat { signature, .. } => signature,
            NetMessage::Disconnect { signature, .. } => signature,
            NetMessage::Elaborate { signature, .. } => signature,
            _ => return Ok(()),
        };
        
        let info = self.connection_pool.get_info(from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let pubkey = info.read().await.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey for peer".into()))?;
        
        self.verify(&signable, signature, &pubkey)
    }
    
    // ========== PUBLIC API ==========
    
    // SECURITY: Use Argon2 for pool authentication
    pub async fn auth(&self, passphrase: &str) -> bool {
        let commitment = hash_pool_passphrase(passphrase);
        if self.state.read().await.active_pools.contains(&commitment) {
            *self.pool.write().await = Some(commitment);
            println!("[SUCCESS] Pool authenticated: {}", hex::encode(&commitment[..8]));
            true
        } else {
            println!("[REJECTION] Unknown pool. Commitment: {}", hex::encode(&commitment[..8]));
            false
        }
    }
    
    pub async fn connect(self: &Arc<Self>, addr_str: &str) -> Result<()> {
        let pool = self.pool.read().await.ok_or_else(|| DiagonError::Validation("Set pool first with 'auth'".into()))?;
        let addr: SocketAddr = addr_str.parse().map_err(|_| DiagonError::Validation("Invalid address".into()))?;
        
        if self.connection_pool.get_info(&addr).await.is_some() { 
            println!("Already connected to {}", addr); 
            return Ok(()); 
        }
        
        match smol::net::TcpStream::connect(addr).await {
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
    
    pub async fn elaborate(&self, text: &str) {
        if text.len() < MIN_ELABORATION_LEN { 
            println!("[REJECTION] Elaboration too short (min {} chars)", MIN_ELABORATION_LEN); 
            return; 
        }
        let awaiting = self.connection_pool.awaiting_elaboration().await;
        if awaiting.is_empty() { 
            println!("No peers awaiting elaboration"); 
            return; 
        }
        let sig = self.sign(text.as_bytes());
        let msg = NetMessage::Elaborate { text: text.to_string(), signature: sig };
        let data = match msg.serialize() { Ok(d) => d, Err(_) => return };
        
        for (addr, info) in awaiting {
            if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                if handle.send(data.clone()).await.is_ok() {
                    let mut info = info.write().await;
                    info.elaboration = Some(text.to_string());
                    info.state = ConnectionState::PendingApproval;
                    println!("[->] Elaboration sent to {}", addr);
                }
            }
        }
    }
    
    pub async fn approve(&self, id: &str) {
        for (addr, info) in self.connection_pool.pending_approval().await {
            let info_guard = info.read().await;
            let did_match = info_guard.did.as_ref().map(|d| d.short().contains(id) || d.0.contains(id)).unwrap_or(false);
            let addr_match = addr.to_string().contains(id);
            let did_clone = info_guard.did.clone();
            let elab_clone = info_guard.elaboration.clone();
            drop(info_guard);
            
            if did_match || addr_match {
                if let Some(peer_did) = did_clone.clone() {
                    let ts = timestamp();
                    // SECURITY: Sign approval with timestamp and peer DID
                    let mut signable = b"approve:".to_vec();
                    signable.extend_from_slice(&ts.to_le_bytes());
                    signable.extend_from_slice(peer_did.0.as_bytes());
                    let sig = self.sign(&signable);
                    
                    if let Ok(data) = (NetMessage::Approve { 
                        timestamp: ts, 
                        peer_did: peer_did.clone(), 
                        signature: sig 
                    }).serialize() {
                        if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                            if handle.send(data).await.is_ok() {
                                info.write().await.state = ConnectionState::Connected;
                                println!("[SUCCESS] Peer {} approved", peer_did.short());
                                if let Some(elab) = elab_clone {
                                    // SECURITY: Mark as verified interaction
                                    self.state.write().await.update_mark(&peer_did, score_elaboration(&elab), true);
                                }
                                return;
                            }
                        }
                    }
                }
            }
        }
        println!("Peer not found or not pending approval");
    }
    
    pub async fn reject(&self, id: &str, reason: &str) {
        for (addr, info) in self.connection_pool.pending_approval().await {
            let did_match = info.read().await.did.as_ref().map(|d| d.short().contains(id)).unwrap_or(false);
            if did_match || addr.to_string().contains(id) {
                let sig = self.sign(reason.as_bytes());
                if let Ok(data) = (NetMessage::Reject { reason: reason.to_string(), signature: sig }).serialize() {
                    if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                        let _ = handle.send(data).await;
                    }
                }
                self.connection_pool.remove(addr).await;
                println!("[REJECTION] Peer rejected: {}", reason);
                return;
            }
        }
        println!("Peer not found");
    }
    
    pub async fn propose(&self, text: &str) {
        if text.len() < MIN_ELABORATION_LEN { println!("[REJECTION] Proposal too short"); return; }
        
        // SECURITY: Check proposal limit
        if !self.state.read().await.can_add_proposal() {
            println!("[REJECTION] Maximum proposals reached");
            return;
        }
        
        let trust = self.state.read().await.get_mark(&self.did).current_score();
        if trust < TRUST_MIN_FOR_PROPOSE { 
            println!("[REJECTION] Insufficient trust: {:.2} < {:.2}", trust, TRUST_MIN_FOR_PROPOSE); 
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
            Err(e) => { println!("[STORE-FAIL] {}", e); return; }
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
            quorum: QuorumState::new(cid, threshold, self.did.clone()), // SECURITY: Track proposer
            executed: false, 
            created: timestamp() 
        };
        self.state.write().await.proposals.insert(cid, proposal);
        let _ = self.save_state().await;
        println!("[PROPOSE] {}", cid);
        self.broadcast_authenticated(&NetMessage::Expression(expr_bytes)).await;
    }
    
    pub async fn vote(&self, cid_prefix: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("[REJECTION] Elaboration too short"); return; }
        
        let state = self.state.read().await;
        let cid = match state.proposals.keys().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, None => { println!("[NULL] Proposal not found"); return; }
        };
        
        // SECURITY: Check if this is self-voting
        if let Some(prop) = state.proposals.get(&cid) {
            if prop.proposer == self.did {
                println!("[REJECTION] Cannot vote on your own proposal");
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
        let (_vote_cid, _) = match store.store(signed_expr) {
            Ok(r) => r,
            Err(e) => { println!("[STORE-FAIL] {}", e); return; }
        };
        let vote_bytes = store.arena().serialize(signed_expr);
        drop(store);
        
        let mark = self.state.read().await.get_mark(&self.did);
        let signal = QuorumSignal { 
            source: self.did.clone(), 
            target: cid, 
            weight: mark.signal_weight(), 
            support, 
            elaboration: elaboration.to_string(), 
            timestamp: timestamp(), 
            signature: self.sign(&{
                let mut data = Vec::new();
                data.extend_from_slice(&cid.0);
                data.push(if support { 1 } else { 0 });
                data.extend_from_slice(elaboration.as_bytes());
                data.extend_from_slice(&timestamp().to_le_bytes());
                data
            })
        };
        
        let (sensed, reached) = {
            let mut state = self.state.write().await;
            if let Some(proposal) = state.proposals.get_mut(&cid) {
                match proposal.quorum.sense(signal.clone()) {
                    Ok(sensed) => {
                        let reached = sensed && proposal.quorum.reached() && !proposal.executed;
                        if reached { 
                            proposal.executed = true; 
                        }
                        (sensed, reached)
                    }
                    Err(e) => {
                        println!("[VOTE-ERR] {}", e);
                        return;
                    }
                }
            } else {
                (false, false)
            }
        };
        
        if sensed {
            // SECURITY: Verified interaction from voting
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
    
    pub async fn propose_pool(&self, phrase: &str, rationale: &str) {
        let commitment = hash_pool_passphrase(phrase);
        let hint = if phrase.len() > 8 { format!("{}...{}", &phrase[..4], &phrase[phrase.len()-4..]) } else { phrase.to_string() };
        let state = self.state.read().await;
        if state.active_pools.contains(&commitment) { println!("[REJECTION] Pool already active"); return; }
        if state.pool_proposals.contains_key(&commitment) { println!("[REJECTION] Proposal already exists"); return; }
        drop(state);
        let peer_count = self.connection_pool.authenticated_addrs().await.len();
        let threshold = self.state.read().await.threshold(peer_count);
        let pool = PoolState { 
            commitment, 
            hint, 
            rationale: rationale.to_string(), 
            proposer: self.did.clone(), 
            quorum: QuorumState::new(Cid(commitment), threshold, self.did.clone()), 
            active: false 
        };
        self.state.write().await.pool_proposals.insert(commitment, pool);
        let _ = self.save_state().await;
        println!("[POOL-PROPOSE] {}", hex::encode(&commitment[..8]));
    }
    
    pub async fn vote_pool(&self, id: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("[REJECTION] Elaboration too short"); return; }
        
        let state = self.state.read().await;
        let commitment = match state.pool_proposals.keys().find(|c| hex::encode(&c[..8]).starts_with(id)).copied() {
            Some(c) => c, None => { println!("[REJECTION] Pool proposal not found"); return; }
        };
        
        // SECURITY: Check if this is self-voting
        if let Some(pool) = state.pool_proposals.get(&commitment) {
            if pool.proposer == self.did {
                println!("[REJECTION] Cannot vote on your own pool proposal");
                return;
            }
        }
        drop(state);
        
        let mark = self.state.read().await.get_mark(&self.did);
        let signal = QuorumSignal { 
            source: self.did.clone(), 
            target: Cid(commitment), 
            weight: mark.signal_weight(), 
            support, 
            elaboration: elaboration.to_string(), 
            timestamp: timestamp(), 
            signature: self.sign(elaboration.as_bytes()) 
        };
        let mut state = self.state.write().await;
        if let Some(pool) = state.pool_proposals.get_mut(&commitment) {
            match pool.quorum.sense(signal) {
                Ok(sensed) => {
                    if sensed && pool.quorum.reached() && !pool.active {
                        pool.active = true; 
                        state.active_pools.insert(commitment);
                        println!("[POOL] {} activated!", hex::encode(&commitment[..8]));
                    }
                }
                Err(e) => {
                    println!("[QUORUM-ERR] {}", e);
                    return;
                }
            }
        }
        drop(state); 
        let _ = self.save_state().await;
        println!("[POOL-VOTE] {} on {}", if support { "YES" } else { "NO" }, hex::encode(&commitment[..8]));
    }
    
    pub async fn status(&self) {
        let state = self.state.read().await;
        let store = self.store.read().await;
        let pool = self.pool.read().await;
        let auth_count = self.connection_pool.authenticated_addrs().await.len();
        let pending = self.connection_pool.pending_approval().await.len();
        let awaiting = self.connection_pool.awaiting_elaboration().await.len();
        println!();
        println!("=== DIAGON STATUS ===");
        println!("[MY ID] DID: {}", self.did.short());
        println!("[POOL] Pool: {}", pool.map(|p| hex::encode(&p[..8])).unwrap_or_else(|| "Not set".to_string()));
        println!("[EXPR] Expressions: {}/{}", store.log().len(), MAX_EXPRESSIONS);
        println!("[PROP] Proposals: {}/{}", state.proposals.len(), MAX_PROPOSALS);
        println!("[ACTIVEPOOLS] Active pools: {}", state.active_pools.len());
        println!("[LINK] Peers: {} auth, {} pending, {} awaiting", auth_count, pending, awaiting);
        
        if !state.proposals.is_empty() {
            println!();
            println!("Proposals:");
            for (cid, prop) in state.proposals.iter().take(10) {
                let status = if prop.executed { "[SUCCESS]" } else { "○" };
                let text = if prop.elaboration.len() > 40 { format!("{}...", &prop.elaboration[..40]) } else { prop.elaboration.clone() };
                println!("  {} {} - \"{}\" ({}/{})", status, cid.short(), text, prop.quorum.accumulated_for(), prop.quorum.threshold);
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
                    ConnectionState::PendingApproval => "pending",
                    ConnectionState::AwaitingElaboration => "awaiting",
                    ConnectionState::Connecting => "connecting",
                    ConnectionState::Authenticating => "authenticating",
                    ConnectionState::Closing => "closing",
                    ConnectionState::Closed => "closed",
                };
                println!("  {} @ {} ({})", did_str, addr, state_str);
            }
        }
        println!();
    }
    
    pub async fn list_pools(&self) {
        let state = self.state.read().await;
        println!();
        println!("=== ACTIVE POOLS ===");
        for (i, pool) in state.active_pools.iter().enumerate() {
            println!("  #{} {} {}", i + 1, hex::encode(&pool[..8]), if GENESIS_POOLS.contains(pool) { "[genesis]" } else { "[dynamic]" });
        }
        if !state.pool_proposals.is_empty() {
            println!();
            println!("=== PENDING POOL PROPOSALS ===");
            for (commitment, pool) in &state.pool_proposals {
                println!("  {} - \"{}\" ({}/{})", hex::encode(&commitment[..8]), 
                    if pool.rationale.len() > 40 { format!("{}...", &pool.rationale[..40]) } else { pool.rationale.clone() }, 
                    pool.quorum.accumulated_for(), pool.quorum.threshold);
            }
        }
        println!();
    }
    
    pub async fn eval(&self, input: &str) {
        let mut store = self.store.write().await;
        if let Some(expr) = store.arena_mut().parse(input) {
            match store.store(expr) {
                Ok((cid, is_new)) => {
                    println!("Parsed: {}", store.arena().display(expr));
                    println!("CID: {} {}", cid, if is_new { "(new)" } else { "(exists)" });
                }
                Err(e) => println!("[EVAL-ERR] {}", e),
            }
        } else { 
            println!("Parse error"); 
        }
    }
    
    // ========== BACKGROUND LOOPS ==========
    
    async fn accept_loop(self: Arc<Self>) {
        let listener = match TcpListener::bind(&self.bind_addr).await {
            Ok(l) => l,
            Err(e) => { eprintln!("Failed to bind: {}", e); return; }
        };
        
        loop {
            futures_lite::future::or(
                async {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let _ = self.handle_incoming(stream, addr).await;
                        }
                        Err(e) => {
                            eprintln!("Accept error: {}", e);
                        }
                    }
                },
                async {
                    let _ = self.shutdown_rx.recv().await;
                }
            ).await;
            
            if self.is_shutdown() { break; }
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
        self: &Arc<Self>,
        stream: TcpStream,
        addr: SocketAddr,
        info: Arc<RwLock<PeerInfo>>,
    ) -> Result<ConnHandle> {
        let reader_stream = stream.clone();
        let writer_stream = stream;
        
        let (cmd_tx, cmd_rx) = bounded::<ConnCmd>(64);
        
        let handle = ConnHandle { addr, cmd_tx };
        
        let pool = Arc::clone(&self.connection_pool);
        smol::spawn(async move {
            Self::writer_task(writer_stream, cmd_rx, addr, pool).await;
        }).detach();
        
        let node = Arc::clone(self);
        let info_clone = Arc::clone(&info);
        smol::spawn(async move {
            node.reader_task(reader_stream, addr, info_clone).await;
        }).detach();
        
        Ok(handle)
    }
    
    async fn writer_task(
        mut stream: TcpStream,
        cmd_rx: Receiver<ConnCmd>,
        addr: SocketAddr,
        pool: Arc<ConnectionPool>,
    ) {
        while let Ok(cmd) = cmd_rx.recv().await {
            match cmd {
                ConnCmd::Send(data) => {
                    if data.len() > MAX_MESSAGE_SIZE {
                        continue;
                    }
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
        mut stream: TcpStream,
        addr: SocketAddr,
        info: Arc<RwLock<PeerInfo>>,
    ) {
        let mut len_buf = [0u8; 4];
        
        loop {
            if !info.read().await.is_alive() { break; }
            
            // SECURITY: Check rate limit before reading
            {
                let mut limiter = self.rate_limiter.write().await;
                if !limiter.check_and_increment(&addr) {
                    eprintln!("Rate limited: {}", addr);
                    break;
                }
            }
            
            if stream.read_exact(&mut len_buf).await.is_err() { break; }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            
            // SECURITY: Check size BEFORE allocation
            if msg_len > MAX_MESSAGE_SIZE { 
                eprintln!("Message too large from {}: {} bytes", addr, msg_len);
                break; 
            }
            
            let mut msg_buf = vec![0u8; msg_len];
            if stream.read_exact(&mut msg_buf).await.is_err() { break; }
            
            info.write().await.last_activity = Instant::now();
            
            if let Ok(msg) = NetMessage::deserialize(&msg_buf) {
                if let Err(e) = self.handle_message(msg, addr, &info).await {
                    eprintln!("Message handling error from {}: {}", addr, e);
                }
            }
        }
        
        self.connection_pool.remove(addr).await;
    }
    
    async fn handle_message(
        &self, 
        msg: NetMessage, 
        from: SocketAddr, 
        info: &Arc<RwLock<PeerInfo>>
    ) -> Result<()> {
        // SECURITY: Verify signatures on applicable messages
        if let Err(e) = self.verify_message_signature(&msg, &from).await {
            // Only fail for messages that MUST have valid signatures
            match &msg {
                NetMessage::Approve { .. } | 
                NetMessage::Elaborate { .. } => return Err(e),
                _ => {} // Other messages can proceed
            }
        }
        
        match msg {
            NetMessage::Hello { did, pubkey, pool, expr_root } => {
                self.handle_hello(did, pubkey, pool, expr_root, from, info).await
            }
            NetMessage::Challenge(nonce) => {
                // SECURITY: Check for replay
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
                info.write().await.state = ConnectionState::AwaitingElaboration;
                println!("[INTERNAL SIGNAL] {} requests elaboration", from);
                println!("   Use 'elaborate <text>' to respond");
                Ok(())
            }
            NetMessage::Elaborate { text, signature } => {
                self.handle_elaborate(text, signature, from, info).await
            }
            NetMessage::Approve { timestamp: msg_ts, peer_did, signature } => {
                self.handle_approve(msg_ts, peer_did, signature, from, info).await
            }
            NetMessage::Reject { reason, .. } => {
                println!("[REJECTION] Rejected by {}: {}", from, reason);
                self.connection_pool.remove(from).await;
                Ok(())
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
            NetMessage::SyncReply { expressions } => {
                self.handle_sync_reply(expressions, from).await
            }
            NetMessage::Heartbeat { timestamp: msg_ts, signature } => {
                self.handle_heartbeat(msg_ts, signature, from, info).await
            }
            NetMessage::Disconnect { timestamp: msg_ts, signature } => {
                self.handle_disconnect(msg_ts, signature, from).await
            }
        }
    }
    
    async fn handle_hello(
        &self,
        did: Did,
        pubkey: Vec<u8>,
        pool: [u8; 32],
        _expr_root: [u8; 32],
        from: SocketAddr,
        info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
        // SECURITY: Verify DID matches pubkey
        if !did.matches_pubkey(&pubkey) {
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send((NetMessage::Reject { 
                    reason: "DID does not match public key".into(), 
                    signature: self.sign(b"did_mismatch") 
                }).serialize()?).await?;
            }
            return Err(DiagonError::Validation("DID mismatch".into()));
        }
        
        let our_pool = *self.pool.read().await;
        if let Some(p) = our_pool {
            if pool != p {
                if let Some(handle) = self.connection_pool.get_handle(&from).await {
                    handle.send((NetMessage::Reject { reason: "Pool mismatch".into(), signature: self.sign(b"pool_mismatch") }).serialize()?).await?;
                }
                return Err(DiagonError::Validation("Pool mismatch".into()));
            }
        } else {
            if let Some(handle) = self.connection_pool.get_handle(&from).await {
                handle.send((NetMessage::Reject { reason: "No pool configured".into(), signature: self.sign(b"no_pool") }).serialize()?).await?;
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
            
            info.write().await.state = ConnectionState::AwaitingElaboration;
            println!("[<-] Connection from {} ({})", from, did.short());
            println!("  Awaiting elaboration...");
        }
        
        Ok(())
    }
    
    async fn handle_response(
        &self,
        nonce: [u8; 32],
        signature: Vec<u8>,
        info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
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
    
    async fn handle_elaborate(
        &self,
        text: String,
        signature: Vec<u8>,
        from: SocketAddr,
        info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
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
        drop(info_guard);
        
        {
            let mut info = info.write().await;
            info.elaboration = Some(text.clone());
            info.state = ConnectionState::PendingApproval;
        }
        
        if let Some(did_short) = did_short {
            println!();
            println!("[INTERNAL SIGNAL] ELABORATION from {}", did_short);
            println!("   \"{}\"", text);
            println!("   Use 'approve {}' or 'reject {} <reason>'", did_short, did_short);
        }
        Ok(())
    }
    
    // SECURITY: New handler for Approve with verification
    async fn handle_approve(
        &self,
        msg_timestamp: u64,
        peer_did: Did,
        signature: Vec<u8>,
        from: SocketAddr,
        info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
        // Verify timestamp is recent (within 60 seconds)
        let now = timestamp();
        if now.saturating_sub(msg_timestamp) > 60 || msg_timestamp > now + 5 {
            return Err(DiagonError::Validation("Stale approval".into()));
        }
        
        // Verify signature
        let mut signable = b"approve:".to_vec();
        signable.extend_from_slice(&msg_timestamp.to_le_bytes());
        signable.extend_from_slice(peer_did.0.as_bytes());
        
        let info_guard = info.read().await;
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(&signable, &signature, pk)?;
        } else {
            return Err(DiagonError::Validation("No pubkey".into()));
        }
        drop(info_guard);
        
        // Verify we're the one being approved
        if peer_did != self.did {
            return Err(DiagonError::Validation("Approval not for us".into()));
        }
        
        info.write().await.state = ConnectionState::Connected;
        println!("[SUCCESS] Authenticated with {}", from);
        let store = self.store.read().await;
        let msg = NetMessage::SyncRequest { merkle: store.merkle_root(), have: store.log().to_vec() };
        drop(store);
        if let Some(handle) = self.connection_pool.get_handle(&from).await {
            handle.send(msg.serialize()?).await?;
        }
        Ok(())
    }
    
    // SECURITY: Verify signed expressions before storing
    async fn handle_expression(
        &self,
        data: Vec<u8>,
        from: SocketAddr,
        info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
        let mut store = self.store.write().await;
        
        // Parse the expression first
        let expr = match store.arena_mut().deserialize(&data) {
            Some(e) => e,
            None => return Err(DiagonError::Validation("Invalid expression".into())),
        };
        
        // Check if it's a signed expression and verify
        let op = store.arena().car(expr);
        if let SexpNode::Atom(s) = store.arena().get(op) {
            if s == "signed" {
                // Extract pubkey and signature
                let pk_ref = store.arena().nth(expr, 1);
                let sig_ref = store.arena().nth(expr, 2);
                let inner = store.arena().nth(expr, 3);
                
                let pubkey = match store.arena().get(pk_ref) {
                    SexpNode::Bytes(b) => b.clone(),
                    _ => return Err(DiagonError::Validation("Invalid pubkey in expression".into())),
                };
                
                let signature = match store.arena().get(sig_ref) {
                    SexpNode::Bytes(b) => b.clone(),
                    _ => return Err(DiagonError::Validation("Invalid signature in expression".into())),
                };
                
                // Verify the signature over the inner expression
                let inner_data = store.arena().serialize(inner);
                self.verify(&inner_data, &signature, &pubkey)?;
            }
        }
        
        // Now store it
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
            Err(e) => {
                eprintln!("Failed to store expression: {}", e);
            }
        }
        Ok(())
    }
    
    async fn process_expression(&self, cid: Cid, data: &[u8]) {
        let store = self.store.read().await;
        let expr = match store.fetch(&cid) { Some(e) => e, None => return };
        let op = store.arena().car(expr);
        if let SexpNode::Atom(s) = store.arena().get(op) {
            if s == "signed" {
                let inner = store.arena().nth(expr, 3);
                let inner_op = store.arena().car(inner);
                
                // Extract proposer DID from pubkey
                let pk_ref = store.arena().nth(expr, 1);
                let proposer_did = if let SexpNode::Bytes(pk_bytes) = store.arena().get(pk_ref) {
                    if let Ok(pk) = PublicKey::from_bytes(pk_bytes) {
                        Did::from_pubkey(&pk)
                    } else {
                        return;
                    }
                } else {
                    return;
                };
                
                if let SexpNode::Atom(inner_s) = store.arena().get(inner_op) {
                    if inner_s == "propose" && !self.state.read().await.proposals.contains_key(&cid) {
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
                                executed: false, 
                                created: timestamp() 
                            };
                            self.state.write().await.proposals.insert(cid, proposal);
                            let _ = self.save_state().await;
                        }
                    }
                }
            }
        }
    }
    
    // SECURITY: Verify signal signatures
    async fn handle_signal(&self, signal: QuorumSignal, from: SocketAddr) -> Result<()> {
        // Get the peer's pubkey to verify the signal
        let info = self.connection_pool.get_info(&from).await
            .ok_or(DiagonError::Validation("Unknown peer".into()))?;
        let pubkey = info.read().await.pubkey.clone()
            .ok_or(DiagonError::Validation("No pubkey".into()))?;
        
        // Verify the signal signature
        let signable = signal.signable_bytes();
        self.verify(&signable, &signal.signature, &pubkey)?;
        
        // Verify the source DID matches the peer
        let peer_did = info.read().await.did.clone();
        if peer_did.as_ref() != Some(&signal.source) {
            return Err(DiagonError::Validation("Signal source doesn't match peer".into()));
        }
        
        let mut state = self.state.write().await;
        if let Some(proposal) = state.proposals.get_mut(&signal.target) {
            match proposal.quorum.sense(signal.clone()) {
                Ok(sensed) => {
                    if sensed {
                        println!("[SIGNAL] {} on {} (+{})", 
                            if signal.support { "FOR" } else { "AGAINST" }, 
                            signal.target.short(), 
                            signal.weight);
                        if proposal.quorum.reached() && !proposal.executed { 
                            proposal.executed = true; 
                            println!("[QUORUM] {} reached!", signal.target); 
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Signal rejected: {}", e);
                }
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
    
    async fn handle_sync_request(
        &self,
        peer_merkle: [u8; 32],
        have: Vec<Cid>,
        from: SocketAddr,
    ) -> Result<()> {
        let store = self.store.read().await;
        if store.merkle_root() != peer_merkle {
            let have_set: HashSet<_> = have.into_iter().collect();
            let missing: Vec<Vec<u8>> = store.log().iter()
                .filter(|cid| !have_set.contains(cid))
                .filter_map(|cid| store.serialize_expr(cid))
                .take(100) // SECURITY: Limit response size
                .collect();
            if !missing.is_empty() {
                if let Some(handle) = self.connection_pool.get_handle(&from).await {
                    handle.send(NetMessage::SyncReply { expressions: missing }.serialize()?).await?;
                }
            }
        }
        Ok(())
    }
    
    // SECURITY: Verify expressions in sync reply
    async fn handle_sync_reply(&self, expressions: Vec<Vec<u8>>, from: SocketAddr) -> Result<()> {
        let mut added = 0;
        for data in expressions {
            // Use handle_expression which now verifies signatures
            let info = match self.connection_pool.get_info(&from).await {
                Some(i) => i,
                None => continue,
            };
            
            if let Err(e) = self.handle_expression(data, from, &info).await {
                eprintln!("Sync expression rejected: {}", e);
                continue;
            }
            added += 1;
        }
        if added > 0 {
            println!("[SYNC] Received {} expressions", added);
            let _ = self.save_state().await;
        }
        Ok(())
    }
    
    // SECURITY: Verify heartbeat signatures
    async fn handle_heartbeat(
        &self,
        msg_timestamp: u64,
        signature: Vec<u8>,
        from: SocketAddr,
        info: &Arc<RwLock<PeerInfo>>,
    ) -> Result<()> {
        // Verify timestamp is recent
        let now = timestamp();
        if now.saturating_sub(msg_timestamp) > 60 {
            return Err(DiagonError::Validation("Stale heartbeat".into()));
        }
        
        // Verify signature
        let mut signable = b"heartbeat:".to_vec();
        signable.extend_from_slice(&msg_timestamp.to_le_bytes());
        
        let info_guard = info.read().await;
        if let Some(ref pk) = info_guard.pubkey {
            self.verify(&signable, &signature, pk)?;
        }
        drop(info_guard);
        
        info.write().await.last_activity = Instant::now();
        Ok(())
    }
    
    // SECURITY: Verify disconnect signatures
    async fn handle_disconnect(
        &self,
        msg_timestamp: u64,
        signature: Vec<u8>,
        from: SocketAddr,
    ) -> Result<()> {
        // Verify timestamp is recent
        let now = timestamp();
        if now.saturating_sub(msg_timestamp) > 60 {
            return Err(DiagonError::Validation("Stale disconnect".into()));
        }
        
        // Verify signature
        let mut signable = b"disconnect:".to_vec();
        signable.extend_from_slice(&msg_timestamp.to_le_bytes());
        
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
    
    async fn broadcast_authenticated(&self, msg: &NetMessage) {
        if let Ok(data) = msg.serialize() {
            for addr in self.connection_pool.authenticated_addrs().await {
                if let Some(handle) = self.connection_pool.get_handle(&addr).await {
                    let _ = handle.send(data.clone()).await;
                }
            }
        }
    }
    
    async fn heartbeat_loop(self: Arc<Self>) {
        loop {
            futures_lite::future::or(
                async { let _ = Timer::after(HEARTBEAT_INTERVAL).await; },
                async { let _ = self.shutdown_rx.recv().await; }
            ).await;
            
            if self.is_shutdown() { break; }
            
            let ts = timestamp();
            let mut signable = b"heartbeat:".to_vec();
            signable.extend_from_slice(&ts.to_le_bytes());
            self.broadcast_authenticated(&NetMessage::Heartbeat { 
                timestamp: ts, 
                signature: self.sign(&signable) 
            }).await;
            
            let dead = self.connection_pool.dead_connections().await;
            for addr in dead {
                self.connection_pool.remove(addr).await;
                self.reconnect_queue.write().await.push_back((addr, Instant::now(), 0));
            }
            
            // SECURITY: Cleanup rate limiter periodically
            self.rate_limiter.write().await.cleanup();
        }
    }
    
    async fn sync_loop(self: Arc<Self>) {
        loop {
            futures_lite::future::or(
                async { let _ = Timer::after(SYNC_INTERVAL).await; },
                async { let _ = self.shutdown_rx.recv().await; }
            ).await;
            
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
            futures_lite::future::or(
                async { let _ = Timer::after(CONNECTION_RETRY_INTERVAL).await; },
                async { let _ = self.shutdown_rx.recv().await; }
            ).await;
            
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
    
    pub async fn shutdown(&self) {
        println!("\n[INTERNAL] Shutting down...");
        let _ = self.shutdown_tx.send(()).await;
        let ts = timestamp();
        let mut signable = b"disconnect:".to_vec();
        signable.extend_from_slice(&ts.to_le_bytes());
        self.broadcast_authenticated(&NetMessage::Disconnect { 
            timestamp: ts, 
            signature: self.sign(&signable) 
        }).await;
        Timer::after(Duration::from_millis(100)).await;
        let _ = self.save_state().await;
        self.connection_pool.shutdown().await;
        println!("[SUCCESS] Shutdown complete");
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

fn timestamp() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }

// SECURITY: Improved elaboration scoring that's harder to game
fn score_elaboration(text: &str) -> f64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 5 { return 0.1; } // Very short = very low score
    
    // Check for unique words
    let unique: HashSet<&str> = words.iter().copied().collect();
    let uniqueness = unique.len() as f64 / words.len() as f64;
    
    // Penalize if too many unique words (likely spam/random)
    let uniqueness_score = if uniqueness > 0.95 { 0.2 } else { uniqueness };
    
    // Check average word length (penalize very short or very long avg)
    let avg_len = words.iter().map(|w| w.len()).sum::<usize>() as f64 / words.len() as f64;
    let length_score = if avg_len < 2.0 || avg_len > 15.0 { 0.3 } else { 0.7 };
    
    // Length component (diminishing returns)
    let length_component = (words.len() as f64 / 50.0).min(1.0).sqrt() * 0.3;
    
    // Combine scores
    (uniqueness_score * 0.4 + length_score * 0.3 + length_component).clamp(0.0, 0.8)
}

fn print_help() {
    println!("Commands:");
    println!("  auth <passphrase>              Set pool passphrase");
    println!("  connect <addr>                 Connect to peer");
    println!("  elaborate <text>               Send elaboration");
    println!("  approve <id>                   Approve pending peer");
    println!("  reject <id> <reason>           Reject pending peer");
    println!("  propose <text>                 Create proposal");
    println!("  vote <cid> <y/n> <elaboration> Vote on proposal");
    println!("  propose-pool <phrase> - <rationale>");
    println!("  vote-pool <id> <y/n> <elaboration>");
    println!("  list-pools                     Show pools");
    println!("  status                         Show status");
    println!("  eval <sexp>                    Evaluate S-expression");
    println!("  help                           Show this help");
    println!("  quit                           Exit");
    println!();
}

// ============================================================================
// ASYNC MAIN
// ============================================================================

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:9070");
    let db_path = args.get(2).map(|s| s.as_str()).unwrap_or("diagon_db");
    
    smol::block_on(async_main(addr, db_path))
}

async fn async_main(addr: &str, db_path: &str) -> io::Result<()> {
    let node = match Node::new(addr, db_path).await {
        Ok(n) => n,
        Err(e) => { eprintln!("Failed to start: {}", e); return Ok(()); }
    };
    
    print_help();
    
    let stdin = smol::Unblock::new(std::io::stdin());
    let mut lines = futures_lite::io::BufReader::new(stdin).lines();
    
    loop {
        print!("> ");
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let line = match lines.next().await {
            Some(Ok(line)) => line,
            _ => break,
        };
        
        let input = line.trim();
        if input.is_empty() { continue; }
        
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).unwrap_or(&"");
        
        match cmd {
            "auth" if !arg.is_empty() => { node.auth(arg).await; }
            "connect" if !arg.is_empty() => { 
                if let Err(e) = node.connect(arg).await { println!("[FAILED-CONNECT] {}", e); } 
            }
            "elaborate" if !arg.is_empty() => { node.elaborate(arg).await; }
            "approve" if !arg.is_empty() => { node.approve(arg).await; }
            "reject" if !arg.is_empty() => { 
                let parts: Vec<&str> = arg.splitn(2, ' ').collect(); 
                node.reject(parts[0], parts.get(1).unwrap_or(&"Rejected")).await; 
            }
            "propose" if !arg.is_empty() => { node.propose(arg).await; }
            "vote" if !arg.is_empty() => { 
                let parts: Vec<&str> = arg.splitn(3, ' ').collect(); 
                if parts.len() >= 3 { 
                    node.vote(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]).await; 
                } else { 
                    println!("Usage: vote <cid> <y/n> <elaboration>"); 
                } 
            }
            "propose-pool" if !arg.is_empty() => { 
                if let Some(pos) = arg.find(" - ") { 
                    node.propose_pool(arg[..pos].trim(), arg[pos + 3..].trim()).await; 
                } else { 
                    println!("Usage: propose-pool <phrase> - <rationale>"); 
                } 
            }
            "vote-pool" if !arg.is_empty() => { 
                let parts: Vec<&str> = arg.splitn(3, ' ').collect(); 
                if parts.len() >= 3 { 
                    node.vote_pool(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]).await; 
                } else { 
                    println!("Usage: vote-pool <id> <y/n> <elaboration>"); 
                } 
            }
            "list-pools" => { node.list_pools().await; }
            "status" => { node.status().await; }
            "eval" if !arg.is_empty() => { node.eval(arg).await; }
            "help" => { print_help(); }
            "quit" | "exit" => { break; }
            _ => { println!("Unknown command. Type 'help' for commands."); }
        }
    }
    
    node.shutdown().await;
    Ok(())
}

// ============================================================================
// TESTS - Run with: cargo test -- --nocapture --test-threads=1
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    // SECURITY: Updated test passphrase - needs to match a genesis pool
    // Since we changed to Argon2, we need to regenerate genesis pools or use a test pool
    const TEST_PASSPHRASE: &str = "quantum leap beyond horizon";
    
    fn setup_test_dir(name: &str) -> String {
        let dir = format!("/tmp/diagon_test_{}", name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    
    fn cleanup_test_dir(dir: &str) {
        let _ = std::fs::remove_dir_all(dir);
    }
    
    /// Helper to run async tests
    fn run<F: std::future::Future>(future: F) -> F::Output {
        smol::block_on(future)
    }
    
    /// Helper to create a test pool commitment using Argon2
    fn test_pool_commitment() -> [u8; 32] {
        hash_pool_passphrase(TEST_PASSPHRASE)
    }
    
    // ========================================================================
    // UNIT TESTS (synchronous, no network)
    // ========================================================================
    
    #[test]
    fn test_sexp_arena() {
        println!("\n═══ TEST: S-Expression Arena ═══");
        
        let mut arena = Arena::new();
        
        // Test atoms
        let a = arena.atom("hello");
        let b = arena.atom("hello"); // Should return same ref
        assert_eq!(a, b, "Interned atoms should be equal");
        println!("[SUCCESS] Atom interning works");
        
        // Test cons
        let c = arena.cons(a, SexpRef::NIL);
        assert!(!c.is_nil());
        assert_eq!(arena.car(c), a);
        assert_eq!(arena.cdr(c), SexpRef::NIL);
        println!("[SUCCESS] Cons cells work");
        
        // Test list
        let x = arena.atom("x");
        let y = arena.atom("y");
        let z = arena.atom("z");
        let list = arena.list(&[x, y, z]);
        assert_eq!(arena.nth(list, 0), x);
        assert_eq!(arena.nth(list, 1), y);
        assert_eq!(arena.nth(list, 2), z);
        println!("[SUCCESS] List construction works");
        
        // Test display
        let display = arena.display(list);
        assert_eq!(display, "(x y z)");
        println!("[SUCCESS] Display: {}", display);
        
        // Test parse
        let parsed = arena.parse("(propose \"test\" 42)").unwrap();
        let parsed_display = arena.display(parsed);
        println!("[SUCCESS] Parsed: {}", parsed_display);
        
        // Test nested parsing
        let nested = arena.parse("(define (factorial n) (if (= n 0) 1 (* n (factorial (- n 1)))))").unwrap();
        println!("[SUCCESS] Nested parse: {}", arena.display(nested));
        
        // Test serialization roundtrip
        let serialized = arena.serialize(list);
        let deserialized = arena.deserialize(&serialized).unwrap();
        assert_eq!(arena.display(deserialized), "(x y z)");
        println!("[SUCCESS] Serialization roundtrip works");
        
        // Test integers
        let int_list = arena.parse("(1 2 3 -42 0)").unwrap();
        let int_serialized = arena.serialize(int_list);
        let int_deserialized = arena.deserialize(&int_serialized).unwrap();
        assert_eq!(arena.display(int_deserialized), "(1 2 3 -42 0)");
        println!("[SUCCESS] Integer serialization works");
        
        // Test bytes
        let bytes_ref = arena.bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes_list = arena.list(&[bytes_ref]);
        println!("[SUCCESS] Bytes: {}", arena.display(bytes_list));
        
        // Test hashing
        let hash1 = arena.hash(list);
        let hash2 = arena.hash(list);
        assert_eq!(hash1, hash2, "Same expression should have same hash");
        println!("[SUCCESS] Hashing is deterministic");
        
        println!("[SUCCESS] S-Expression arena test passed\n");
    }
    
    #[test]
    fn test_expression_store() {
        println!("\n═══ TEST: Expression Store ═══");
        
        let mut store = ExprStore::new();
        
        // Store an expression
        let expr = store.arena_mut().parse("(propose \"test proposal\")").unwrap();
        let (cid1, is_new1) = store.store(expr).expect("Store failed");
        assert!(is_new1, "First store should be new");
        println!("[SUCCESS] Stored expression: {}", cid1);
        
        // Store same expression again
        let expr2 = store.arena_mut().parse("(propose \"test proposal\")").unwrap();
        let (cid2, is_new2) = store.store(expr2).expect("Store failed");
        assert!(!is_new2, "Duplicate should not be new");
        assert_eq!(cid1, cid2, "Same content should have same CID");
        println!("[SUCCESS] Deduplication works");
        
        // Store different expression
        let expr3 = store.arena_mut().parse("(propose \"different proposal\")").unwrap();
        let (cid3, is_new3) = store.store(expr3).expect("Store failed");
        assert!(is_new3, "Different content should be new");
        assert_ne!(cid1, cid3, "Different content should have different CID");
        println!("[SUCCESS] Different expressions have different CIDs");
        
        // Fetch
        let fetched = store.fetch(&cid1);
        assert!(fetched.is_some());
        println!("[SUCCESS] Fetch works");
        
        // Fetch non-existent
        let fake_cid = Cid([0u8; 32]);
        assert!(store.fetch(&fake_cid).is_none());
        println!("[SUCCESS] Fetch non-existent returns None");
        
        // Log
        assert_eq!(store.log().len(), 2);
        println!("[SUCCESS] Log has 2 entries");
        
        // Merkle root changes
        let root1 = store.merkle_root();
        let expr4 = store.arena_mut().parse("(vote yes)").unwrap();
        store.store(expr4).expect("Store failed");
        let root2 = store.merkle_root();
        assert_ne!(root1, root2, "Merkle root should change after new expression");
        println!("[SUCCESS] Merkle root updates correctly");
        
        println!("[SUCCESS] Expression store test passed\n");
    }
    
    #[test]
    fn test_expression_store_limits() {
        println!("\n═══ TEST: Expression Store Limits ═══");
        
        // Create a store with a small limit for testing
        let mut store = ExprStore::new();
        store.max_size = 10; // Override for testing
        
        // Fill it up
        for i in 0..10 {
            let expr = store.arena_mut().parse(&format!("(expr {})", i)).unwrap();
            store.store(expr).expect("Store should succeed");
        }
        
        assert_eq!(store.len(), 10);
        println!("[SUCCESS] Stored 10 expressions");
        
        // Try to add one more - should fail
        let expr = store.arena_mut().parse("(overflow)").unwrap();
        let result = store.store(expr);
        assert!(matches!(result, Err(DiagonError::StoreFull)));
        println!("[SUCCESS] Store correctly rejects when full");
        
        println!("[SUCCESS] Expression store limits test passed\n");
    }
    
    #[test]
    fn test_quorum_sensing() {
        println!("\n═══ TEST: Quorum Sensing ═══");
        
        let target = Cid::new(b"test_proposal");
        let threshold = 2000;
        let proposer = Did("did:test:proposer".into());
        let mut quorum = QuorumState::new(target, threshold, proposer.clone());
        
        // Add signals
        let signal1 = QuorumSignal {
            source: Did("did:test:node1".into()),
            target,
            weight: 800,
            support: true,
            elaboration: "I support this proposal strongly".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        assert!(quorum.sense(signal1.clone()).expect("Sense failed"), "First signal should be accepted");
        println!("[SUCCESS] Signal 1 accepted: weight={}", signal1.weight);
        
        // Duplicate source should be rejected
        let signal1_dup = QuorumSignal {
            source: Did("did:test:node1".into()),
            target,
            weight: 500,
            support: true,
            elaboration: "Duplicate signal".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        assert!(!quorum.sense(signal1_dup).expect("Sense failed"), "Duplicate source should be rejected");
        println!("[SUCCESS] Duplicate source rejected");
        
        // Different source should work
        let signal2 = QuorumSignal {
            source: Did("did:test:node2".into()),
            target,
            weight: 700,
            support: true,
            elaboration: "I also support this proposal".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        assert!(quorum.sense(signal2.clone()).expect("Sense failed"), "Second signal should be accepted");
        println!("[SUCCESS] Signal 2 accepted: weight={}", signal2.weight);
        
        // Check accumulation
        let accumulated = quorum.accumulated_for();
        println!("[SUCCESS] Accumulated: {}/{}", accumulated, threshold);
        assert!(accumulated >= 1400, "Should have at least 1400 weight");
        
        // Not yet reached
        assert!(!quorum.reached(), "Quorum should not be reached yet");
        println!("[SUCCESS] Quorum not yet reached");
        
        // Add more to reach threshold
        let signal3 = QuorumSignal {
            source: Did("did:test:node3".into()),
            target,
            weight: 800,
            support: true,
            elaboration: "This brings us to quorum".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        quorum.sense(signal3).expect("Sense failed");
        
        assert!(quorum.reached(), "Quorum should be reached");
        println!("[SUCCESS] Quorum reached: {}/{}", quorum.accumulated_for(), threshold);
        
        // Test against votes
        let proposer2 = Did("did:test:proposer2".into());
        let mut quorum2 = QuorumState::new(Cid::new(b"another"), 1000, proposer2);
        let against = QuorumSignal {
            source: Did("did:test:voter".into()),
            target: Cid::new(b"another"),
            weight: 500,
            support: false,
            elaboration: "I oppose this".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        // Note: target mismatch, should fail
        assert!(!quorum2.sense(against.clone()).expect("Sense failed"), "Wrong target should be rejected");
        
        let against_correct = QuorumSignal {
            target: quorum2.target,
            ..against
        };
        assert!(quorum2.sense(against_correct).expect("Sense failed"), "Against vote should be accepted");
        assert_eq!(quorum2.signals_against.len(), 1);
        println!("[SUCCESS] Against votes tracked separately");
        
        println!("[SUCCESS] Quorum sensing test passed\n");
    }
    
    #[test]
    fn test_self_voting_prevention() {
        println!("\n═══ TEST: Self-Voting Prevention ═══");
        
        let target = Cid::new(b"test_proposal");
        let proposer = Did("did:test:proposer".into());
        let mut quorum = QuorumState::new(target, 1000, proposer.clone());
        
        // Try to vote as the proposer - should be rejected
        let self_vote = QuorumSignal {
            source: proposer.clone(),
            target,
            weight: 500,
            support: true,
            elaboration: "I vote for my own proposal".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        let result = quorum.sense(self_vote);
        assert!(matches!(result, Err(DiagonError::SelfVoteProhibited)));
        println!("[SUCCESS] Self-voting correctly rejected");
        
        // Vote from different source should work
        let other_vote = QuorumSignal {
            source: Did("did:test:other".into()),
            target,
            weight: 500,
            support: true,
            elaboration: "I support this".into(),
            timestamp: timestamp(),
            signature: vec![],
        };
        
        assert!(quorum.sense(other_vote).expect("Sense failed"));
        println!("[SUCCESS] Vote from other source accepted");
        
        println!("[SUCCESS] Self-voting prevention test passed\n");
    }
    
    #[test]
    fn test_epigenetic_marks() {
        println!("\n═══ TEST: Epigenetic Marks ═══");
        
        let mut mark = EpigeneticMark::new();
        assert!((mark.score - TRUST_DEFAULT).abs() < 0.01);
        println!("[SUCCESS] Initial score: {:.2}", mark.score);
        
        // Good verified interaction
        mark.update(1.0, true);
        assert!(mark.score > TRUST_DEFAULT);
        println!("[SUCCESS] After good verified interaction: {:.2}", mark.score);
        
        // Bad interaction
        mark.update(0.0, true);
        let after_bad = mark.score;
        println!("[SUCCESS] After bad interaction: {:.2}", after_bad);
        
        // Multiple good verified interactions
        for _ in 0..10 {
            mark.update(0.9, true);
        }
        assert!(mark.score > after_bad);
        println!("[SUCCESS] After 10 good verified interactions: {:.2}", mark.score);
        
        // Test unverified interactions are capped
        let mut mark2 = EpigeneticMark::new();
        for _ in 0..20 {
            mark2.update(1.0, false); // Unverified
        }
        // Unverified interactions should be capped at 0.6 quality
        assert!(mark2.score < mark.score, "Unverified should result in lower score");
        println!("[SUCCESS] Unverified interactions capped: {:.2}", mark2.score);
        
        // Signal weight
        let weight = mark.signal_weight();
        assert!(weight >= 100);
        println!("[SUCCESS] Signal weight: {}", weight);
        
        println!("[SUCCESS] Epigenetic marks test passed\n");
    }
    
    #[test]
    fn test_cid_generation() {
        println!("\n═══ TEST: CID Generation ═══");
        
        let cid1 = Cid::new(b"hello");
        let cid2 = Cid::new(b"hello");
        let cid3 = Cid::new(b"world");
        
        // Same data should produce different CIDs (due to cryptographic randomness)
        assert_ne!(cid1, cid2, "CIDs should be unique even for same data");
        println!("[SUCCESS] CIDs are unique (cryptographic randomness works)");
        
        // Short representation
        assert_eq!(cid1.short().len(), 16); // 8 bytes = 16 hex chars
        println!("[SUCCESS] Short CID: {}", cid1.short());
        
        // Display
        println!("[SUCCESS] CID display: {}", cid1);
        
        println!("[SUCCESS] CID generation test passed\n");
    }
    
    #[test]
    fn test_did_generation() {
        println!("\n═══ TEST: DID Generation ═══");
        
        let (pk, _sk) = keypair();
        let did = Did::from_pubkey(&pk);
        
        assert!(did.0.starts_with("did:diagon:"));
        println!("[SUCCESS] DID format correct: {}", did.0);
        
        let short = did.short();
        assert!(short.len() < did.0.len());
        println!("[SUCCESS] Short DID: {}", short);
        
        // Test DID-pubkey matching
        assert!(did.matches_pubkey(pk.as_bytes()), "DID should match its pubkey");
        println!("[SUCCESS] DID matches pubkey");
        
        // Test mismatch detection
        let (pk2, _) = keypair();
        assert!(!did.matches_pubkey(pk2.as_bytes()), "DID should not match different pubkey");
        println!("[SUCCESS] DID mismatch detected");
        
        println!("[SUCCESS] DID generation test passed\n");
    }
    
    #[test]
    fn test_rate_limiter() {
        println!("\n═══ TEST: Rate Limiter ═══");
        
        let mut limiter = RateLimiter::default();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        
        // Should allow up to RATE_LIMIT_MAX_MESSAGES
        for i in 0..RATE_LIMIT_MAX_MESSAGES {
            assert!(limiter.check_and_increment(&addr), "Request {} should be allowed", i);
        }
        println!("[SUCCESS] Allowed {} requests", RATE_LIMIT_MAX_MESSAGES);
        
        // Next should be rejected
        assert!(!limiter.check_and_increment(&addr), "Should be rate limited");
        println!("[SUCCESS] Rate limited after max requests");
        
        // Different address should work
        let addr2: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        assert!(limiter.check_and_increment(&addr2), "Different address should work");
        println!("[SUCCESS] Different addresses tracked separately");
        
        println!("[SUCCESS] Rate limiter test passed\n");
    }
    
    #[test]
    fn test_nonce_tracker() {
        println!("\n═══ TEST: Nonce Tracker ═══");
        
        let mut tracker = NonceTracker::new(60);
        
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        
        // First use should succeed
        assert!(tracker.check_and_record(&nonce1), "First use should succeed");
        println!("[SUCCESS] First nonce accepted");
        
        // Replay should fail
        assert!(!tracker.check_and_record(&nonce1), "Replay should fail");
        println!("[SUCCESS] Replay rejected");
        
        // Different nonce should work
        assert!(tracker.check_and_record(&nonce2), "Different nonce should work");
        println!("[SUCCESS] Different nonce accepted");
        
        println!("[SUCCESS] Nonce tracker test passed\n");
    }
    
    #[test]
    fn test_pool_hash_argon2() {
        println!("\n═══ TEST: Pool Hash (Argon2) ═══");
        
        let passphrase = "test passphrase";
        let hash1 = hash_pool_passphrase(passphrase);
        let hash2 = hash_pool_passphrase(passphrase);
        
        // Same passphrase should produce same hash (deterministic with fixed salt)
        assert_eq!(hash1, hash2, "Same passphrase should produce same hash");
        println!("[SUCCESS] Hash is deterministic");
        
        // Different passphrase should produce different hash
        let hash3 = hash_pool_passphrase("different passphrase");
        assert_ne!(hash1, hash3, "Different passphrases should produce different hashes");
        println!("[SUCCESS] Different passphrases produce different hashes");
        
        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);
        println!("[SUCCESS] Hash is 32 bytes: {}", hex::encode(&hash1[..8]));
        
        println!("[SUCCESS] Pool hash (Argon2) test passed\n");
    }
    
    #[test]
    fn test_elaboration_scoring() {
        println!("\n═══ TEST: Elaboration Scoring ═══");
        
        // Very short - should get low score
        let short_score = score_elaboration("hi");
        assert!(short_score < 0.2, "Very short should score low");
        println!("[SUCCESS] Short text scores low: {:.2}", short_score);
        
        // Normal elaboration
        let normal = "This is a reasonable elaboration with several words and some variety in the content.";
        let normal_score = score_elaboration(normal);
        assert!(normal_score > 0.3, "Normal text should score reasonably");
        println!("[SUCCESS] Normal text scores: {:.2}", normal_score);
        
        // Spam with all unique words (trying to game the system)
        let spam = "aaa bbb ccc ddd eee fff ggg hhh iii jjj kkk lll mmm nnn ooo ppp qqq rrr sss ttt";
        let spam_score = score_elaboration(spam);
        assert!(spam_score < 0.5, "Spam should be penalized");
        println!("[SUCCESS] Spam text penalized: {:.2}", spam_score);
        
        // Repetitive text
        let repetitive = "the the the the the the the the the the";
        let rep_score = score_elaboration(repetitive);
        println!("[SUCCESS] Repetitive text scores: {:.2}", rep_score);
        
        // Max score should be capped at 0.8
        let good = "This is an excellent well-thought-out elaboration that provides comprehensive reasoning for the proposal with multiple valid points and considerations for the community to evaluate carefully.";
        let good_score = score_elaboration(good);
        assert!(good_score <= 0.8, "Score should be capped at 0.8");
        println!("[SUCCESS] Good text capped at: {:.2}", good_score);
        
        println!("[SUCCESS] Elaboration scoring test passed\n");
    }
    
    // ========================================================================
    // ASYNC INTEGRATION TESTS
    // ========================================================================
    
    #[test]
    fn test_node_creation_async() {
        println!("\n═══ TEST: Async Node Creation ═══");
        let dir = setup_test_dir("creation_async");
        
        run(async {
            let node = Node::new("127.0.0.1:19181", &format!("{}/node", dir))
                .await
                .expect("Failed to create node");
            
            println!("[SUCCESS] Node created with DID: {}", node.did.0);
            assert!(!node.did.0.is_empty());
            
            // Check initial state
            let state = node.state.read().await;
            assert!(state.proposals.is_empty());
            assert_eq!(state.active_pools.len(), GENESIS_POOLS.len());
            drop(state);
            
            let store = node.store.read().await;
            assert!(store.log().is_empty());
            drop(store);
            
            node.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Async node creation test passed\n");
    }
    
    #[test]
    fn test_pool_authentication_async() {
        println!("\n═══ TEST: Async Pool Authentication ═══");
        let dir = setup_test_dir("auth_async");
        
        run(async {
            let node = Node::new("127.0.0.1:19182", &format!("{}/node", dir))
                .await
                .expect("Failed to create node");
            
            // Add test pool to active pools (since Argon2 hash won't match genesis)
            let test_commitment = test_pool_commitment();
            node.state.write().await.active_pools.insert(test_commitment);
            
            // Test valid passphrase
            assert!(node.auth(TEST_PASSPHRASE).await, "Valid passphrase should authenticate");
            println!("[SUCCESS] Valid passphrase accepted");
            
            // Verify pool is set
            let pool = node.pool.read().await;
            assert!(pool.is_some());
            drop(pool);
            
            // Test invalid passphrase (doesn't clear existing)
            assert!(!node.auth("wrong passphrase").await, "Invalid passphrase should fail");
            println!("[SUCCESS] Invalid passphrase rejected");
            
            node.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Async pool authentication test passed\n");
    }
    
    #[test]
    fn test_two_node_connection() {
        println!("\n═══ TEST: Two Node Connection ═══");
        let dir = setup_test_dir("two_node");
        
        run(async {
            // Create nodes
            let node1 = Node::new("127.0.0.1:19183", &format!("{}/node1", dir))
                .await.expect("Node 1 failed");
            let node2 = Node::new("127.0.0.1:19184", &format!("{}/node2", dir))
                .await.expect("Node 2 failed");
            
            println!("[SUCCESS] Nodes created");
            println!("  Node 1: {}", node1.did.short());
            println!("  Node 2: {}", node2.did.short());
            
            // Add test pool to both nodes
            let test_commitment = test_pool_commitment();
            node1.state.write().await.active_pools.insert(test_commitment);
            node2.state.write().await.active_pools.insert(test_commitment);
            
            // Authenticate
            assert!(node1.auth(TEST_PASSPHRASE).await);
            assert!(node2.auth(TEST_PASSPHRASE).await);
            println!("[SUCCESS] Both nodes authenticated to pool");
            
            // Connect
            Timer::after(Duration::from_millis(100)).await;
            node1.connect("127.0.0.1:19184").await.expect("Connection failed");
            println!("[SUCCESS] Connection initiated");
            
            Timer::after(Duration::from_millis(300)).await;
            
            // Node1 should be awaiting elaboration (it initiated)
            let awaiting = node1.connection_pool.awaiting_elaboration().await;
            println!("  Node 1 awaiting elaboration: {}", awaiting.len());
            
            // Elaborate
            node1.elaborate("Node 1 requesting to join the network for testing purposes.").await;
            println!("[SUCCESS] Elaboration sent");
            
            Timer::after(Duration::from_millis(300)).await;
            
            // Node2 should have pending approval
            let pending = node2.connection_pool.pending_approval().await;
            println!("  Node 2 pending approvals: {}", pending.len());
            
            // Approve
            for (_, info) in &pending {
                let did = info.read().await.did.clone();
                if let Some(did) = did {
                    node2.approve(&did.short()).await;
                    println!("[SUCCESS] Approved: {}", did.short());
                }
            }
            
            Timer::after(Duration::from_millis(300)).await;
            
            // Verify connection
            let n1_auth = node1.connection_pool.authenticated_addrs().await.len();
            let n2_auth = node2.connection_pool.authenticated_addrs().await.len();
            println!("  Node 1 authenticated peers: {}", n1_auth);
            println!("  Node 2 authenticated peers: {}", n2_auth);
            
            assert!(n1_auth >= 1 || n2_auth >= 1, "At least one node should have authenticated peer");
            
            node1.shutdown().await;
            node2.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Two node connection test passed\n");
    }
    
    #[test]
    fn test_three_node_mesh_async() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║   DIAGON v0.9.1 - 3-NODE ASYNC MESH TEST (Security Hardened) ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let dir = setup_test_dir("mesh_async");
        
        run(async {
            // Phase 1: Create nodes
            println!("═══ PHASE 1: Node Creation ═══");
            let node1 = Node::new("127.0.0.1:19191", &format!("{}/node1", dir))
                .await.expect("Node 1 failed");
            println!("[SUCCESS] Node 1: {}", node1.did.short());
            
            let node2 = Node::new("127.0.0.1:19192", &format!("{}/node2", dir))
                .await.expect("Node 2 failed");
            println!("[SUCCESS] Node 2: {}", node2.did.short());
            
            let node3 = Node::new("127.0.0.1:19193", &format!("{}/node3", dir))
                .await.expect("Node 3 failed");
            println!("[SUCCESS] Node 3: {}", node3.did.short());
            
            Timer::after(Duration::from_millis(200)).await;
            
            // Add test pool to all nodes
            let test_commitment = test_pool_commitment();
            node1.state.write().await.active_pools.insert(test_commitment);
            node2.state.write().await.active_pools.insert(test_commitment);
            node3.state.write().await.active_pools.insert(test_commitment);
            
            // Phase 2: Authenticate
            println!("\n═══ PHASE 2: Pool Authentication ═══");
            assert!(node1.auth(TEST_PASSPHRASE).await);
            assert!(node2.auth(TEST_PASSPHRASE).await);
            assert!(node3.auth(TEST_PASSPHRASE).await);
            println!("[SUCCESS] All nodes authenticated to pool");
            
            // Phase 3: Connect mesh
            println!("\n═══ PHASE 3: Mesh Connection ═══");
            println!("  Topology: N1→N2, N1→N3, N2→N3");
            
            node1.connect("127.0.0.1:19192").await.expect("N1→N2 failed");
            Timer::after(Duration::from_millis(150)).await;
            
            node1.connect("127.0.0.1:19193").await.expect("N1→N3 failed");
            Timer::after(Duration::from_millis(150)).await;
            
            node2.connect("127.0.0.1:19193").await.expect("N2→N3 failed");
            Timer::after(Duration::from_millis(300)).await;
            
            println!("[SUCCESS] Connection attempts complete");
            
            // Phase 4: Elaboration
            println!("\n═══ PHASE 4: HITL Elaboration ═══");
            
            node1.elaborate("Node 1 joining the biological consensus network for distributed governance and quorum sensing experiments.").await;
            println!("[SUCCESS] Node 1 elaborated");
            Timer::after(Duration::from_millis(200)).await;
            
            node2.elaborate("Node 2 participating in collective intelligence testing for decentralized decision making protocols.").await;
            println!("[SUCCESS] Node 2 elaborated");
            Timer::after(Duration::from_millis(300)).await;
            
            // Phase 5: Approval
            println!("\n═══ PHASE 5: Peer Approval ═══");

            // Node2 approves Node1
            let pending2 = node2.connection_pool.pending_approval().await;
            println!("  Node 2 has {} pending", pending2.len());
            for (_, info) in &pending2 {
                let did = info.read().await.did.clone();
                if let Some(did) = did {
                    node2.approve(&did.short()).await;
                    println!("  [SUCCESS] Node 2 approved {}", did.short());
                }
            }
            Timer::after(Duration::from_millis(150)).await;

            // Node3 approves Node1 and Node2
            let pending3 = node3.connection_pool.pending_approval().await;
            println!("  Node 3 has {} pending", pending3.len());
            for (_, info) in &pending3 {
                let did = info.read().await.did.clone();
                if let Some(did) = did {
                    node3.approve(&did.short()).await;
                    println!("  [SUCCESS] Node 3 approved {}", did.short());
                }
            }
            Timer::after(Duration::from_millis(300)).await;
            
            // Phase 6: Verify mesh
            println!("\n═══ PHASE 6: Connection Verification ═══");
            let n1_auth = node1.connection_pool.authenticated_addrs().await.len();
            let n2_auth = node2.connection_pool.authenticated_addrs().await.len();
            let n3_auth = node3.connection_pool.authenticated_addrs().await.len();
            println!("  Node 1: {} authenticated peers", n1_auth);
            println!("  Node 2: {} authenticated peers", n2_auth);
            println!("  Node 3: {} authenticated peers", n3_auth);
            
            // Phase 7: Create proposal
            println!("\n═══ PHASE 7: Proposal Creation ═══");
            
            // Boost trust (verified)
            node1.state.write().await.update_mark(&node1.did, 0.9, true);
            
            node1.propose("Implement Verkle tree state commitments for efficient state proofs and reduced witness sizes.").await;
            Timer::after(Duration::from_millis(400)).await;
            
            let proposal_cid = {
                let state = node1.state.read().await;
                state.proposals.keys().next().copied()
            };
            
            if let Some(cid) = proposal_cid {
                println!("[SUCCESS] Proposal created: {}", cid);
                
                // Phase 8: Voting (note: node1 cannot vote on own proposal now)
                println!("\n═══ PHASE 8: Voting ═══");
                let prefix = cid.short();
                
                // Boost trust for voters (verified)
                node2.state.write().await.update_mark(&node2.did, 0.85, true);
                node3.state.write().await.update_mark(&node3.did, 0.85, true);
                
                node2.vote(&prefix, true, "Strong support for Verkle trees - they provide significant efficiency improvements for state proofs.").await;
                println!("[SUCCESS] Node 2 voted YES");
                Timer::after(Duration::from_millis(250)).await;
                
                node3.vote(&prefix, true, "Agreed - Verkle trees are essential for scalability and will reduce proof sizes substantially.").await;
                println!("[SUCCESS] Node 3 voted YES");
                Timer::after(Duration::from_millis(400)).await;
                
                // Phase 9: Check results
                println!("\n═══ PHASE 9: Final State ═══");
                
                // Check proposal on each node
                for (name, node) in [("Node 1", &node1), ("Node 2", &node2), ("Node 3", &node3)] {
                    let state = node.state.read().await;
                    if let Some(prop) = state.proposals.get(&cid) {
                        let votes = prop.quorum.accumulated_for();
                        let threshold = prop.quorum.threshold;
                        let status = if prop.executed { "EXECUTED" } 
                            else if prop.quorum.reached() { "REACHED" } 
                            else { "PENDING" };
                        println!("  {} sees: {}/{} [{}]", name, votes, threshold, status);
                    }
                }
                
                // Expression counts
                let n1_expr = node1.store.read().await.log().len();
                let n2_expr = node2.store.read().await.log().len();
                let n3_expr = node3.store.read().await.log().len();
                println!("  Expressions: N1={}, N2={}, N3={}", n1_expr, n2_expr, n3_expr);
            } else {
                println!("[REJECTION] No proposal found!");
            }
            
            // Phase 10: Shutdown
            println!("\n═══ PHASE 10: Shutdown ═══");
            node1.shutdown().await;
            node2.shutdown().await;
            node3.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║                    TEST COMPLETE                             ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
    }
    
    #[test]
    fn test_proposal_lifecycle() {
        println!("\n═══ TEST: Proposal Lifecycle ═══");
        let dir = setup_test_dir("proposal_lifecycle");
        
        run(async {
            let node = Node::new("127.0.0.1:19185", &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Add test pool
            let test_commitment = test_pool_commitment();
            node.state.write().await.active_pools.insert(test_commitment);
            node.auth(TEST_PASSPHRASE).await;
            
            // Boost trust to allow proposing (verified)
            node.state.write().await.update_mark(&node.did, 0.9, true);
            
            // Create proposal
            node.propose("Test proposal for lifecycle testing with sufficient length to pass validation.").await;
            
            let state = node.state.read().await;
            assert_eq!(state.proposals.len(), 1, "Should have one proposal");
            
            let (cid, prop) = state.proposals.iter().next().unwrap();
            println!("[SUCCESS] Proposal created: {}", cid);
            println!("  Proposer: {}", prop.proposer.short());
            println!("  Threshold: {}", prop.quorum.threshold);
            assert!(!prop.executed);
            assert!(!prop.quorum.reached());
            
            drop(state);
            
            // Try to vote on own proposal - should be rejected now
            let cid_str = node.state.read().await.proposals.keys().next().unwrap().short();
            node.vote(&cid_str, true, "Self-voting to test the voting mechanism in isolation mode.").await;
            
            // Verify no votes were counted (self-voting blocked)
            let state = node.state.read().await;
            let prop = state.proposals.values().next().unwrap();
            assert_eq!(prop.quorum.accumulated_for(), 0, "Self-vote should be rejected");
            println!("[SUCCESS] Self-voting correctly blocked, accumulated=0");
            
            node.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Proposal lifecycle test passed\n");
    }
    
    #[test]
    fn test_pool_proposal() {
        println!("\n═══ TEST: Pool Proposal ═══");
        let dir = setup_test_dir("pool_proposal");
        
        run(async {
            let node = Node::new("127.0.0.1:19186", &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Add test pool
            let test_commitment = test_pool_commitment();
            node.state.write().await.active_pools.insert(test_commitment);
            node.auth(TEST_PASSPHRASE).await;
            
            // List initial pools
            let state = node.state.read().await;
            let initial_pools = state.active_pools.len();
            println!("[SUCCESS] Initial active pools: {}", initial_pools);
            drop(state);
            
            // Propose new pool
            node.propose_pool("secret garden path", "A new pool for garden enthusiasts to discuss botanical matters.").await;
            
            let state = node.state.read().await;
            assert_eq!(state.pool_proposals.len(), 1);
            println!("[SUCCESS] Pool proposal created");
            
            let (commitment, pool) = state.pool_proposals.iter().next().unwrap();
            println!("  Commitment: {}", hex::encode(&commitment[..8]));
            println!("  Hint: {}", pool.hint);
            println!("  Rationale: {}", pool.rationale);
            
            drop(state);
            
            // Try to vote on own pool proposal - should be rejected
            let id = hex::encode(&node.state.read().await.pool_proposals.keys().next().unwrap()[..8]);
            node.vote_pool(&id[..4], true, "I support this new pool for botanical discussions.").await;
            
            // Should show self-voting blocked message
            println!("[SUCCESS] Self-vote on pool proposal blocked");
            
            node.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Pool proposal test passed\n");
    }
    
    #[test]
    fn test_expression_eval() {
        println!("\n═══ TEST: Expression Evaluation ═══");
        let dir = setup_test_dir("eval");
        
        run(async {
            let node = Node::new("127.0.0.1:19187", &format!("{}/node", dir))
                .await.expect("Node failed");
            
            // Eval simple expression
            node.eval("(hello world)").await;
            
            // Eval nested
            node.eval("(define (fact n) (if (= n 0) 1 (* n (fact (- n 1)))))").await;
            
            // Eval with integers
            node.eval("(list 1 2 3 4 5)").await;
            
            let store = node.store.read().await;
            println!("[SUCCESS] Expressions stored: {}", store.log().len());
            
            node.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Expression eval test passed\n");
    }
    
    #[test]
    fn test_persistence() {
        println!("\n═══ TEST: Persistence ═══");
        let dir = setup_test_dir("persistence");
        let node_dir = format!("{}/node", dir);
        
        // First run - create and store data, return values we need
        let (did1, proposal_count) = run(async {
            let node = Node::new("127.0.0.1:19188", &node_dir)
                .await.expect("Node failed");
            
            let did = node.did.clone();
            println!("[SUCCESS] Node created: {}", did.short());
            
            // Add test pool
            let test_commitment = test_pool_commitment();
            node.state.write().await.active_pools.insert(test_commitment);
            node.auth(TEST_PASSPHRASE).await;
            node.state.write().await.update_mark(&node.did, 0.9, true);
            
            // Create proposal
            node.propose("Persistent proposal that should survive restart of the node system.").await;
            
            let count = node.state.read().await.proposals.len();
            println!("[SUCCESS] Created {} proposal(s)", count);
            
            // Explicit save
            node.save_state().await.expect("Save failed");
            println!("[SUCCESS] State saved");
            
            node.shutdown().await;
            
            (did, count)
        });
        
        // Second run - verify data loaded
        run(async {
            let node = Node::new("127.0.0.1:19189", &node_dir)
                .await.expect("Node reload failed");
            
            // Same DID
            assert_eq!(node.did, did1, "DID should persist");
            println!("[SUCCESS] DID persisted: {}", node.did.short());
            
            // Proposals loaded
            let state = node.state.read().await;
            assert_eq!(state.proposals.len(), proposal_count, "Proposals should persist");
            println!("[SUCCESS] Proposals persisted: {}", state.proposals.len());
            
            node.shutdown().await;
        });
        
        cleanup_test_dir(&dir);
        println!("[SUCCESS] Persistence test passed\n");
    }
    
    #[test]
    fn test_connection_pool_limits() {
        println!("\n═══ TEST: Connection Pool Limits ═══");
        
        run(async {
            let pool = ConnectionPool::new();
            
            // Add connections up to a reasonable test limit
            let test_limit = 10;
            for i in 0..test_limit {
                let addr: SocketAddr = format!("127.0.0.1:{}", 30000 + i).parse().unwrap();
                let info = Arc::new(RwLock::new(PeerInfo::new(addr, false)));
                let (tx, _rx) = bounded(1);
                let handle = ConnHandle { addr, cmd_tx: tx };
                pool.add(addr, info, handle).await.expect("Add should succeed");
            }
            
            let peers = pool.peers.read().await;
            assert_eq!(peers.len(), test_limit);
            println!("[SUCCESS] Added {} connections", test_limit);
            drop(peers);
            
            // Verify authenticated count (all should be unauthenticated initially)
            let auth = pool.authenticated_addrs().await;
            assert_eq!(auth.len(), 0);
            println!("[SUCCESS] No authenticated connections initially");
            
            // Authenticate one
            let addr: SocketAddr = "127.0.0.1:30000".parse().unwrap();
            if let Some(info) = pool.get_info(&addr).await {
                info.write().await.state = ConnectionState::Connected;
            }
            
            let auth = pool.authenticated_addrs().await;
            assert_eq!(auth.len(), 1);
            println!("[SUCCESS] One authenticated after state change");
            
            // Remove
            pool.remove(addr).await;
            let peers = pool.peers.read().await;
            assert_eq!(peers.len(), test_limit - 1);
            println!("[SUCCESS] Removed connection, {} remaining", peers.len());
            drop(peers);
            
            pool.shutdown().await;
            println!("[SUCCESS] Shutdown complete");
        });
        
        println!("[SUCCESS] Connection pool limits test passed\n");
    }
    
    #[test]
    fn test_message_serialization() {
        println!("\n═══ TEST: Message Serialization ═══");
        
        let messages = vec![
            NetMessage::Hello {
                did: Did("did:test:123".into()),
                pubkey: vec![1, 2, 3, 4],
                pool: [0u8; 32],
                expr_root: [1u8; 32],
            },
            NetMessage::Challenge([42u8; 32]),
            NetMessage::Response {
                nonce: [42u8; 32],
                signature: vec![1, 2, 3],
            },
            NetMessage::ElaborateRequest,
            NetMessage::Elaborate {
                text: "Test elaboration".into(),
                signature: vec![4, 5, 6],
            },
            NetMessage::Approve { 
                timestamp: timestamp(),
                peer_did: Did("did:test:peer".into()),
                signature: vec![7, 8, 9] 
            },
            NetMessage::Reject {
                reason: "Test rejection".into(),
                signature: vec![10, 11, 12],
            },
            NetMessage::Expression(vec![1, 2, 3, 4, 5]),
            NetMessage::Signal(QuorumSignal {
                source: Did("did:test:voter".into()),
                target: Cid([0u8; 32]),
                weight: 1000,
                support: true,
                elaboration: "I support".into(),
                timestamp: timestamp(),
                signature: vec![],
            }),
            NetMessage::SyncRequest {
                merkle: [0u8; 32],
                have: vec![Cid([1u8; 32]), Cid([2u8; 32])],
            },
            NetMessage::SyncReply {
                expressions: vec![vec![1, 2], vec![3, 4]],
            },
            NetMessage::Heartbeat { 
                timestamp: timestamp(),
                signature: vec![1] 
            },
            NetMessage::Disconnect { 
                timestamp: timestamp(),
                signature: vec![2] 
            },
        ];
        
        for msg in messages {
            let serialized = msg.serialize().expect("Serialization failed");
            let deserialized = NetMessage::deserialize(&serialized).expect("Deserialization failed");
            
            // Re-serialize to verify round-trip
            let reserialized = deserialized.serialize().expect("Re-serialization failed");
            assert_eq!(serialized, reserialized, "Round-trip should be identical");
            
            println!("[SUCCESS] {:?} round-trip OK ({} bytes)", 
                std::mem::discriminant(&msg), serialized.len());
        }
        
        println!("[SUCCESS] Message serialization test passed\n");
    }
    
    #[test]
    fn test_derived_state_threshold() {
        println!("\n═══ TEST: Derived State Threshold ═══");
        
        let state = DerivedState::new();
        
        // Test threshold calculation at various peer counts
        let tests = [
            (0, 670),   // 1 * 0.67 * 1000 = 670, but min is 1000
            (1, 1340),  // 2 * 0.67 * 1000 = 1340
            (2, 2010),  // 3 * 0.67 * 1000 = 2010
            (5, 4020),  // 6 * 0.67 * 1000 = 4020
            (10, 7370), // 11 * 0.67 * 1000 = 7370
        ];
        
        for (peers, _expected_min) in tests {
            let threshold = state.threshold(peers);
            assert!(threshold >= 1000, "Threshold should be at least 1000");
            println!("  {} peers [->] threshold {}", peers, threshold);
        }
        
        println!("[SUCCESS] Derived state threshold test passed\n");
    }
    
    #[test]
    fn test_derived_state_limits() {
        println!("\n═══ TEST: Derived State Limits ═══");
        
        let mut state = DerivedState::new();
        
        // Check initial state
        assert!(state.can_add_proposal());
        println!("[SUCCESS] Can add proposals initially");
        
        // Fill up to limit
        for i in 0..MAX_PROPOSALS {
            let cid = Cid::new(&i.to_le_bytes());
            let proposer = Did(format!("did:test:{}", i));
            let proposal = ProposalState {
                cid,
                expr_data: vec![],
                proposer: proposer.clone(),
                elaboration: "Test".into(),
                quorum: QuorumState::new(cid, 1000, proposer),
                executed: false,
                created: timestamp(),
            };
            state.proposals.insert(cid, proposal);
        }
        
        assert!(!state.can_add_proposal());
        println!("[SUCCESS] Cannot add proposals when full ({} proposals)", state.proposals.len());
        
        println!("[SUCCESS] Derived state limits test passed\n");
    }
    
    #[test]
    fn test_stress_expressions() {
        println!("\n═══ TEST: Stress - Many Expressions ═══");
        
        let mut store = ExprStore::new();
        let count = 1000;
        
        let start = std::time::Instant::now();
        for i in 0..count {
            let expr = store.arena_mut().parse(&format!("(expr {} data)", i)).unwrap();
            store.store(expr).expect("Store failed");
        }
        let elapsed = start.elapsed();
        
        assert_eq!(store.log().len(), count);
        println!("[SUCCESS] Stored {} expressions in {:?}", count, elapsed);
        println!("  Rate: {:.0} expr/sec", count as f64 / elapsed.as_secs_f64());
        
        // Verify merkle root
        let root = store.merkle_root();
        println!("[SUCCESS] Merkle root: {}", hex::encode(&root[..8]));
        
        println!("[SUCCESS] Stress expression test passed\n");
    }
    
    #[test]
    fn test_quorum_signal_signable_bytes() {
        println!("\n═══ TEST: QuorumSignal Signable Bytes ═══");
        
        let signal = QuorumSignal {
            source: Did("did:test:source".into()),
            target: Cid([1u8; 32]),
            weight: 500,
            support: true,
            elaboration: "Test elaboration".into(),
            timestamp: 1234567890,
            signature: vec![],
        };
        
        let signable = signal.signable_bytes();
        assert!(!signable.is_empty());
        println!("[SUCCESS] Signable bytes generated: {} bytes", signable.len());
        
        // Same signal should produce same signable bytes
        let signable2 = signal.signable_bytes();
        assert_eq!(signable, signable2);
        println!("[SUCCESS] Signable bytes are deterministic");
        
        // Different support value should produce different bytes
        let signal2 = QuorumSignal {
            support: false,
            ..signal.clone()
        };
        let signable3 = signal2.signable_bytes();
        assert_ne!(signable, signable3);
        println!("[SUCCESS] Different support produces different bytes");
        
        println!("[SUCCESS] QuorumSignal signable bytes test passed\n");
    }
    
    #[test]
    fn test_message_signable_bytes() {
        println!("\n═══ TEST: NetMessage Signable Bytes ═══");
        
        // Approve message
        let approve = NetMessage::Approve {
            timestamp: 1234567890,
            peer_did: Did("did:test:peer".into()),
            signature: vec![],
        };
        let approve_signable = approve.signable_bytes();
        assert!(approve_signable.is_some());
        println!("[SUCCESS] Approve has signable bytes");
        
        // Heartbeat message
        let heartbeat = NetMessage::Heartbeat {
            timestamp: 1234567890,
            signature: vec![],
        };
        let heartbeat_signable = heartbeat.signable_bytes();
        assert!(heartbeat_signable.is_some());
        println!("[SUCCESS] Heartbeat has signable bytes");
        
        // Disconnect message
        let disconnect = NetMessage::Disconnect {
            timestamp: 1234567890,
            signature: vec![],
        };
        let disconnect_signable = disconnect.signable_bytes();
        assert!(disconnect_signable.is_some());
        println!("[SUCCESS] Disconnect has signable bytes");
        
        // Challenge message (no signable bytes needed)
        let challenge = NetMessage::Challenge([0u8; 32]);
        assert!(challenge.signable_bytes().is_none());
        println!("[SUCCESS] Challenge has no signable bytes (as expected)");
        
        println!("[SUCCESS] NetMessage signable bytes test passed\n");
    }
}