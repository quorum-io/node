use std::{
    collections::{HashMap, HashSet, BTreeMap, VecDeque},
    fs::File,
    io::{self, Read, Write, BufReader, BufWriter, ErrorKind},
    net::{TcpListener, TcpStream, SocketAddr, Shutdown},
    sync::{Arc, RwLock, Mutex, Weak, atomic::{AtomicBool, AtomicU64, Ordering}},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    fmt,
};

use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};

// ============================================================================
// BIOLOGICAL CONSTANTS
// ============================================================================

const EIGEN_THRESHOLD: f64 = 0.67;
const SIGNAL_HALF_LIFE: u64 = 300;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const PEER_TIMEOUT_SECS: u64 = 150;
const CHALLENGE_TIMEOUT_SECS: u64 = 30;
const MIN_ELABORATION_LEN: usize = 20;
const MAX_MESSAGE_SIZE: usize = 1_048_576;
const MAX_CONNECTIONS: usize = 100;
const CONNECTION_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RECONNECT_ATTEMPTS: u32 = 10;
const TRUST_DEFAULT: f64 = 0.5;
const TRUST_HISTORY_WEIGHT: f64 = 0.7;
const TRUST_NEW_WEIGHT: f64 = 0.3;
const TRUST_MIN_FOR_PROPOSE: f64 = 0.4;

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
        let nonce = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&nonce.to_le_bytes());
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
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.short()) }
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
}

impl ExprStore {
    pub fn new() -> Self { Self { expressions: HashMap::new(), log: Vec::new(), arena: Arena::new() } }
    
    pub fn store(&mut self, expr: SexpRef) -> (Cid, bool) {
        let (cid, canonical) = self.arena.intern(expr);
        let is_new = !self.expressions.contains_key(&cid);
        if is_new { self.expressions.insert(cid, canonical); self.log.push(cid); }
        (cid, is_new)
    }
    
    pub fn fetch(&self, cid: &Cid) -> Option<SexpRef> { self.expressions.get(cid).copied() }
    pub fn has(&self, cid: &Cid) -> bool { self.expressions.contains_key(cid) }
    pub fn log(&self) -> &[Cid] { &self.log }
    pub fn arena(&self) -> &Arena { &self.arena }
    pub fn arena_mut(&mut self) -> &mut Arena { &mut self.arena }
    pub fn serialize_expr(&self, cid: &Cid) -> Option<Vec<u8>> { self.expressions.get(cid).map(|&idx| self.arena.serialize(idx)) }
    
    pub fn deserialize_and_store(&mut self, data: &[u8]) -> Option<(Cid, bool)> {
        let expr = self.arena.deserialize(data)?;
        Some(self.store(expr))
    }
    
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for cid in &self.log { hasher.update(&cid.0); }
        hasher.finalize().into()
    }
}

impl Default for ExprStore { fn default() -> Self { Self::new() } }

// ============================================================================
// QUORUM SENSING
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumState {
    pub target: Cid,
    pub threshold: u64,
    pub signals_for: Vec<QuorumSignal>,
    pub signals_against: Vec<QuorumSignal>,
    pub sources_seen: HashSet<Did>,
    pub created: u64,
}

impl QuorumState {
    pub fn new(target: Cid, threshold: u64) -> Self {
        Self { target, threshold, signals_for: Vec::new(), signals_against: Vec::new(), sources_seen: HashSet::new(), created: timestamp() }
    }
    
    pub fn sense(&mut self, signal: QuorumSignal) -> bool {
        if self.sources_seen.contains(&signal.source) || signal.target != self.target { return false; }
        self.sources_seen.insert(signal.source.clone());
        if signal.support { self.signals_for.push(signal); } else { self.signals_against.push(signal); }
        true
    }
    
    pub fn accumulated_for(&self) -> u64 { self.signals_for.iter().map(|s| s.current_strength()).sum() }
    pub fn reached(&self) -> bool { self.accumulated_for() >= self.threshold }
}

// ============================================================================
// EPIGENETIC MARKS
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpigeneticMark {
    pub score: f64,
    pub interactions: u32,
    pub last_active: u64,
}

impl EpigeneticMark {
    pub fn new() -> Self { Self { score: TRUST_DEFAULT, interactions: 0, last_active: timestamp() } }
    
    pub fn update(&mut self, quality: f64) {
        self.score = self.score * TRUST_HISTORY_WEIGHT + quality * TRUST_NEW_WEIGHT;
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

// ============================================================================
// PROPOSAL STATE
// ============================================================================

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

// ============================================================================
// POOL STATE
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolState {
    pub commitment: [u8; 32],
    pub hint: String,
    pub rationale: String,
    pub proposer: Did,
    pub quorum: QuorumState,
    pub active: bool,
}

// 

const GENESIS_POOLS: [[u8; 32]; 3] = [
    [0x80, 0x1e, 0x10, 0x0b, 0x0c, 0xa3, 0x10, 0x30, 0xa6, 0xb2, 0x9f, 0x69, 0x2d, 0x0f, 0x19, 0x4c,
     0x33, 0x07, 0x0f, 0xeb, 0x59, 0x50, 0x66, 0x60, 0xad, 0x7b, 0x90, 0x81, 0x3e, 0x42, 0x7b, 0x8b], // QUANTUM LEAP BEYOND HORIZON
    [0x5d, 0x55, 0xb7, 0xcd, 0x42, 0xd2, 0x62, 0x9d, 0x3e, 0x5e, 0x91, 0xe0, 0xc5, 0xb5, 0xfb, 0xd5,
     0x1d, 0x4f, 0xd9, 0xb1, 0x8d, 0x30, 0x96, 0xec, 0xe5, 0x56, 0x68, 0x21, 0xc1, 0xd7, 0x8b, 0xf5], // TRUTH DECAYS WITHOUT WITNESSES
    [0x80, 0x1e, 0x10, 0x0b, 0x0c, 0xa3, 0x10, 0x30, 0xa6, 0xb2, 0x9f, 0x69, 0x2d, 0x0f, 0x19, 0x4c,
     0x33, 0x07, 0x0f, 0xeb, 0x59, 0x50, 0x66, 0x60, 0xad, 0x7b, 0x90, 0x81, 0x3e, 0x42, 0x7b, 0x8b], // DAYLIGHT FADES FROM DAWN
];

// ============================================================================
// DERIVED STATE
// ============================================================================

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
    pub fn update_mark(&mut self, did: &Did, quality: f64) { self.marks.entry(did.clone()).or_default().update(quality); }
}

// ============================================================================
// MESSAGE FRAMER
// ============================================================================

struct MessageFramer {
    len_buf: [u8; 4],
    msg_buffer: Vec<u8>,
    expected_len: usize,
}

impl MessageFramer {
    fn new() -> Self { Self { len_buf: [0u8; 4], msg_buffer: Vec::with_capacity(MAX_MESSAGE_SIZE), expected_len: 0 } }
    
    fn read_message(&mut self, stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
        if self.expected_len == 0 {
            match stream.read_exact(&mut self.len_buf) {
                Ok(_) => {
                    self.expected_len = u32::from_be_bytes(self.len_buf) as usize;
                    if self.expected_len > MAX_MESSAGE_SIZE { return Err(io::Error::new(ErrorKind::InvalidData, "Message too large")); }
                    self.msg_buffer.clear();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        if self.expected_len > 0 {
            let remaining = self.expected_len - self.msg_buffer.len();
            let mut temp = vec![0u8; remaining.min(8192)];
            match stream.read(&mut temp) {
                Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "Connection closed")),
                Ok(n) => {
                    self.msg_buffer.extend_from_slice(&temp[..n]);
                    if self.msg_buffer.len() >= self.expected_len {
                        let msg = self.msg_buffer.clone();
                        self.msg_buffer.clear();
                        self.expected_len = 0;
                        return Ok(Some(msg));
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
}

// ============================================================================
// TCP CONNECTION
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionState { Connecting, Authenticating, AwaitingElaboration, PendingApproval, Connected, Closing, Closed }

struct TcpConnection {
    stream: Arc<Mutex<TcpStream>>,
    addr: SocketAddr,
    did: Arc<RwLock<Option<Did>>>,
    pubkey: Arc<RwLock<Option<Vec<u8>>>>,
    state: Arc<RwLock<ConnectionState>>,
    elaboration: Arc<RwLock<Option<String>>>,
    last_activity: Arc<RwLock<Instant>>,
    seen_cids: Arc<RwLock<HashSet<Cid>>>,
    challenge_sent: Arc<RwLock<Option<[u8; 32]>>>,
    challenge_time: Arc<RwLock<Option<Instant>>>,
    initiated: bool,  // true = we initiated this connection, false = they connected to us
}

impl TcpConnection {
    fn new(stream: TcpStream, addr: SocketAddr, initiated: bool) -> Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)), addr,
            did: Arc::new(RwLock::new(None)), pubkey: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(ConnectionState::Connecting)),
            elaboration: Arc::new(RwLock::new(None)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            seen_cids: Arc::new(RwLock::new(HashSet::new())),
            challenge_sent: Arc::new(RwLock::new(None)),
            challenge_time: Arc::new(RwLock::new(None)),
            initiated,
        })
    }
    
    fn send(&self, data: &[u8]) -> Result<()> {
        let state = *self.state.read().unwrap();
        if state == ConnectionState::Closed || state == ConnectionState::Closing { return Err(DiagonError::ConnectionLost); }
        if data.len() > MAX_MESSAGE_SIZE { return Err(DiagonError::MessageTooLarge); }
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&(data.len() as u32).to_be_bytes())?;
        stream.write_all(data)?;
        stream.flush()?;
        *self.last_activity.write().unwrap() = Instant::now();
        Ok(())
    }
    
    fn mark_seen(&self, cid: &Cid) { self.seen_cids.write().unwrap().insert(*cid); }
    fn has_seen(&self, cid: &Cid) -> bool { self.seen_cids.read().unwrap().contains(cid) }
    fn is_alive(&self) -> bool {
        let state = *self.state.read().unwrap();
        let last = *self.last_activity.read().unwrap();
        state != ConnectionState::Closed && state != ConnectionState::Closing && last.elapsed() < Duration::from_secs(PEER_TIMEOUT_SECS)
    }
    fn is_authenticated(&self) -> bool { *self.state.read().unwrap() == ConnectionState::Connected }
    fn close(&self) {
        *self.state.write().unwrap() = ConnectionState::Closing;
        if let Ok(stream) = self.stream.lock() { let _ = stream.shutdown(Shutdown::Both); }
        *self.state.write().unwrap() = ConnectionState::Closed;
    }
}

// ============================================================================
// CONNECTION POOL
// ============================================================================

struct ConnectionPool {
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<TcpConnection>>>>,
    by_did: Arc<RwLock<HashMap<Did, Vec<SocketAddr>>>>,
    readers: Arc<Mutex<HashMap<SocketAddr, JoinHandle<()>>>>,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            by_did: Arc::new(RwLock::new(HashMap::new())),
            readers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    fn add(&self, addr: SocketAddr, conn: Arc<TcpConnection>) -> Result<()> {
        let mut conns = self.connections.write().unwrap();
        if conns.len() >= MAX_CONNECTIONS {
            if let Some(oldest) = conns.iter().filter(|(_, c)| !c.is_authenticated()).min_by_key(|(_, c)| *c.last_activity.read().unwrap()).map(|(a, _)| *a) {
                drop(conns); self.remove(oldest); conns = self.connections.write().unwrap();
            } else { return Err(DiagonError::PoolFull); }
        }
        conns.insert(addr, conn);
        Ok(())
    }
    
    fn add_reader(&self, addr: SocketAddr, handle: JoinHandle<()>) { self.readers.lock().unwrap().insert(addr, handle); }
    
    fn register_did(&self, addr: SocketAddr, did: &Did) {
        if let Some(conn) = self.connections.read().unwrap().get(&addr) {
            *conn.did.write().unwrap() = Some(did.clone());
            self.by_did.write().unwrap().entry(did.clone()).or_default().push(addr);
        }
    }
    
    fn get(&self, addr: &SocketAddr) -> Option<Arc<TcpConnection>> { self.connections.read().unwrap().get(addr).cloned() }
    
    fn remove(&self, addr: SocketAddr) {
        if let Some(conn) = self.connections.write().unwrap().remove(&addr) {
            if let Some(did) = conn.did.read().unwrap().as_ref() {
                let mut by_did = self.by_did.write().unwrap();
                if let Some(addrs) = by_did.get_mut(did) { addrs.retain(|a| *a != addr); if addrs.is_empty() { by_did.remove(did); } }
            }
            conn.close();
        }
        if let Some(h) = self.readers.lock().unwrap().remove(&addr) { thread::spawn(move || { let _ = h.join(); }); }
    }
    
    fn authenticated_addrs(&self) -> Vec<SocketAddr> {
        self.connections.read().unwrap().iter().filter(|(_, c)| c.is_authenticated()).map(|(a, _)| *a).collect()
    }
    
    fn pending_approval(&self) -> Vec<(SocketAddr, Arc<TcpConnection>)> {
        self.connections.read().unwrap().iter().filter(|(_, c)| *c.state.read().unwrap() == ConnectionState::PendingApproval).map(|(a, c)| (*a, c.clone())).collect()
    }
    
    fn awaiting_elaboration(&self) -> Vec<(SocketAddr, Arc<TcpConnection>)> {
        self.connections.read().unwrap().iter().filter(|(_, c)| *c.state.read().unwrap() == ConnectionState::AwaitingElaboration).map(|(a, c)| (*a, c.clone())).collect()
    }
    
    fn shutdown(&self) {
        let addrs: Vec<_> = self.connections.read().unwrap().keys().cloned().collect();
        for addr in addrs { self.remove(addr); }
        thread::sleep(Duration::from_millis(100));
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
    Approve { signature: Vec<u8> },
    Reject { reason: String, signature: Vec<u8> },
    Expression(Vec<u8>),
    Signal(QuorumSignal),
    SyncRequest { merkle: [u8; 32], have: Vec<Cid> },
    SyncReply { expressions: Vec<Vec<u8>> },
    Heartbeat { signature: Vec<u8> },
    Disconnect { signature: Vec<u8> },
}

impl NetMessage {
    fn serialize(&self) -> Result<Vec<u8>> { bincode::serialize(self).map_err(|e| DiagonError::Serialization(e.to_string())) }
    fn deserialize(data: &[u8]) -> Result<Self> { bincode::deserialize(data).map_err(|e| DiagonError::Serialization(e.to_string())) }
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
    nonce_counter: u64,
}

// ============================================================================
// NODE
// ============================================================================

pub struct Node {
    did: Did,
    secret_key: SecretKey,
    public_key: PublicKey,
    listener: Arc<RwLock<Option<TcpListener>>>,
    bind_addr: String,
    pool: Arc<RwLock<Option<[u8; 32]>>>,
    connection_pool: ConnectionPool,
    reconnect_queue: Arc<RwLock<VecDeque<(SocketAddr, Instant, u32)>>>,
    store: Arc<RwLock<ExprStore>>,
    state: Arc<RwLock<DerivedState>>,
    running: Arc<AtomicBool>,
    db_path: String,
    weak_self: Arc<Mutex<Option<Weak<Node>>>>,
}

impl Node {
    pub fn new(bind_addr: &str, db_path: &str) -> Result<Arc<Self>> {
        std::fs::create_dir_all(db_path).ok();
        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        
        let persistence_path = format!("{}/state.cbor", db_path);
        let (did, secret_key, public_key, store, state, nonce) = Self::load_or_create(&persistence_path)?;
        NONCE_COUNTER.store(nonce, Ordering::Relaxed);
        
        let node = Arc::new(Self {
            did: did.clone(), secret_key, public_key,
            listener: Arc::new(RwLock::new(Some(listener))),
            bind_addr: bind_addr.to_string(),
            pool: Arc::new(RwLock::new(None)),
            connection_pool: ConnectionPool::new(),
            reconnect_queue: Arc::new(RwLock::new(VecDeque::new())),
            store: Arc::new(RwLock::new(store)),
            state: Arc::new(RwLock::new(state)),
            running: Arc::new(AtomicBool::new(true)),
            db_path: db_path.to_string(),
            weak_self: Arc::new(Mutex::new(None)),
        });
        
        *node.weak_self.lock().unwrap() = Some(Arc::downgrade(&node));
        
        println!("🧬 DIAGON v0.9.0 - Biological Consensus Machine");
        println!("   \"Consensus on expressions, derivation of truth\"");
        println!();
        println!("🔑 DID: {}", did.0);
        println!("📡 Listening: {}", bind_addr);
        println!("🗄️  Database: {}", db_path);
        println!();
        
        let n = Arc::clone(&node); thread::spawn(move || Self::accept_loop(n));
        let n = Arc::clone(&node); thread::spawn(move || Self::heartbeat_loop(n));
        let n = Arc::clone(&node); thread::spawn(move || Self::sync_loop(n));
        let n = Arc::clone(&node); thread::spawn(move || Self::reconnect_loop(n));
        
        Ok(node)
    }
    
    fn load_or_create(path: &str) -> Result<(Did, SecretKey, PublicKey, ExprStore, DerivedState, u64)> {
        if let Ok(file) = File::open(path) {
            if let Ok(persisted) = serde_cbor::from_reader::<PersistedState, _>(BufReader::new(file)) {
                if let (Ok(pk), Ok(sk)) = (PublicKey::from_bytes(&persisted.identity.0), SecretKey::from_bytes(&persisted.identity.1)) {
                    let did = Did::from_pubkey(&pk);
                    if did == persisted.identity.2 {
                        let mut store = ExprStore::new();
                        for (_cid, data) in persisted.expressions { if let Some(expr) = store.arena_mut().deserialize(&data) { store.store(expr); } }
                        let mut state = DerivedState::new();
                        for (cid, prop) in persisted.proposals { state.proposals.insert(cid, prop); }
                        for (commitment, pool) in persisted.pool_proposals { state.pool_proposals.insert(commitment, pool); }
                        for pool in persisted.active_pools { state.active_pools.insert(pool); }
                        for (did, mark) in persisted.marks { state.marks.insert(did, mark); }
                        println!("📥 Loaded {} expressions, {} proposals", store.log().len(), state.proposals.len());
                        return Ok((did, sk, pk, store, state, persisted.nonce_counter));
                    }
                }
            }
        }
        let (public_key, secret_key) = keypair();
        let did = Did::from_pubkey(&public_key);
        Ok((did, secret_key, public_key, ExprStore::new(), DerivedState::new(), 0))
    }
    
    fn save_state(&self) -> Result<()> {
        let store = self.store.read().unwrap();
        let state = self.state.read().unwrap();
        let expressions: Vec<_> = store.log().iter().filter_map(|cid| store.serialize_expr(cid).map(|data| (*cid, data))).collect();
        let persisted = PersistedState {
            identity: (self.public_key.as_bytes().to_vec(), self.secret_key.as_bytes().to_vec(), self.did.clone()),
            expressions,
            proposals: state.proposals.iter().map(|(k, v)| (*k, v.clone())).collect(),
            pool_proposals: state.pool_proposals.iter().map(|(k, v)| (*k, v.clone())).collect(),
            active_pools: state.active_pools.iter().cloned().collect(),
            marks: state.marks.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            nonce_counter: NONCE_COUNTER.load(Ordering::Relaxed),
        };
        let temp = format!("{}/state.cbor.tmp", self.db_path);
        let path = format!("{}/state.cbor", self.db_path);
        serde_cbor::to_writer(BufWriter::new(File::create(&temp)?), &persisted).map_err(|e| DiagonError::Serialization(e.to_string()))?;
        std::fs::rename(temp, path)?;
        Ok(())
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> { detached_sign(data, &self.secret_key).as_bytes().to_vec() }
    
    fn verify(&self, data: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<()> {
        let pk = PublicKey::from_bytes(pubkey).map_err(|_| DiagonError::Crypto("Invalid public key".into()))?;
        let sig = DetachedSignature::from_bytes(signature).map_err(|_| DiagonError::Crypto("Invalid signature".into()))?;
        verify_detached_signature(&sig, data, &pk).map_err(|_| DiagonError::Crypto("Verification failed".into()))
    }
    
    pub fn auth(&self, passphrase: &str) -> bool {
        let commitment = sha256(passphrase.as_bytes());
        if self.state.read().unwrap().active_pools.contains(&commitment) {
            *self.pool.write().unwrap() = Some(commitment);
            println!("✔ Pool authenticated: {}", hex::encode(&commitment[..8]));
            true
        } else {
            println!("✗ Unknown pool. Commitment: {}", hex::encode(&commitment[..8]));
            false
        }
    }
    
    pub fn connect(&self, addr_str: &str) -> Result<()> {
        let pool = self.pool.read().unwrap().ok_or_else(|| DiagonError::Validation("Set pool first with 'auth'".into()))?;
        let addr: SocketAddr = addr_str.parse().map_err(|_| DiagonError::Validation("Invalid address".into()))?;
        if self.connection_pool.get(&addr).is_some() { println!("Already connected to {}", addr); return Ok(()); }
        
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(stream) => {
                let conn = Arc::new(TcpConnection::new(stream, addr, true)?);  // we initiated
                *conn.state.write().unwrap() = ConnectionState::Authenticating;
                let store = self.store.read().unwrap();
                let msg = NetMessage::Hello { did: self.did.clone(), pubkey: self.public_key.as_bytes().to_vec(), pool, expr_root: store.merkle_root() };
                conn.send(&msg.serialize()?)?;
                self.connection_pool.add(addr, Arc::clone(&conn))?;
                let node_weak = self.weak_self.lock().unwrap().clone().unwrap();
                let handle = thread::spawn(move || Self::reader_loop(node_weak, conn, addr));
                self.connection_pool.add_reader(addr, handle);
                println!("→ Connecting to {}", addr);
                Ok(())
            }
            Err(e) => { self.reconnect_queue.write().unwrap().push_back((addr, Instant::now(), 0)); Err(DiagonError::Io(e)) }
        }
    }
    
    pub fn elaborate(&self, text: &str) {
        if text.len() < MIN_ELABORATION_LEN { println!("✗ Elaboration too short (min {} chars)", MIN_ELABORATION_LEN); return; }
        let awaiting = self.connection_pool.awaiting_elaboration();
        if awaiting.is_empty() { println!("No peers awaiting elaboration"); return; }
        let sig = self.sign(text.as_bytes());
        let msg = NetMessage::Elaborate { text: text.to_string(), signature: sig };
        let data = match msg.serialize() { Ok(d) => d, Err(_) => return };
        for (addr, conn) in awaiting {
            if conn.send(&data).is_ok() {
                *conn.elaboration.write().unwrap() = Some(text.to_string());
                *conn.state.write().unwrap() = ConnectionState::PendingApproval;
                println!("→ Elaboration sent to {}", addr);
            }
        }
    }
    
    pub fn approve(&self, id: &str) {
        for (addr, conn) in self.connection_pool.pending_approval() {
            let did_match = conn.did.read().unwrap().as_ref().map(|d| d.short().contains(id) || d.0.contains(id)).unwrap_or(false);
            let addr_match = addr.to_string().contains(id);
            if did_match || addr_match {
                let sig = self.sign(b"approve");
                if let Ok(data) = (NetMessage::Approve { signature: sig }).serialize() {
                    if conn.send(&data).is_ok() {
                        *conn.state.write().unwrap() = ConnectionState::Connected;
                        if let Some(did) = conn.did.read().unwrap().as_ref() {
                            println!("✓ Peer {} approved", did.short());
                            if let Some(elab) = conn.elaboration.read().unwrap().as_ref() {
                                self.state.write().unwrap().update_mark(did, score_elaboration(elab));
                            }
                        }
                        return;
                    }
                }
            }
        }
        println!("Peer not found or not pending approval");
    }
    
    pub fn reject(&self, id: &str, reason: &str) {
        for (addr, conn) in self.connection_pool.pending_approval() {
            let did_match = conn.did.read().unwrap().as_ref().map(|d| d.short().contains(id)).unwrap_or(false);
            if did_match || addr.to_string().contains(id) {
                let sig = self.sign(reason.as_bytes());
                if let Ok(data) = (NetMessage::Reject { reason: reason.to_string(), signature: sig }).serialize() { conn.send(&data).ok(); }
                self.connection_pool.remove(addr);
                println!("✗ Peer rejected: {}", reason);
                return;
            }
        }
        println!("Peer not found");
    }
    
    pub fn propose(&self, text: &str) {
        if text.len() < MIN_ELABORATION_LEN { println!("✗ Proposal too short"); return; }
        let trust = self.state.read().unwrap().get_mark(&self.did).current_score();
        if trust < TRUST_MIN_FOR_PROPOSE { println!("✗ Insufficient trust: {:.2} < {:.2}", trust, TRUST_MIN_FOR_PROPOSE); return; }
        
        let mut store = self.store.write().unwrap();
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
        let (cid, _) = store.store(signed_expr);
        let expr_bytes = store.arena().serialize(signed_expr);
        drop(store);
        
        let peer_count = self.connection_pool.authenticated_addrs().len();
        let threshold = self.state.read().unwrap().threshold(peer_count);
        let proposal = ProposalState { cid, expr_data: expr_bytes.clone(), proposer: self.did.clone(), elaboration: text.to_string(), quorum: QuorumState::new(cid, threshold), executed: false, created: timestamp() };
        self.state.write().unwrap().proposals.insert(cid, proposal);
        let _ = self.save_state();
        println!("[PROPOSE] {}", cid);
        self.broadcast_authenticated(&NetMessage::Expression(expr_bytes));
    }
    
    pub fn vote(&self, cid_prefix: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("✗ Elaboration too short"); return; }
        let cid = match self.state.read().unwrap().proposals.keys().find(|c| c.short().starts_with(cid_prefix)).copied() {
            Some(c) => c, None => { println!("✗ Proposal not found"); return; }
        };
        
        let mut store = self.store.write().unwrap();
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
        let (_vote_cid, _) = store.store(signed_expr);
        let vote_bytes = store.arena().serialize(signed_expr);
        drop(store);
        
        let mark = self.state.read().unwrap().get_mark(&self.did);
        let signal = QuorumSignal { source: self.did.clone(), target: cid, weight: mark.signal_weight(), support, elaboration: elaboration.to_string(), timestamp: timestamp(), signature: self.sign(&bincode::serialize(&(&cid, support, elaboration)).unwrap()) };
        
        {
            let (sensed, reached) = {
                let mut state = self.state.write().unwrap();
                if let Some(proposal) = state.proposals.get_mut(&cid) {
                    let sensed = proposal.quorum.sense(signal.clone());
                    let reached = sensed && proposal.quorum.reached() && !proposal.executed;
                    if reached { proposal.executed = true; }
                    (sensed, reached)
                } else { (false, false) }
            };
            if sensed {
                self.state.write().unwrap().update_mark(&self.did, score_elaboration(elaboration));
                if reached { println!("[QUORUM] {} reached threshold!", cid); }
            }
        }
        let _ = self.save_state();
        println!("[VOTE] {} on {}", if support { "YES" } else { "NO" }, cid);
        self.broadcast_authenticated(&NetMessage::Expression(vote_bytes));
        self.broadcast_authenticated(&NetMessage::Signal(signal));
    }
    
    pub fn propose_pool(&self, phrase: &str, rationale: &str) {
        let commitment = sha256(phrase.as_bytes());
        let hint = if phrase.len() > 8 { format!("{}...{}", &phrase[..4], &phrase[phrase.len()-4..]) } else { phrase.to_string() };
        let state = self.state.read().unwrap();
        if state.active_pools.contains(&commitment) { println!("✗ Pool already active"); return; }
        if state.pool_proposals.contains_key(&commitment) { println!("✗ Proposal already exists"); return; }
        drop(state);
        let peer_count = self.connection_pool.authenticated_addrs().len();
        let threshold = self.state.read().unwrap().threshold(peer_count);
        let pool = PoolState { commitment, hint, rationale: rationale.to_string(), proposer: self.did.clone(), quorum: QuorumState::new(Cid(commitment), threshold), active: false };
        self.state.write().unwrap().pool_proposals.insert(commitment, pool);
        let _ = self.save_state();
        println!("[POOL-PROPOSE] {}", hex::encode(&commitment[..8]));
    }
    
    pub fn vote_pool(&self, id: &str, support: bool, elaboration: &str) {
        if elaboration.len() < MIN_ELABORATION_LEN { println!("✗ Elaboration too short"); return; }
        let commitment = match self.state.read().unwrap().pool_proposals.keys().find(|c| hex::encode(&c[..8]).starts_with(id)).copied() {
            Some(c) => c, None => { println!("✗ Pool proposal not found"); return; }
        };
        let mark = self.state.read().unwrap().get_mark(&self.did);
        let signal = QuorumSignal { source: self.did.clone(), target: Cid(commitment), weight: mark.signal_weight(), support, elaboration: elaboration.to_string(), timestamp: timestamp(), signature: self.sign(elaboration.as_bytes()) };
        let mut state = self.state.write().unwrap();
        if let Some(pool) = state.pool_proposals.get_mut(&commitment) {
            if pool.quorum.sense(signal) && pool.quorum.reached() && !pool.active {
                pool.active = true; state.active_pools.insert(commitment);
                println!("[POOL] {} activated!", hex::encode(&commitment[..8]));
            }
        }
        drop(state); let _ = self.save_state();
        println!("[POOL-VOTE] {} on {}", if support { "YES" } else { "NO" }, hex::encode(&commitment[..8]));
    }
    
    pub fn status(&self) {
        let state = self.state.read().unwrap();
        let store = self.store.read().unwrap();
        let pool = self.pool.read().unwrap();
        let auth_count = self.connection_pool.authenticated_addrs().len();
        let pending = self.connection_pool.pending_approval().len();
        let awaiting = self.connection_pool.awaiting_elaboration().len();
        println!();
        println!("=== DIAGON STATUS ===");
        println!("🔑 DID: {}", self.did.short());
        println!("🏊 Pool: {}", pool.map(|p| hex::encode(&p[..8])).unwrap_or_else(|| "Not set".to_string()));
        println!("📝 Expressions: {}", store.log().len());
        println!("📋 Proposals: {}", state.proposals.len());
        println!("🏊 Active pools: {}", state.active_pools.len());
        println!("🔗 Peers: {} auth, {} pending, {} awaiting", auth_count, pending, awaiting);
        if !state.proposals.is_empty() {
            println!();
            println!("Proposals:");
            for (cid, prop) in state.proposals.iter().take(10) {
                let status = if prop.executed { "✓" } else { "○" };
                let text = if prop.elaboration.len() > 40 { format!("{}...", &prop.elaboration[..40]) } else { prop.elaboration.clone() };
                println!("  {} {} - \"{}\" ({}/{})", status, cid.short(), text, prop.quorum.accumulated_for(), prop.quorum.threshold);
            }
        }
        let conns = self.connection_pool.connections.read().unwrap();
        if !conns.is_empty() {
            println!();
            println!("Connections:");
            for (addr, conn) in conns.iter() {
                let did_str = conn.did.read().unwrap().as_ref().map(|d| d.short()).unwrap_or_else(|| "?".to_string());
                let state_str = match *conn.state.read().unwrap() { ConnectionState::Connected => "auth", ConnectionState::PendingApproval => "pending", ConnectionState::AwaitingElaboration => "awaiting", s => &format!("{:?}", s).to_lowercase() };
                println!("  {} @ {} ({})", did_str, addr, state_str);
            }
        }
        println!();
    }
    
    pub fn list_pools(&self) {
        let state = self.state.read().unwrap();
        println!();
        println!("=== ACTIVE POOLS ===");
        for (i, pool) in state.active_pools.iter().enumerate() {
            println!("  #{} {} {}", i + 1, hex::encode(&pool[..8]), if GENESIS_POOLS.contains(pool) { "[genesis]" } else { "[dynamic]" });
        }
        if !state.pool_proposals.is_empty() {
            println!();
            println!("=== PENDING POOL PROPOSALS ===");
            for (commitment, pool) in &state.pool_proposals {
                println!("  {} - \"{}\" ({}/{})", hex::encode(&commitment[..8]), if pool.rationale.len() > 40 { format!("{}...", &pool.rationale[..40]) } else { pool.rationale.clone() }, pool.quorum.accumulated_for(), pool.quorum.threshold);
            }
        }
        println!();
    }
    
    pub fn eval(&self, input: &str) {
        let mut store = self.store.write().unwrap();
        if let Some(expr) = store.arena_mut().parse(input) {
            let (cid, is_new) = store.store(expr);
            println!("Parsed: {}", store.arena().display(expr));
            println!("CID: {} {}", cid, if is_new { "(new)" } else { "(exists)" });
        } else { println!("Parse error"); }
    }
    
    fn accept_loop(node: Arc<Node>) {
        while node.running.load(Ordering::Relaxed) {
            let listener_guard = node.listener.read().unwrap();
            if let Some(ref listener) = *listener_guard {
                match listener.accept() {
                    Ok((stream, addr)) => { drop(listener_guard); node.handle_incoming(stream, addr); }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => { drop(listener_guard); thread::sleep(Duration::from_millis(50)); }
                    Err(_) => { drop(listener_guard); thread::sleep(Duration::from_millis(50)); }
                }
            } else { break; }
        }
    }
    
    fn handle_incoming(&self, stream: TcpStream, addr: SocketAddr) {
        stream.set_nonblocking(false).ok();
        if let Ok(conn) = TcpConnection::new(stream, addr, false) {  // they connected to us
            let conn = Arc::new(conn);
            *conn.state.write().unwrap() = ConnectionState::Authenticating;
            if self.connection_pool.add(addr, Arc::clone(&conn)).is_ok() {
                let node_weak = self.weak_self.lock().unwrap().clone().unwrap();
                let handle = thread::spawn(move || Self::reader_loop(node_weak, conn, addr));
                self.connection_pool.add_reader(addr, handle);
            }
        }
    }
    
    fn reader_loop(node_weak: Weak<Node>, conn: Arc<TcpConnection>, addr: SocketAddr) {
        let mut stream = match conn.stream.lock().unwrap().try_clone() { Ok(s) => s, Err(_) => return };
        let mut framer = MessageFramer::new();
        loop {
            let node = match node_weak.upgrade() { Some(n) => n, None => break };
            if !conn.is_alive() { break; }
            match framer.read_message(&mut stream) {
                Ok(Some(data)) => { *conn.last_activity.write().unwrap() = Instant::now(); if let Ok(msg) = NetMessage::deserialize(&data) { let _ = node.handle_message(msg, addr, &conn); } }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        if let Some(node) = node_weak.upgrade() { node.connection_pool.remove(addr); }
    }
    
    fn handle_message(&self, msg: NetMessage, from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        match msg {
            NetMessage::Hello { did, pubkey, pool, expr_root } => self.handle_hello(did, pubkey, pool, expr_root, from, conn),
            NetMessage::Challenge(nonce) => { let sig = self.sign(&nonce); conn.send(&NetMessage::Response { nonce, signature: sig }.serialize()?)?; Ok(()) }
            NetMessage::Response { nonce, signature } => self.handle_response(nonce, signature, from, conn),
            NetMessage::ElaborateRequest => { *conn.state.write().unwrap() = ConnectionState::AwaitingElaboration; println!("🔔 {} requests elaboration", from); println!("   Use 'elaborate <text>' to respond"); Ok(()) }
            NetMessage::Elaborate { text, signature } => self.handle_elaborate(text, signature, from, conn),
            NetMessage::Approve { .. } => { *conn.state.write().unwrap() = ConnectionState::Connected; println!("✓ Authenticated with {}", from); let store = self.store.read().unwrap(); let msg = NetMessage::SyncRequest { merkle: store.merkle_root(), have: store.log().to_vec() }; conn.send(&msg.serialize()?)?; Ok(()) }
            NetMessage::Reject { reason, .. } => { println!("✗ Rejected by {}: {}", from, reason); self.connection_pool.remove(from); Ok(()) }
            NetMessage::Expression(data) => self.handle_expression(data, from, conn),
            NetMessage::Signal(signal) => self.handle_signal(signal, from, conn),
            NetMessage::SyncRequest { merkle, have } => self.handle_sync_request(merkle, have, from, conn),
            NetMessage::SyncReply { expressions } => self.handle_sync_reply(expressions, from, conn),
            NetMessage::Heartbeat { .. } => { *conn.last_activity.write().unwrap() = Instant::now(); Ok(()) }
            NetMessage::Disconnect { .. } => { self.connection_pool.remove(from); println!("🔌 {} disconnected", from); Ok(()) }
        }
    }
    
    fn handle_hello(&self, did: Did, pubkey: Vec<u8>, pool: [u8; 32], _expr_root: [u8; 32], from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        // Verify pool
        let our_pool = self.pool.read().unwrap();
        if let Some(p) = *our_pool { if pool != p { conn.send(&NetMessage::Reject { reason: "Pool mismatch".into(), signature: self.sign(b"pool_mismatch") }.serialize()?)?; return Err(DiagonError::Validation("Pool mismatch".into())); } }
        else { conn.send(&NetMessage::Reject { reason: "No pool configured".into(), signature: self.sign(b"no_pool") }.serialize()?)?; return Err(DiagonError::Validation("No pool".into())); }
        
        // Store peer info
        *conn.did.write().unwrap() = Some(did.clone());
        *conn.pubkey.write().unwrap() = Some(pubkey);
        self.connection_pool.register_did(from, &did);
        
        if conn.initiated {
            // WE initiated this connection - this is their Hello response
            // Just wait for their Challenge, then we'll elaborate
            println!("← Hello from {} ({})", from, did.short());
            // Send our challenge to verify them too
            let mut nonce = [0u8; 32]; OsRng.fill_bytes(&mut nonce);
            *conn.challenge_sent.write().unwrap() = Some(nonce);
            *conn.challenge_time.write().unwrap() = Some(Instant::now());
            conn.send(&NetMessage::Challenge(nonce).serialize()?)?;
        } else {
            // THEY connected to us - send Hello back + Challenge + ElaborateRequest
            let store = self.store.read().unwrap();
            conn.send(&NetMessage::Hello { did: self.did.clone(), pubkey: self.public_key.as_bytes().to_vec(), pool: self.pool.read().unwrap().unwrap(), expr_root: store.merkle_root() }.serialize()?)?;
            
            // Generate and send challenge
            let mut nonce = [0u8; 32]; OsRng.fill_bytes(&mut nonce);
            *conn.challenge_sent.write().unwrap() = Some(nonce);
            *conn.challenge_time.write().unwrap() = Some(Instant::now());
            conn.send(&NetMessage::Challenge(nonce).serialize()?)?;
            
            // Request elaboration from initiator
            conn.send(&NetMessage::ElaborateRequest.serialize()?)?;
            
            println!("← Connection from {} ({})", from, did.short());
            println!("  Awaiting elaboration...");
            *conn.state.write().unwrap() = ConnectionState::AwaitingElaboration;
        }
        
        Ok(())
    }
    
    fn handle_response(&self, nonce: [u8; 32], signature: Vec<u8>, _from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        if conn.challenge_sent.read().unwrap().as_ref() != Some(&nonce) { return Err(DiagonError::Validation("Nonce mismatch".into())); }
        if let Some(time) = *conn.challenge_time.read().unwrap() { if time.elapsed() > Duration::from_secs(CHALLENGE_TIMEOUT_SECS) { return Err(DiagonError::Validation("Challenge expired".into())); } }
        if let Some(pk) = conn.pubkey.read().unwrap().as_ref() { self.verify(&nonce, &signature, pk)?; } else { return Err(DiagonError::Validation("No pubkey".into())); }
        *conn.challenge_sent.write().unwrap() = None;
        Ok(())
    }
    
    fn handle_elaborate(&self, text: String, signature: Vec<u8>, from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        if text.len() < MIN_ELABORATION_LEN { return Err(DiagonError::Validation("Elaboration too short".into())); }
        if let Some(pk) = conn.pubkey.read().unwrap().as_ref() { self.verify(text.as_bytes(), &signature, pk)?; } else { return Err(DiagonError::Validation("No pubkey".into())); }
        *conn.elaboration.write().unwrap() = Some(text.clone());
        *conn.state.write().unwrap() = ConnectionState::PendingApproval;
        if let Some(did) = conn.did.read().unwrap().as_ref() {
            println!();
            println!("🔔 ELABORATION from {}", did.short());
            println!("   \"{}\"", text);
            println!("   Use 'approve {}' or 'reject {} <reason>'", did.short(), did.short());
        }
        Ok(())
    }
    
    fn handle_expression(&self, data: Vec<u8>, from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        let mut store = self.store.write().unwrap();
        if let Some((cid, is_new)) = store.deserialize_and_store(&data) {
            if is_new {
                println!("[EXPR] Received {}", cid);
                conn.mark_seen(&cid);
                drop(store);
                self.process_expression(cid, &data);
                let msg = NetMessage::Expression(data);
                let msg_data = msg.serialize()?;
                let conns = self.connection_pool.connections.read().unwrap();
                for (addr, peer_conn) in conns.iter() {
                    if *addr != from && peer_conn.is_authenticated() && !peer_conn.has_seen(&cid) {
                        peer_conn.mark_seen(&cid);
                        peer_conn.send(&msg_data).ok();
                    }
                }
            }
        }
        Ok(())
    }
    
    fn process_expression(&self, cid: Cid, data: &[u8]) {
        let store = self.store.read().unwrap();
        let expr = match store.fetch(&cid) { Some(e) => e, None => return };
        let op = store.arena().car(expr);
        if let SexpNode::Atom(s) = store.arena().get(op) {
            if s == "signed" {
                let inner = store.arena().nth(expr, 3);
                let inner_op = store.arena().car(inner);
                if let SexpNode::Atom(inner_s) = store.arena().get(inner_op) {
                    if inner_s == "propose" && !self.state.read().unwrap().proposals.contains_key(&cid) {
                        let text_ref = store.arena().nth(inner, 1);
                        if let SexpNode::Atom(text) = store.arena().get(text_ref) {
                            let peer_count = self.connection_pool.authenticated_addrs().len();
                            let threshold = self.state.read().unwrap().threshold(peer_count);
                            let proposal = ProposalState { cid, expr_data: data.to_vec(), proposer: self.did.clone(), elaboration: text.clone(), quorum: QuorumState::new(cid, threshold), executed: false, created: timestamp() };
                            self.state.write().unwrap().proposals.insert(cid, proposal);
                            let _ = self.save_state();
                        }
                    }
                }
            }
        }
    }
    
    fn handle_signal(&self, signal: QuorumSignal, from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if let Some(proposal) = state.proposals.get_mut(&signal.target) {
            if proposal.quorum.sense(signal.clone()) {
                println!("[SIGNAL] {} on {} (+{})", if signal.support { "FOR" } else { "AGAINST" }, signal.target.short(), signal.weight);
                if proposal.quorum.reached() && !proposal.executed { proposal.executed = true; println!("[QUORUM] {} reached!", signal.target); }
            }
        }
        drop(state);
        let msg = NetMessage::Signal(signal);
        let msg_data = msg.serialize()?;
        let conns = self.connection_pool.connections.read().unwrap();
        for (addr, peer_conn) in conns.iter() { if *addr != from && peer_conn.is_authenticated() { peer_conn.send(&msg_data).ok(); } }
        Ok(())
    }
    
    fn handle_sync_request(&self, peer_merkle: [u8; 32], have: Vec<Cid>, from: SocketAddr, conn: &Arc<TcpConnection>) -> Result<()> {
        let store = self.store.read().unwrap();
        if store.merkle_root() != peer_merkle {
            let have_set: HashSet<_> = have.into_iter().collect();
            let missing: Vec<Vec<u8>> = store.log().iter().filter(|cid| !have_set.contains(cid)).filter_map(|cid| store.serialize_expr(cid)).collect();
            if !missing.is_empty() { conn.send(&NetMessage::SyncReply { expressions: missing }.serialize()?)?; }
        }
        Ok(())
    }
    
    fn handle_sync_reply(&self, expressions: Vec<Vec<u8>>, _from: SocketAddr, _conn: &Arc<TcpConnection>) -> Result<()> {
        let mut store = self.store.write().unwrap();
        let mut added = 0;
        for data in expressions {
            if let Some((cid, true)) = store.deserialize_and_store(&data) { added += 1; drop(store); self.process_expression(cid, &data); store = self.store.write().unwrap(); }
        }
        if added > 0 { println!("[SYNC] Received {} expressions", added); drop(store); let _ = self.save_state(); }
        Ok(())
    }
    
    fn broadcast_authenticated(&self, msg: &NetMessage) {
        if let Ok(data) = msg.serialize() { for addr in self.connection_pool.authenticated_addrs() { if let Some(conn) = self.connection_pool.get(&addr) { conn.send(&data).ok(); } } }
    }
    
    fn heartbeat_loop(node: Arc<Node>) {
        while node.running.load(Ordering::Relaxed) {
            thread::sleep(HEARTBEAT_INTERVAL);
            node.broadcast_authenticated(&NetMessage::Heartbeat { signature: node.sign(b"heartbeat") });
            let conns = node.connection_pool.connections.read().unwrap();
            let dead: Vec<_> = conns.iter().filter(|(_, c)| !c.is_alive()).map(|(a, _)| *a).collect();
            drop(conns);
            for addr in dead { node.connection_pool.remove(addr); node.reconnect_queue.write().unwrap().push_back((addr, Instant::now(), 0)); }
        }
    }
    
    fn sync_loop(node: Arc<Node>) {
        while node.running.load(Ordering::Relaxed) {
            thread::sleep(SYNC_INTERVAL);
            let store = node.store.read().unwrap();
            let msg = NetMessage::SyncRequest { merkle: store.merkle_root(), have: store.log().to_vec() };
            drop(store);
            for addr in node.connection_pool.authenticated_addrs().into_iter().take(3) {
                if let Some(conn) = node.connection_pool.get(&addr) { if let Ok(data) = msg.serialize() { conn.send(&data).ok(); } }
            }
        }
    }
    
    fn reconnect_loop(node: Arc<Node>) {
        while node.running.load(Ordering::Relaxed) {
            thread::sleep(CONNECTION_RETRY_INTERVAL);
            let mut queue = node.reconnect_queue.write().unwrap();
            let len = queue.len();
            for _ in 0..len.min(5) {
                if let Some((addr, last, attempts)) = queue.pop_front() {
                    if last.elapsed() < CONNECTION_RETRY_INTERVAL { queue.push_back((addr, last, attempts)); continue; }
                    if attempts >= MAX_RECONNECT_ATTEMPTS { continue; }
                    drop(queue);
                    if node.connect(&addr.to_string()).is_err() { node.reconnect_queue.write().unwrap().push_back((addr, Instant::now(), attempts + 1)); }
                    queue = node.reconnect_queue.write().unwrap();
                }
            }
        }
    }
    
    pub fn shutdown(&self) {
        println!("\n🛑 Shutting down...");
        self.running.store(false, Ordering::Relaxed);
        self.broadcast_authenticated(&NetMessage::Disconnect { signature: self.sign(b"disconnect") });
        thread::sleep(Duration::from_millis(100));
        let _ = self.save_state();
        self.connection_pool.shutdown();
        self.listener.write().unwrap().take();
        println!("✓ Shutdown complete");
    }
}

fn sha256(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }
fn timestamp() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }
fn score_elaboration(text: &str) -> f64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() { return 0.0; }
    let unique: HashSet<&str> = words.iter().copied().collect();
    ((unique.len() as f64 / words.len() as f64) * 0.5 + (words.len() as f64 / 100.0).min(1.0) * 0.5).clamp(0.0, 1.0)
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }
    pub fn decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 { return Err(()); }
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ())).collect()
    }
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

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:9070");
    let db_path = args.get(2).map(|s| s.as_str()).unwrap_or("diagon_db");
    let node = match Node::new(addr, db_path) { Ok(n) => n, Err(e) => { eprintln!("Failed to start: {}", e); return Ok(()); } };
    print_help();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    while node.running.load(Ordering::Relaxed) {
        print!("> "); stdout.flush()?;
        let mut input = String::new();
        match stdin.read_line(&mut input) { Ok(0) => break, Ok(_) => {}, Err(_) => break }
        let input = input.trim();
        if input.is_empty() { continue; }
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).unwrap_or(&"");
        match cmd {
            "auth" if !arg.is_empty() => { node.auth(arg); }
            "connect" if !arg.is_empty() => { if let Err(e) = node.connect(arg) { println!("✗ {}", e); } }
            "elaborate" if !arg.is_empty() => { node.elaborate(arg); }
            "approve" if !arg.is_empty() => { node.approve(arg); }
            "reject" if !arg.is_empty() => { let parts: Vec<&str> = arg.splitn(2, ' ').collect(); node.reject(parts[0], parts.get(1).unwrap_or(&"Rejected")); }
            "propose" if !arg.is_empty() => { node.propose(arg); }
            "vote" if !arg.is_empty() => { let parts: Vec<&str> = arg.splitn(3, ' ').collect(); if parts.len() >= 3 { node.vote(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]); } else { println!("Usage: vote <cid> <y/n> <elaboration>"); } }
            "propose-pool" if !arg.is_empty() => { if let Some(pos) = arg.find(" - ") { node.propose_pool(arg[..pos].trim(), arg[pos + 3..].trim()); } else { println!("Usage: propose-pool <phrase> - <rationale>"); } }
            "vote-pool" if !arg.is_empty() => { let parts: Vec<&str> = arg.splitn(3, ' ').collect(); if parts.len() >= 3 { node.vote_pool(parts[0], matches!(parts[1], "y" | "yes" | "true"), parts[2]); } else { println!("Usage: vote-pool <id> <y/n> <elaboration>"); } }
            "list-pools" => { node.list_pools(); }
            "status" => { node.status(); }
            "eval" if !arg.is_empty() => { node.eval(arg); }
            "help" => { print_help(); }
            "quit" | "exit" => { break; }
            _ => { println!("Unknown command. Type 'help' for commands."); }
        }
    }
    node.shutdown();
    Ok(())
}

// ============================================================================
// TESTS - Run with: cargo test -- --nocapture --test-threads=1
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
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
    
    #[test]
    fn test_node_creation() {
        println!("\n═══ TEST: Node Creation ═══");
        let dir = setup_test_dir("creation");
        
        {
            let node = Node::new("127.0.0.1:19081", &format!("{}/node", dir))
                .expect("Failed to create node");
            println!("✓ Node created with DID: {}", node.did.0);
            assert!(!node.did.0.is_empty());
            node.shutdown();
        }
        
        cleanup_test_dir(&dir);
        println!("✓ Node creation test passed\n");
    }
    
    #[test]
    fn test_pool_authentication() {
        println!("\n═══ TEST: Pool Authentication ═══");
        let dir = setup_test_dir("auth");
        
        {
            let node = Node::new("127.0.0.1:19082", &format!("{}/node", dir))
                .expect("Failed to create node");
            
            // Test valid passphrase
            assert!(node.auth(TEST_PASSPHRASE), "Valid passphrase should authenticate");
            println!("✓ Valid passphrase accepted");
            
            // Test invalid passphrase
            assert!(!node.auth("wrong passphrase"), "Invalid passphrase should fail");
            println!("✓ Invalid passphrase rejected");
            
            node.shutdown();
        }
        
        cleanup_test_dir(&dir);
        println!("✓ Pool authentication test passed\n");
    }
    
    #[test]
    fn test_sexp_arena() {
        println!("\n═══ TEST: S-Expression Arena ═══");
        
        let mut arena = Arena::new();
        
        // Test atoms
        let a = arena.atom("hello");
        let b = arena.atom("hello"); // Should return same ref
        assert_eq!(a, b, "Interned atoms should be equal");
        println!("✓ Atom interning works");
        
        // Test cons
        let c = arena.cons(a, SexpRef::NIL);
        assert!(!c.is_nil());
        assert_eq!(arena.car(c), a);
        assert_eq!(arena.cdr(c), SexpRef::NIL);
        println!("✓ Cons cells work");
        
        // Test list
        let x = arena.atom("x");
        let y = arena.atom("y");
        let z = arena.atom("z");
        let list = arena.list(&[x, y, z]);
        assert_eq!(arena.nth(list, 0), x);
        assert_eq!(arena.nth(list, 1), y);
        assert_eq!(arena.nth(list, 2), z);
        println!("✓ List construction works");
        
        // Test display
        let display = arena.display(list);
        assert_eq!(display, "(x y z)");
        println!("✓ Display: {}", display);
        
        // Test parse
        let parsed = arena.parse("(propose \"test\" 42)").unwrap();
        let parsed_display = arena.display(parsed);
        println!("✓ Parsed: {}", parsed_display);
        
        // Test serialization roundtrip
        let serialized = arena.serialize(list);
        let deserialized = arena.deserialize(&serialized).unwrap();
        assert_eq!(arena.display(deserialized), "(x y z)");
        println!("✓ Serialization roundtrip works");
        
        println!("✓ S-Expression arena test passed\n");
    }
    
    #[test]
    fn test_expression_store() {
        println!("\n═══ TEST: Expression Store ═══");
        
        let mut store = ExprStore::new();
        
        // Store an expression
        let expr = store.arena_mut().parse("(propose \"test proposal\")").unwrap();
        let (cid1, is_new1) = store.store(expr);
        assert!(is_new1, "First store should be new");
        println!("✓ Stored expression: {}", cid1);
        
        // Store same expression again
        let expr2 = store.arena_mut().parse("(propose \"test proposal\")").unwrap();
        let (cid2, is_new2) = store.store(expr2);
        assert!(!is_new2, "Duplicate should not be new");
        assert_eq!(cid1, cid2, "Same content should have same CID");
        println!("✓ Deduplication works");
        
        // Fetch
        let fetched = store.fetch(&cid1);
        assert!(fetched.is_some());
        println!("✓ Fetch works");
        
        // Log
        assert_eq!(store.log().len(), 1);
        println!("✓ Log has 1 entry");
        
        println!("✓ Expression store test passed\n");
    }
    
    #[test]
    fn test_quorum_sensing() {
        println!("\n═══ TEST: Quorum Sensing ═══");
        
        let target = Cid::new(b"test_proposal");
        let threshold = 2000;
        let mut quorum = QuorumState::new(target, threshold);
        
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
        
        assert!(quorum.sense(signal1.clone()), "First signal should be accepted");
        println!("✓ Signal 1 accepted: weight={}", signal1.weight);
        
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
        assert!(!quorum.sense(signal1_dup), "Duplicate source should be rejected");
        println!("✓ Duplicate source rejected");
        
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
        assert!(quorum.sense(signal2.clone()), "Second signal should be accepted");
        println!("✓ Signal 2 accepted: weight={}", signal2.weight);
        
        // Check accumulation
        let accumulated = quorum.accumulated_for();
        println!("✓ Accumulated: {}/{}", accumulated, threshold);
        assert!(accumulated >= 1400, "Should have at least 1400 weight");
        
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
        quorum.sense(signal3);
        
        assert!(quorum.reached(), "Quorum should be reached");
        println!("✓ Quorum reached: {}/{}", quorum.accumulated_for(), threshold);
        
        println!("✓ Quorum sensing test passed\n");
    }
    
    #[test]
    fn test_three_node_mesh() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║           DIAGON v0.9.0 - 3-NODE MESH TEST                   ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let dir = setup_test_dir("mesh");
        
        // Phase 1: Create nodes
        println!("═══ PHASE 1: Node Creation ═══");
        let node1 = Node::new("127.0.0.1:19091", &format!("{}/node1", dir)).expect("Node 1 failed");
        println!("✓ Node 1: {}", node1.did.short());
        
        let node2 = Node::new("127.0.0.1:19092", &format!("{}/node2", dir)).expect("Node 2 failed");
        println!("✓ Node 2: {}", node2.did.short());
        
        let node3 = Node::new("127.0.0.1:19093", &format!("{}/node3", dir)).expect("Node 3 failed");
        println!("✓ Node 3: {}", node3.did.short());
        
        thread::sleep(Duration::from_millis(300));
        
        // Phase 2: Authenticate
        println!("\n═══ PHASE 2: Pool Authentication ═══");
        assert!(node1.auth(TEST_PASSPHRASE));
        assert!(node2.auth(TEST_PASSPHRASE));
        assert!(node3.auth(TEST_PASSPHRASE));
        println!("✓ All nodes authenticated");
        
        // Phase 3: Connect mesh
        // Connection topology:
        //   node1 (initiator) -> node2 (receiver)
        //   node1 (initiator) -> node3 (receiver)
        //   node2 (initiator) -> node3 (receiver)
        println!("\n═══ PHASE 3: Mesh Connection ═══");
        node1.connect("127.0.0.1:19092").expect("N1->N2 failed");
        thread::sleep(Duration::from_millis(200));
        node1.connect("127.0.0.1:19093").expect("N1->N3 failed");
        thread::sleep(Duration::from_millis(200));
        node2.connect("127.0.0.1:19093").expect("N2->N3 failed");
        thread::sleep(Duration::from_millis(500));
        println!("✓ Connection attempts complete");
        
        // Phase 4: Initiators elaborate
        // node1 initiated connections to node2 and node3 -> must elaborate to them
        // node2 initiated connection to node3 -> must elaborate to node3
        println!("\n═══ PHASE 4: HITL Elaboration (Initiators) ═══");
        
        // node1 is initiator for 2 connections
        node1.elaborate("Node 1 joining the biological consensus network for distributed governance testing.");
        println!("✓ Node 1 elaborated (initiator to node2, node3)");
        thread::sleep(Duration::from_millis(300));
        
        // node2 is initiator for 1 connection (to node3)
        node2.elaborate("Node 2 participating in quorum sensing for collective decision making tests.");
        println!("✓ Node 2 elaborated (initiator to node3)");
        thread::sleep(Duration::from_millis(500));
        
        // Phase 5: Receivers approve
        // node2 received connection from node1 -> approves node1
        // node3 received connections from node1 and node2 -> approves both
        println!("\n═══ PHASE 5: Peer Approval (Receivers) ═══");
        
        // node2 approves node1
        {
            let pending = node2.connection_pool.pending_approval();
            println!("  Node 2 has {} pending peers", pending.len());
            for (_, conn) in &pending {
                if let Some(did) = conn.did.read().unwrap().as_ref() {
                    node2.approve(&did.short());
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
        
        // node3 approves node1 and node2
        {
            let pending = node3.connection_pool.pending_approval();
            println!("  Node 3 has {} pending peers", pending.len());
            for (_, conn) in &pending {
                if let Some(did) = conn.did.read().unwrap().as_ref() {
                    node3.approve(&did.short());
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
        
        // Phase 6: Verify connections
        println!("\n═══ PHASE 6: Connection Verification ═══");
        let n1_auth = node1.connection_pool.authenticated_addrs().len();
        let n2_auth = node2.connection_pool.authenticated_addrs().len();
        let n3_auth = node3.connection_pool.authenticated_addrs().len();
        println!("  Node 1: {} authenticated peers", n1_auth);
        println!("  Node 2: {} authenticated peers", n2_auth);
        println!("  Node 3: {} authenticated peers", n3_auth);
        
        // Phase 7: Create proposal
        println!("\n═══ PHASE 7: Proposal Creation ═══");
        // Boost trust to allow proposing
        node1.state.write().unwrap().update_mark(&node1.did, 0.9);
        node1.propose("Implement Verkle tree state commitments for efficient state proofs.");
        thread::sleep(Duration::from_millis(500));
        
        let proposal_cid = {
            let state = node1.state.read().unwrap();
            state.proposals.keys().next().copied()
        };
        
        if let Some(cid) = proposal_cid {
            println!("✓ Proposal: {}", cid);
            
            // Phase 8: Vote
            println!("\n═══ PHASE 8: Voting ═══");
            let prefix = cid.short();
            
            node2.state.write().unwrap().update_mark(&node2.did, 0.8);
            node2.vote(&prefix, true, "Strong support for Verkle trees - significant efficiency gains.");
            println!("✓ Node 2 voted YES");
            thread::sleep(Duration::from_millis(300));
            
            node3.state.write().unwrap().update_mark(&node3.did, 0.8);
            node3.vote(&prefix, true, "Agreed, Verkle trees are essential for scalability improvements.");
            println!("✓ Node 3 voted YES");
            thread::sleep(Duration::from_millis(500));
            
            // Phase 9: Check final state
            println!("\n═══ PHASE 9: Final State ═══");
            {
                let state = node1.state.read().unwrap();
                if let Some(prop) = state.proposals.get(&cid) {
                    let votes_for = prop.quorum.accumulated_for();
                    let threshold = prop.quorum.threshold;
                    let status = if prop.executed { "EXECUTED" } else if prop.quorum.reached() { "REACHED" } else { "PENDING" };
                    println!("  Proposal {}: {}/{} [{}]", cid.short(), votes_for, threshold, status);
                }
            }
            
            let n1_expr = node1.store.read().unwrap().log().len();
            let n2_expr = node2.store.read().unwrap().log().len();
            let n3_expr = node3.store.read().unwrap().log().len();
            println!("  Expressions: N1={}, N2={}, N3={}", n1_expr, n2_expr, n3_expr);
        }
        
        // Phase 10: Shutdown
        println!("\n═══ PHASE 10: Shutdown ═══");
        node1.shutdown();
        node2.shutdown();
        node3.shutdown();
        
        cleanup_test_dir(&dir);
        
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║                    TEST COMPLETE                             ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
    }
}