//! KARST L6 Objects, and the canonical encoding the whole stack signs over.
//!
//! An object is signed, immutable, and named by the hash of its own content. Anyone
//! holding it can serve it, so every reader is a replica and there is no unique origin
//! for a takedown order to name.
//!
//! # Canonical encoding
//!
//! Everything hashed or signed in KARST goes through [`Enc`]. It is deterministic,
//! length-prefixed, and has exactly one valid representation of any value. There is no
//! error recovery and no ambiguity: a byte string either decodes to one thing or is
//! rejected.
//!
//! This is deliberate. Parser differentials, where two implementations disagree about
//! what a document says, are one of the largest vulnerability classes on today's web,
//! and they exist because HTML was specified to heroically recover from malformed input
//! rather than reject it. Rejecting is a security property.

use core::fmt;
use std::collections::BTreeMap;

use karst_id::{Address, Identity, Peer, Signature};

/// A content identifier: the BLAKE3 hash of a canonical encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid {
    alg: u8,
    len: u8,
    /// Zero-padded so the derived comparisons stay well defined.
    digest: [u8; MAX_DIGEST],
}

/// Largest digest any algorithm may produce, sized for SHA3-512 and friends.
pub const MAX_DIGEST: usize = 64;

/// Hash algorithm identifiers.
///
/// **A content address is a permanent name**, so a digest that does not say which function
/// produced it can never be migrated: if BLAKE3 breaks, every reference everywhere points at a
/// name an attacker can now collide, and there is no way to tell an old name from a new one.
/// Self-description costs two bytes per reference and is the only thing that makes a future
/// hash distinguishable rather than ambiguous.
///
/// This must exist before there is data, which is why it exists now.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashAlg {
    Blake3 = 1,
}

impl HashAlg {
    pub fn from_tag(t: u8) -> Option<HashAlg> {
        match t {
            1 => Some(HashAlg::Blake3),
            _ => None,
        }
    }
    pub fn digest_len(&self) -> usize {
        match self {
            HashAlg::Blake3 => 32,
        }
    }
}

/// The algorithm new content is named with. Changing this is a protocol version change, per
/// `docs/12-algorithm-evolution.md`, never a per-peer negotiation.
pub const CURRENT_HASH: HashAlg = HashAlg::Blake3;

impl Cid {
    pub fn of(bytes: &[u8]) -> Self {
        let mut digest = [0u8; MAX_DIGEST];
        digest[..32].copy_from_slice(blake3::hash(bytes).as_bytes());
        Cid {
            alg: CURRENT_HASH as u8,
            len: 32,
            digest,
        }
    }

    /// Reconstruct from parts, rejecting an unknown algorithm or a length that does not match
    /// it. A decoder must not accept a digest whose length disagrees with its own tag.
    pub fn from_parts(alg: u8, digest: &[u8]) -> Option<Cid> {
        let a = HashAlg::from_tag(alg)?;
        if digest.len() != a.digest_len() || digest.len() > MAX_DIGEST {
            return None;
        }
        let mut buf = [0u8; MAX_DIGEST];
        buf[..digest.len()].copy_from_slice(digest);
        Some(Cid {
            alg,
            len: digest.len() as u8,
            digest: buf,
        })
    }

    pub fn alg(&self) -> Option<HashAlg> {
        HashAlg::from_tag(self.alg)
    }

    /// The digest bytes, without the algorithm tag.
    pub fn as_bytes(&self) -> &[u8] {
        &self.digest[..self.len as usize]
    }

    pub fn short(&self) -> String {
        format!("c:{}", hex::encode(&self.digest[..5]))
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "c{}:{}", self.alg, hex::encode(self.as_bytes()))
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", self.short())
    }
}

/// Deterministic canonical encoder. One value, one byte string, always.
#[derive(Default)]
pub struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    pub fn new() -> Self {
        Enc { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 1 } else { 0 });
        self
    }

    /// Length-prefixed raw bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// Self-describing: algorithm tag, then length, then digest. Two bytes more than a bare
    /// hash, and the difference between a migration being possible and impossible.
    pub fn cid(&mut self, c: &Cid) -> &mut Self {
        self.buf.push(c.alg);
        self.buf.push(c.len);
        self.buf.extend_from_slice(c.as_bytes());
        self
    }

    pub fn opt_cid(&mut self, c: Option<&Cid>) -> &mut Self {
        match c {
            Some(v) => {
                self.u8(1);
                self.cid(v)
            }
            None => self.u8(0),
        }
    }

    pub fn addr(&mut self, a: &Address) -> &mut Self {
        self.buf.extend_from_slice(a.as_bytes());
        self
    }

    pub fn finish(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn hash(&self) -> Cid {
        Cid::of(&self.buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before the value did.
    Truncated,
    /// Bytes remained after the value was complete. Rejected, never ignored.
    TrailingBytes,
    /// A tag byte was not one of the defined values.
    UnknownTag(u8),
    /// A string field was not valid UTF-8.
    BadUtf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "input truncated"),
            DecodeError::TrailingBytes => write!(f, "trailing bytes after value"),
            DecodeError::UnknownTag(t) => write!(f, "unknown tag byte {t}"),
            DecodeError::BadUtf8 => write!(f, "invalid utf-8 in string field"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Canonical decoder.
///
/// There is no error recovery here by design. Anything that is not exactly one
/// well-formed value is an error, including trailing bytes. HTML's recovery-based
/// parsing is where parser differentials come from, and a differential is a security
/// bug: two implementations that disagree about what a signed document says.
pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Dec { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(DecodeError::UnknownTag(t)),
        }
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.take(4)?;
        let len = u32::from_le_bytes(n.try_into().unwrap()) as usize;
        self.take(len)
    }

    pub fn str(&mut self) -> Result<String, DecodeError> {
        let b = self.bytes()?;
        core::str::from_utf8(b)
            .map(|s| s.to_string())
            .map_err(|_| DecodeError::BadUtf8)
    }

    pub fn cid(&mut self) -> Result<Cid, DecodeError> {
        let alg = self.u8()?;
        let len = self.u8()? as usize;
        if len > MAX_DIGEST {
            return Err(DecodeError::Truncated);
        }
        let b = self.take(len)?;
        Cid::from_parts(alg, b).ok_or(DecodeError::UnknownTag(alg))
    }

    pub fn addr(&mut self) -> Result<Address, DecodeError> {
        let b: [u8; 32] = self.take(32)?.try_into().unwrap();
        Ok(Address::from_raw(b))
    }

    pub fn opt_cid(&mut self) -> Result<Option<Cid>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.cid()?)),
            t => Err(DecodeError::UnknownTag(t)),
        }
    }

    /// Consume the decoder, rejecting any unread bytes.
    pub fn end(self) -> Result<(), DecodeError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    BadSignature,
    MalformedAuthorKey,
    /// The object's stated CID does not match its content.
    CidMismatch,
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectError::BadSignature => write!(f, "object signature did not verify"),
            ObjectError::MalformedAuthorKey => write!(f, "malformed author key"),
            ObjectError::CidMismatch => write!(f, "content does not match its identifier"),
        }
    }
}

impl std::error::Error for ObjectError {}

/// A signed immutable object.
///
/// The author's public key travels with the object, so verification needs no directory,
/// no certificate, and no lookup. An address is the hash of that key, so the object
/// proves its own authorship offline.
#[derive(Clone)]
pub struct Object {
    pub kind: String,
    pub author_key: [u8; 32],
    /// Previous version, for L13 lineage. `None` for an original.
    pub supersedes: Option<Cid>,
    pub seq: u64,
    pub payload: Vec<u8>,
    signature: [u8; 64],
}

impl Object {
    fn signing_bytes(
        kind: &str,
        author_key: &[u8; 32],
        supersedes: Option<&Cid>,
        seq: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut e = Enc::new();
        e.str("karst.object.v1")
            .str(kind)
            .bytes(author_key)
            .opt_cid(supersedes)
            .u64(seq)
            .bytes(payload);
        e.finish()
    }

    pub fn create(
        author: &Identity,
        kind: &str,
        seq: u64,
        payload: Vec<u8>,
        supersedes: Option<Cid>,
    ) -> Self {
        let key = author.key_bytes();
        let msg = Self::signing_bytes(kind, &key, supersedes.as_ref(), seq, &payload);
        let sig = author.sign(&msg);
        Object {
            kind: kind.to_string(),
            author_key: key,
            supersedes,
            seq,
            payload,
            signature: sig.to_bytes(),
        }
    }

    /// The object's name. Pure content addressing: identical content by the same author
    /// has one address, regardless of who is serving it or how many copies exist.
    pub fn cid(&self) -> Cid {
        Cid::of(&Self::signing_bytes(
            &self.kind,
            &self.author_key,
            self.supersedes.as_ref(),
            self.seq,
            &self.payload,
        ))
    }

    pub fn author(&self) -> Result<Address, ObjectError> {
        Address::from_key_bytes(&self.author_key).map_err(|_| ObjectError::MalformedAuthorKey)
    }

    /// Verify authorship offline, against nothing but the object itself.
    pub fn verify(&self) -> Result<Address, ObjectError> {
        let peer =
            Peer::from_key_bytes(&self.author_key).map_err(|_| ObjectError::MalformedAuthorKey)?;
        let msg = Self::signing_bytes(
            &self.kind,
            &self.author_key,
            self.supersedes.as_ref(),
            self.seq,
            &self.payload,
        );
        let sig = Signature::from_bytes(&self.signature);
        peer.verify(&msg, &sig)
            .map_err(|_| ObjectError::BadSignature)?;
        Ok(peer.address())
    }

    /// Simulate a relay tampering with an object in flight.
    #[doc(hidden)]
    pub fn tamper(&self, new_payload: Vec<u8>) -> Self {
        let mut c = self.clone();
        c.payload = new_payload;
        c
    }
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Object({}, kind={}, {} bytes)",
            self.cid().short(),
            self.kind,
            self.payload.len()
        )
    }
}

/// Object kind for the two halves of a key rotation.
pub mod freshness;

pub const ROTATION_KIND: &str = "karst.rotation.v1";

/// A completed key rotation: the one legitimate cross-key edge in a lineage.
///
/// An address is the hash of a public key, so changing signature algorithm, or simply
/// rotating a key, means a new address. Without an exception, the same-author rule that stops
/// lineage hijacking (issue #31) also stops a legitimate rotation, and identity could never
/// migrate.
///
/// **Both directions must be signed.** The old key attests to its successor and the new key
/// attests to its predecessor. A single-sided claim proves nothing: with only the forward half
/// a compromised old key could hand identity to an attacker, and with only the backward half
/// anyone could claim to be anyone's successor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub from: Address,
    pub to: Address,
}

impl Rotation {
    /// The old key attests that `to` succeeds it.
    pub fn forward(old: &Identity, new_key: &[u8; 32], seq: u64) -> Result<Object, ObjectError> {
        let new_addr = Address::from_key_bytes(new_key).map_err(|_| ObjectError::MalformedAuthorKey)?;
        let mut e = Enc::new();
        e.str("forward").addr(&new_addr);
        Ok(Object::create(old, ROTATION_KIND, seq, e.finish(), None))
    }

    /// The new key attests that it succeeds `old`.
    pub fn backward(new: &Identity, old_key: &[u8; 32], seq: u64) -> Result<Object, ObjectError> {
        let old_addr = Address::from_key_bytes(old_key).map_err(|_| ObjectError::MalformedAuthorKey)?;
        let mut e = Enc::new();
        e.str("backward").addr(&old_addr);
        Ok(Object::create(new, ROTATION_KIND, seq, e.finish(), None))
    }

    fn parse(obj: &Object) -> Option<(bool, Address, Address)> {
        if obj.kind != ROTATION_KIND {
            return None;
        }
        let signer = obj.verify().ok()?;
        let mut d = Dec::new(&obj.payload);
        let dir = d.str().ok()?;
        let other = d.addr().ok()?;
        d.end().ok()?;
        match dir.as_str() {
            "forward" => Some((true, signer, other)),
            "backward" => Some((false, other, signer)),
            _ => None,
        }
    }
}

/// How a version series resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// One current version.
    Head(Cid),
    /// The author signed two or more successors to the same version. This is
    /// equivocation and it is surfaced rather than silently resolved, because silently
    /// picking one is how an author shows different histories to different readers.
    Forked(Vec<Cid>),
    Unknown,
}

impl Resolution {
    pub fn head(&self) -> Option<Cid> {
        match self {
            Resolution::Head(c) => Some(*c),
            _ => None,
        }
    }
}

/// A version history: immutable objects linked by `supersedes`.
///
/// This is the answer to "can content be updated while old versions survive". Editing
/// publishes a new object pointing at its predecessor. The predecessor is untouched,
/// still verifies, and keeps its own name forever, so a citation to it cannot rot and
/// cannot silently come to mean something else.
///
/// **What this does not do is keep the bytes alive.** Content addressing gives integrity
/// and addressability, never availability. If nobody holds a version, it is gone, and it
/// is gone whether or not anybody can prove what it said. See
/// `docs/10-versioning-and-permanence.md`.
#[derive(Default)]
pub struct Lineage {
    objects: BTreeMap<Cid, Object>,
    /// Half-signed rotation claims, awaiting their counterpart.
    rotation_halves: BTreeMap<(Address, Address), (bool, bool)>,
}

impl Lineage {
    pub fn new() -> Self {
        Lineage::default()
    }

    /// Verify and store. Objects may arrive in any order and from anyone.
    ///
    /// Rotation halves are recorded as they arrive, and a rotation only becomes usable once
    /// both directions are present.
    pub fn insert(&mut self, obj: Object) -> Result<Cid, ObjectError> {
        obj.verify()?;
        if let Some((is_forward, from, to)) = Rotation::parse(&obj) {
            let e = self.rotation_halves.entry((from, to)).or_insert((false, false));
            if is_forward {
                e.0 = true;
            } else {
                e.1 = true;
            }
        }
        let cid = obj.cid();
        self.objects.insert(cid, obj);
        Ok(cid)
    }

    /// Rotations with both halves present.
    pub fn rotations(&self) -> Vec<Rotation> {
        self.rotation_halves
            .iter()
            .filter(|(_, (f, b))| *f && *b)
            .map(|((from, to), _)| Rotation {
                from: *from,
                to: *to,
            })
            .collect()
    }

    fn rotation_exists(&self, from: &Address, to: &Address) -> bool {
        matches!(self.rotation_halves.get(&(*from, *to)), Some((true, true)))
    }

    /// Follow rotations forward from an address to the identity currently in use.
    ///
    /// Returns the input unchanged when there is no rotation, and stops rather than looping if
    /// a cycle is present.
    pub fn current_identity(&self, addr: Address) -> Address {
        let mut seen = std::collections::BTreeSet::new();
        let mut cur = addr;
        while seen.insert(cur) {
            let next = self
                .rotations()
                .into_iter()
                .find(|r| r.from == cur)
                .map(|r| r.to);
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        cur
    }

    pub fn get(&self, cid: &Cid) -> Option<&Object> {
        self.objects.get(cid)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Is `successor` a legitimate next version of `predecessor`?
    ///
    /// A lineage edge is an update by the same author within the same series, not merely
    /// an arbitrary signed backlink. Without this, anyone can publish a validly signed
    /// object pointing at somebody else's CID and become the resolved head of their
    /// document, or manufacture a fork that gets attributed to them.
    ///
    /// Rules: same author, same kind, strictly increasing sequence.
    ///
    /// See [`Lineage::is_valid_edge_with_rotations`] for the one exception.
    pub fn is_valid_edge(predecessor: &Object, successor: &Object) -> bool {
        successor.supersedes == Some(predecessor.cid())
            && successor.kind == predecessor.kind
            && successor.seq > predecessor.seq
            && successor.author_key == predecessor.author_key
    }

    /// The same rule, with the key-rotation exception applied.
    ///
    /// A cross-key edge is legitimate exactly when a **fully countersigned** rotation links the
    /// two authors. One-sided claims are refused, so neither a compromised old key nor an
    /// opportunistic new one can move an identity alone.
    pub fn is_valid_edge_with_rotations(&self, predecessor: &Object, successor: &Object) -> bool {
        if successor.supersedes != Some(predecessor.cid())
            || successor.kind != predecessor.kind
            || successor.seq <= predecessor.seq
        {
            return false;
        }
        if successor.author_key == predecessor.author_key {
            return true;
        }
        match (predecessor.author(), successor.author()) {
            (Ok(from), Ok(to)) => self.rotation_exists(&from, &to),
            _ => false,
        }
    }

    /// Walk backwards to the original, newest first. Every entry still verifies, and
    /// every step is a valid edge. A history stops at the first edge that is not.
    pub fn history(&self, cid: &Cid) -> Vec<&Object> {
        let mut out = Vec::new();
        let mut cursor = self.objects.get(cid);
        while let Some(o) = cursor {
            out.push(o);
            cursor = match o.supersedes.and_then(|p| self.objects.get(&p)) {
                Some(prev) if self.is_valid_edge_with_rotations(prev, o) => Some(prev),
                // Either we do not hold the predecessor, or the edge is not a legitimate
                // same-author same-series update. Either way the walk stops here.
                _ => None,
            };
        }
        out
    }

    /// Versions that legitimately supersede this one. More than one means the author
    /// equivocated, or a fork was intentional.
    ///
    /// Objects from other authors that merely point at this CID are not successors and
    /// never appear here.
    pub fn successors(&self, cid: &Cid) -> Vec<Cid> {
        let Some(pred) = self.objects.get(cid) else {
            return Vec::new();
        };
        let mut out: Vec<Cid> = self
            .objects
            .values()
            .filter(|o| self.is_valid_edge_with_rotations(pred, o))
            .map(|o| o.cid())
            .collect();
        out.sort();
        out
    }

    /// Objects we hold that claim to supersede `cid` but are not entitled to, with the
    /// reason. Surfaced rather than silently dropped, because someone attempting to hijack
    /// a version series is worth seeing.
    pub fn rejected_edges(&self, cid: &Cid) -> Vec<(Cid, &'static str)> {
        let Some(pred) = self.objects.get(cid) else {
            return Vec::new();
        };
        self.objects
            .values()
            .filter(|o| o.supersedes.as_ref() == Some(cid))
            .filter_map(|o| {
                let why = if o.author_key != pred.author_key
                    && !matches!(
                        (pred.author(), o.author()),
                        (Ok(f), Ok(t)) if self.rotation_exists(&f, &t)
                    ) {
                    "different author, no countersigned rotation"
                } else if o.kind != pred.kind {
                    "different kind"
                } else if o.seq <= pred.seq {
                    "sequence did not advance"
                } else {
                    return None;
                };
                Some((o.cid(), why))
            })
            .collect()
    }

    /// Follow the chain forward from any version to the current one.
    pub fn resolve(&self, from: &Cid) -> Resolution {
        if !self.objects.contains_key(from) {
            return Resolution::Unknown;
        }
        let mut cursor = *from;
        loop {
            let next = self.successors(&cursor);
            match next.len() {
                0 => return Resolution::Head(cursor),
                1 => cursor = next[0],
                _ => return Resolution::Forked(next),
            }
        }
    }

    /// Did this author ever sign two successors to the same version anywhere in the
    /// store. A transparency log at L8 is what makes this detectable in practice, since
    /// an equivocating author simply would not show you both.
    pub fn equivocations(&self) -> Vec<Cid> {
        self.objects
            .keys()
            .filter(|c| self.successors(c).len() > 1)
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_id::Identity;

    #[test]
    fn encoding_is_deterministic() {
        let mut a = Enc::new();
        a.str("x").u64(7).bool(true);
        let mut b = Enc::new();
        b.str("x").u64(7).bool(true);
        assert_eq!(a.finish(), b.finish());
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn length_prefixing_prevents_field_confusion() {
        // Without length prefixes "ab" + "c" and "a" + "bc" would collide.
        let mut a = Enc::new();
        a.str("ab").str("c");
        let mut b = Enc::new();
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn object_verifies_offline_with_no_directory() {
        let author = Identity::generate();
        let obj = Object::create(&author, "note", 0, b"hello".to_vec(), None);
        assert_eq!(obj.verify().unwrap(), author.address());
    }

    #[test]
    fn tampering_breaks_both_the_name_and_the_signature() {
        let author = Identity::generate();
        let obj = Object::create(&author, "note", 0, b"transfer 10".to_vec(), None);
        let evil = obj.tamper(b"transfer 9000".to_vec());

        assert_ne!(obj.cid(), evil.cid(), "content address must change");
        assert_eq!(evil.verify(), Err(ObjectError::BadSignature));
    }

    #[test]
    fn identical_content_has_one_address_so_replicas_dedupe() {
        let author = Identity::from_seed([7u8; 32]);
        let a = Object::create(&author, "note", 3, b"same".to_vec(), None);
        let b = Object::create(&author, "note", 3, b"same".to_vec(), None);
        assert_eq!(a.cid(), b.cid());
    }

    #[test]
    fn an_old_citation_still_resolves_and_still_verifies_after_edits() {
        let author = Identity::generate();
        let mut lin = Lineage::new();

        let v1 = Object::create(&author, "page", 0, b"the original claim".to_vec(), None);
        let c1 = lin.insert(v1).unwrap();
        let v2 = Object::create(&author, "page", 1, b"a revised claim".to_vec(), Some(c1));
        let c2 = lin.insert(v2).unwrap();
        let v3 = Object::create(&author, "page", 2, b"the final claim".to_vec(), Some(c2));
        let c3 = lin.insert(v3).unwrap();

        // Someone cited v1 years ago. It has not moved and has not changed.
        let cited = lin.get(&c1).unwrap();
        assert_eq!(cited.payload, b"the original claim");
        assert!(cited.verify().is_ok());

        // And from that citation you can find what it became.
        assert_eq!(lin.resolve(&c1), Resolution::Head(c3));
        assert_eq!(lin.history(&c3).len(), 3);
        assert_eq!(lin.history(&c3)[2].payload, b"the original claim");
    }

    /// Regression for issue #31, reported by @matthiasantierens.
    ///
    /// `successors` used to match on `supersedes` alone, so anyone could publish a validly
    /// signed object pointing at someone else's CID and become the resolved head of their
    /// document. An edge is now an update by the same author in the same series.
    #[test]
    fn a_content_address_says_which_hash_produced_it() {
        let c = Cid::of(b"x");
        assert_eq!(c.alg(), Some(HashAlg::Blake3));
        assert_eq!(c.as_bytes().len(), 32);

        let mut e = Enc::new();
        e.cid(&c);
        let bytes = e.finish();
        // Algorithm tag, length, digest. Two bytes more than a bare hash.
        assert_eq!(bytes.len(), 34);
        assert_eq!(bytes[0], HashAlg::Blake3 as u8);
        assert_eq!(bytes[1], 32);

        let mut d = Dec::new(&bytes);
        assert_eq!(d.cid().unwrap(), c);
        assert!(d.end().is_ok());
    }

    #[test]
    fn an_unknown_hash_algorithm_is_refused_rather_than_guessed() {
        // A future digest arriving at a client that does not know the algorithm must be
        // rejected, not silently treated as the current one.
        let mut bytes = vec![9u8, 32];
        bytes.extend_from_slice(&[0u8; 32]);
        let mut d = Dec::new(&bytes);
        assert_eq!(d.cid(), Err(DecodeError::UnknownTag(9)));

        // A length that disagrees with the algorithm's own is equally refused.
        assert!(Cid::from_parts(HashAlg::Blake3 as u8, &[0u8; 16]).is_none());
        assert!(Cid::from_parts(HashAlg::Blake3 as u8, &[0u8; 64]).is_none());
    }

    fn rotate(old: &Identity, new: &Identity, lin: &mut Lineage) {
        lin.insert(Rotation::forward(old, &new.key_bytes(), 0).unwrap())
            .unwrap();
        lin.insert(Rotation::backward(new, &old.key_bytes(), 0).unwrap())
            .unwrap();
    }

    #[test]
    fn a_countersigned_rotation_lets_an_identity_move() {
        let old = Identity::generate();
        let new = Identity::generate();
        let mut lin = Lineage::new();

        let v1 = Object::create(&old, "page", 0, b"before".to_vec(), None);
        let c1 = lin.insert(v1).unwrap();

        rotate(&old, &new, &mut lin);
        assert_eq!(lin.rotations().len(), 1);
        assert_eq!(lin.current_identity(old.address()), new.address());

        // The new key continues the old key's series.
        let v2 = Object::create(&new, "page", 1, b"after".to_vec(), Some(c1));
        let c2 = lin.insert(v2).unwrap();

        assert_eq!(lin.successors(&c1), vec![c2]);
        assert_eq!(lin.resolve(&c1), Resolution::Head(c2));
        assert_eq!(lin.history(&c2).len(), 2);
    }

    /// **Both halves are required.** A one-sided claim proves nothing, and each direction
    /// alone enables a different attack.
    #[test]
    fn a_one_sided_rotation_claim_moves_nothing() {
        let old = Identity::generate();
        let attacker = Identity::generate();

        // Forward only: a compromised old key tries to hand identity to an attacker.
        let mut lin = Lineage::new();
        let c1 = lin
            .insert(Object::create(&old, "page", 0, b"before".to_vec(), None))
            .unwrap();
        lin.insert(Rotation::forward(&old, &attacker.key_bytes(), 0).unwrap())
            .unwrap();
        assert!(lin.rotations().is_empty(), "forward half alone was accepted");
        lin.insert(Object::create(&attacker, "page", 1, b"seized".to_vec(), Some(c1)))
            .unwrap();
        assert!(lin.successors(&c1).is_empty());
        assert_eq!(lin.resolve(&c1), Resolution::Head(c1));

        // Backward only: anyone claims to be anyone's successor.
        let mut lin2 = Lineage::new();
        let d1 = lin2
            .insert(Object::create(&old, "page", 0, b"before".to_vec(), None))
            .unwrap();
        lin2.insert(Rotation::backward(&attacker, &old.key_bytes(), 0).unwrap())
            .unwrap();
        assert!(lin2.rotations().is_empty(), "backward half alone was accepted");
        lin2.insert(Object::create(&attacker, "page", 1, b"claimed".to_vec(), Some(d1)))
            .unwrap();
        assert!(lin2.successors(&d1).is_empty());
    }

    #[test]
    fn a_rotation_between_two_other_parties_does_not_help_an_attacker() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let attacker = Identity::generate();
        let mut lin = Lineage::new();

        let c1 = lin
            .insert(Object::create(&alice, "page", 0, b"alice".to_vec(), None))
            .unwrap();
        // A perfectly valid rotation, between two parties who are not Alice.
        rotate(&bob, &carol, &mut lin);

        lin.insert(Object::create(&attacker, "page", 1, b"hijack".to_vec(), Some(c1)))
            .unwrap();
        assert!(lin.successors(&c1).is_empty());
        assert_eq!(
            lin.rejected_edges(&c1)[0].1,
            "different author, no countersigned rotation"
        );
    }

    #[test]
    fn rotations_chain_and_do_not_loop() {
        let a = Identity::generate();
        let b = Identity::generate();
        let c = Identity::generate();
        let mut lin = Lineage::new();

        rotate(&a, &b, &mut lin);
        rotate(&b, &c, &mut lin);
        assert_eq!(lin.current_identity(a.address()), c.address());
        assert_eq!(lin.current_identity(c.address()), c.address());

        // A cycle terminates rather than hanging.
        rotate(&c, &a, &mut lin);
        let _ = lin.current_identity(a.address());
    }

    #[test]
    fn an_address_with_no_rotation_resolves_to_itself() {
        let a = Identity::generate();
        let lin = Lineage::new();
        assert_eq!(lin.current_identity(a.address()), a.address());
    }

    #[test]
    fn a_stranger_cannot_hijack_someone_elses_version_series() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mut lin = Lineage::new();

        let v1 = Object::create(&alice, "page", 0, b"alice's page".to_vec(), None);
        let c1 = lin.insert(v1).unwrap();

        // Bob signs a perfectly valid object claiming to supersede Alice's.
        let hijack = Object::create(&bob, "page", 1, b"bob's replacement".to_vec(), Some(c1));
        let hijack_cid = lin.insert(hijack).unwrap();

        assert!(lin.successors(&c1).is_empty(), "hijack became a successor");
        assert_eq!(
            lin.resolve(&c1),
            Resolution::Head(c1),
            "Alice's page is still the head of her own series"
        );
        assert!(lin.equivocations().is_empty(), "Alice was blamed for Bob's object");

        // The attempt is visible rather than silently discarded.
        assert_eq!(
            lin.rejected_edges(&c1),
            vec![(hijack_cid, "different author, no countersigned rotation")]
        );
    }

    #[test]
    fn edges_must_stay_in_the_same_series_and_advance() {
        let alice = Identity::generate();
        let mut lin = Lineage::new();
        let v1 = Object::create(&alice, "page", 5, b"v1".to_vec(), None);
        let c1 = lin.insert(v1).unwrap();

        // Same author, different kind.
        lin.insert(Object::create(&alice, "note", 6, b"x".to_vec(), Some(c1)))
            .unwrap();
        // Same author, same kind, sequence went backwards.
        lin.insert(Object::create(&alice, "page", 4, b"y".to_vec(), Some(c1)))
            .unwrap();
        // Same author, same kind, sequence did not move.
        lin.insert(Object::create(&alice, "page", 5, b"z".to_vec(), Some(c1)))
            .unwrap();

        assert!(lin.successors(&c1).is_empty());
        assert_eq!(lin.rejected_edges(&c1).len(), 3);

        // A legitimate update is still accepted.
        let good = Object::create(&alice, "page", 6, b"real v2".to_vec(), Some(c1));
        let c2 = lin.insert(good).unwrap();
        assert_eq!(lin.successors(&c1), vec![c2]);
        assert_eq!(lin.resolve(&c1), Resolution::Head(c2));
    }

    #[test]
    fn out_of_order_arrival_still_assembles_the_history() {
        let alice = Identity::generate();
        let mut lin = Lineage::new();

        let v1 = Object::create(&alice, "page", 0, b"one".to_vec(), None);
        let c1 = v1.cid();
        let v2 = Object::create(&alice, "page", 1, b"two".to_vec(), Some(c1));
        let c2 = v2.cid();
        let v3 = Object::create(&alice, "page", 2, b"three".to_vec(), Some(c2));

        // Arrive backwards, as they would from a swarm.
        lin.insert(v3).unwrap();
        lin.insert(v2).unwrap();
        lin.insert(v1).unwrap();

        assert_eq!(lin.history(&lin.resolve(&c1).head().unwrap()).len(), 3);
        assert_eq!(lin.successors(&c1), vec![c2]);
    }

    #[test]
    fn an_author_showing_two_histories_is_detectable_rather_than_silent() {
        let author = Identity::generate();
        let mut lin = Lineage::new();

        let v1 = Object::create(&author, "page", 0, b"original".to_vec(), None);
        let c1 = lin.insert(v1).unwrap();

        // The same author signs two different successors to the same version.
        let a = Object::create(&author, "page", 1, b"what I told you".to_vec(), Some(c1));
        let b = Object::create(&author, "page", 1, b"what I told them".to_vec(), Some(c1));
        let ca = lin.insert(a).unwrap();
        let cb = lin.insert(b).unwrap();

        match lin.resolve(&c1) {
            Resolution::Forked(heads) => {
                assert_eq!(heads.len(), 2);
                assert!(heads.contains(&ca) && heads.contains(&cb));
            }
            other => panic!("equivocation must not resolve silently, got {other:?}"),
        }
        assert_eq!(lin.equivocations(), vec![c1]);
    }

    #[test]
    fn holding_only_part_of_a_history_is_honest_about_it() {
        // Availability is not a property content addressing provides. If nobody kept v1,
        // v1 is gone, and the store says so rather than inventing something.
        let author = Identity::generate();
        let mut lin = Lineage::new();
        let v1 = Object::create(&author, "page", 0, b"lost".to_vec(), None);
        let c1 = v1.cid();
        let v2 = Object::create(&author, "page", 1, b"kept".to_vec(), Some(c1));
        let c2 = lin.insert(v2).unwrap();

        assert_eq!(lin.history(&c2).len(), 1, "we hold only what we hold");
        assert_eq!(lin.resolve(&c1), Resolution::Unknown);
        assert!(lin.get(&c1).is_none());
    }

    #[test]
    fn lineage_links_versions_without_mutating_anything() {
        let author = Identity::generate();
        let v1 = Object::create(&author, "note", 0, b"draft".to_vec(), None);
        let v2 = Object::create(&author, "note", 1, b"final".to_vec(), Some(v1.cid()));
        assert_eq!(v2.supersedes, Some(v1.cid()));
        // v1 still exists, still verifies, still has its own name.
        assert!(v1.verify().is_ok());
        assert_ne!(v1.cid(), v2.cid());
    }
}
