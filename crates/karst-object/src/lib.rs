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

use karst_id::{Address, Identity, Peer, Signature};

/// A content identifier: the BLAKE3 hash of a canonical encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid([u8; 32]);

impl Cid {
    pub fn of(bytes: &[u8]) -> Self {
        Cid(*blake3::hash(bytes).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short(&self) -> String {
        format!("c:{}", hex::encode(&self.0[..5]))
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "c:{}", hex::encode(self.0))
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

    pub fn cid(&mut self, c: &Cid) -> &mut Self {
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
        let b = self.take(32)?;
        Ok(Cid(b.try_into().unwrap()))
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
