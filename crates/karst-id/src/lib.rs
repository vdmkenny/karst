//! KARST L2 Identity.
//!
//! An address is the BLAKE3 hash of a locally generated Ed25519 public key.
//!
//! There is no registration step and nobody to register with, so there is no roll of
//! participants for anyone to seize, publish, or be compelled to produce. This is the
//! layer that fixes error 01 (location used as identity) at the packet level: an
//! address says who you are and says nothing whatsoever about where you are.
//!
//! Everything here is self-certifying. Given a public key you can derive its address
//! and check it matches, with no directory, no authority, and no lookup. That property
//! is what lets capability chains in `karst-cap` verify offline.

use core::fmt;

pub use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand::rngs::OsRng;

/// Length of an address in bytes.
pub const ADDR_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The signature did not verify against the claimed key.
    BadSignature,
    /// The supplied public key was not a valid Ed25519 point.
    MalformedKey,
    /// The address did not match the hash of the supplied key.
    AddressMismatch,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::BadSignature => write!(f, "signature did not verify"),
            IdError::MalformedKey => write!(f, "malformed public key"),
            IdError::AddressMismatch => write!(f, "address does not match key"),
        }
    }
}

impl std::error::Error for IdError {}

/// A KARST address: the hash of a public key.
///
/// Copy, comparable, and orderable so it can be used as a map key throughout.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; ADDR_LEN]);

/// Decode a verifying key, refusing the ones that are not really keys.
///
/// `VerifyingKey::from_bytes` decompresses the point and stops there, so it accepts the
/// small-order elements. `ed25519-dalek`'s own documentation says a weak key "can be used to
/// generate a signature that's valid for almost every message", which makes accepting one at
/// the identity layer a way to mint an address whose signatures mean nothing.
///
/// Refused at the door, so no such key is ever inside an `Address` or a `Peer`.
fn decode_key(bytes: &[u8; 32]) -> Result<VerifyingKey, IdError> {
    let vk = VerifyingKey::from_bytes(bytes).map_err(|_| IdError::MalformedKey)?;
    if vk.is_weak() {
        return Err(IdError::MalformedKey);
    }
    Ok(vk)
}

impl Address {
    pub fn from_key(vk: &VerifyingKey) -> Self {
        Address(*blake3::hash(vk.as_bytes()).as_bytes())
    }

    pub fn from_key_bytes(bytes: &[u8; 32]) -> Result<Self, IdError> {
        Ok(Address::from_key(&decode_key(bytes)?))
    }

    pub fn as_bytes(&self) -> &[u8; ADDR_LEN] {
        &self.0
    }

    /// Reconstruct an address from its raw bytes, for decoding. This does not and cannot
    /// prove a key exists behind it; use [`Address::from_key_bytes`] where the key is
    /// available.
    pub fn from_raw(bytes: [u8; ADDR_LEN]) -> Self {
        Address(bytes)
    }

    /// Short form for human-facing output. Never use this for comparison.
    pub fn short(&self) -> String {
        format!("k:{}", hex::encode(&self.0[..5]))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "k:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.short())
    }
}

/// A keypair. Holds secret material, so it never crosses the wire and never
/// appears in a serialised object.
pub struct Identity {
    signing: SigningKey,
    address: Address,
}

impl Identity {
    /// Generate a fresh identity. This is the entire account creation flow.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let address = Address::from_key(&signing.verifying_key());
        Identity { signing, address }
    }

    /// Deterministic identity from a 32 byte seed. Test and demo use only.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let address = Address::from_key(&signing.verifying_key());
        Identity { signing, address }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// The public half, safe to hand to anyone.
    pub fn peer(&self) -> Peer {
        Peer {
            vk: self.signing.verifying_key(),
            address: self.address,
        }
    }
}

/// The public half of an identity.
#[derive(Clone)]
pub struct Peer {
    vk: VerifyingKey,
    address: Address,
}

impl Peer {
    pub fn from_key_bytes(bytes: &[u8; 32]) -> Result<Self, IdError> {
        let vk = decode_key(bytes)?;
        Ok(Peer {
            address: Address::from_key(&vk),
            vk,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn key_bytes(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }

    /// Verify a signature, strictly.
    ///
    /// `verify_strict` rather than `verify`. The difference is not a matter of taste: the
    /// permissive equation is cofactorless and accepts small-order components, so a signature
    /// can verify under more than one key and a weak key produces signatures valid for almost
    /// any message. Chalkias, Garillot and Nikolaenko (*Taming the Many EdDSAs*, SSR 2020)
    /// catalogue the resulting divergence between implementations; ZIP-215 is the same
    /// question answered for a deployed system.
    ///
    /// This layer is what every other layer names things with, so a signature that means two
    /// things here means two things everywhere.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), IdError> {
        self.vk
            .verify_strict(msg, sig)
            .map_err(|_| IdError::BadSignature)
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Peer({})", self.address.short())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer;

    /// A small-order key is not an identity, and is refused before it becomes one.
    ///
    /// `VerifyingKey::from_bytes` decompresses and stops, so it accepts these. dalek's own
    /// documentation on `is_weak` says such a key "can be used to generate a signature that's
    /// valid for almost every message", which at the identity layer means an address whose
    /// signatures carry no information.
    #[test]
    fn a_weak_key_cannot_become_an_identity() {
        // The eight small-order points on edwards25519, from RFC 8032 and the dalek tests.
        let weak: [[u8; 32]; 7] = [
            [0u8; 32],
            {
                let mut b = [0u8; 32];
                b[0] = 1;
                b
            },
            hex32("0000000000000000000000000000000000000000000000000000000000000080"),
            hex32("0100000000000000000000000000000000000000000000000000000000000080"),
            hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
            hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
            hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];
        let mut refused = 0;
        for k in weak {
            if ed25519_dalek::VerifyingKey::from_bytes(&k).is_ok() {
                assert_eq!(
                    Peer::from_key_bytes(&k).err(),
                    Some(IdError::MalformedKey),
                    "a decodable weak key was accepted as a peer"
                );
                assert!(Address::from_key_bytes(&k).is_err());
                refused += 1;
            }
        }
        assert!(refused > 0, "no weak key decoded, so this test proved nothing");
    }

    /// An honest key is still accepted, so the check above is not simply refusing everything.
    #[test]
    fn an_ordinary_key_still_verifies() {
        let id = Identity::from_seed([5u8; 32]);
        let peer = Peer::from_key_bytes(&id.key_bytes()).expect("an ordinary key");
        let sig = id.sign(b"hello");
        assert!(peer.verify(b"hello", &sig).is_ok());
        assert!(peer.verify(b"goodbye", &sig).is_err());
    }

    /// A tampered signature is refused.
    ///
    /// This does **not** exercise the difference between `verify` and `verify_strict`: a
    /// substituted R fails the recomputation check under either equation, so the test passes
    /// with strictness removed. Distinguishing the two needs a signature that satisfies the
    /// cofactorless equation while carrying a small-order component, which means a known
    /// answer vector from Chalkias, Garillot and Nikolaenko rather than one constructed here.
    ///
    /// What is directly tested is the half that matters most at this layer and that is
    /// mutation-verified: a weak key never becomes an identity, so the keys `verify_strict`
    /// exists to catch cannot enter in the first place.
    #[test]
    fn a_tampered_signature_is_refused() {
        let id = Identity::from_seed([6u8; 32]);
        let peer = Peer::from_key_bytes(&id.key_bytes()).unwrap();
        let sig = id.sign(b"m");

        let mut raw = sig.to_bytes();
        raw[..32].copy_from_slice(&hex32(
            "0100000000000000000000000000000000000000000000000000000000000080",
        ));
        assert!(peer.verify(b"m", &Signature::from_bytes(&raw)).is_err());
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    use super::*;

    #[test]
    fn address_is_derived_from_key_with_no_registration() {
        let id = Identity::generate();
        let derived = Address::from_key_bytes(&id.key_bytes()).unwrap();
        assert_eq!(id.address(), derived, "address must be self-certifying");
    }

    #[test]
    fn signatures_verify_and_tampering_fails() {
        let id = Identity::generate();
        let sig = id.sign(b"the packet");
        assert!(id.peer().verify(b"the packet", &sig).is_ok());
        assert_eq!(
            id.peer().verify(b"the pocket", &sig),
            Err(IdError::BadSignature)
        );
    }

    #[test]
    fn distinct_identities_get_distinct_addresses() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn a_stranger_cannot_forge_as_someone_else() {
        let real = Identity::generate();
        let impostor = Identity::generate();
        let sig = impostor.sign(b"pay to the order of");
        assert!(real.peer().verify(b"pay to the order of", &sig).is_err());
    }
}
