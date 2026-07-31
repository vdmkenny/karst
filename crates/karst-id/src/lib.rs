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

impl Address {
    pub fn from_key(vk: &VerifyingKey) -> Self {
        Address(*blake3::hash(vk.as_bytes()).as_bytes())
    }

    pub fn from_key_bytes(bytes: &[u8; 32]) -> Result<Self, IdError> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|_| IdError::MalformedKey)?;
        Ok(Address::from_key(&vk))
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
        let vk = VerifyingKey::from_bytes(bytes).map_err(|_| IdError::MalformedKey)?;
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

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), IdError> {
        self.vk.verify(msg, sig).map_err(|_| IdError::BadSignature)
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Peer({})", self.address.short())
    }
}

#[cfg(test)]
mod tests {
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
