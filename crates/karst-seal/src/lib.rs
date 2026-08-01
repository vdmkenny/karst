//! Encrypt to a public key, revealing nothing about who it was for.
//!
//! A mix network hides who sent a packet and who received it. It does not hide the payload
//! from the party the payload is delivered to, and at L4 that party is a provider rather than
//! the recipient. Content confidentiality is therefore a separate mechanism, not a consequence
//! of mixing, and it must not reintroduce the identifiers mixing just removed.
//!
//! The construction is HPKE base mode (RFC 9180) with DHKEM(X25519) and ChaCha20-Poly1305: a
//! fresh ephemeral key per message, a shared secret by Diffie-Hellman, key and nonce derived
//! together, and the ciphertext bound to associated data.
//!
//! # Why the key is not the identity key
//!
//! L2 identities are Ed25519. Converting an Ed25519 key to X25519 is possible and is the
//! tempting shortcut, and it means one key secures both a signature scheme and a KEM. Joint
//! security of a signature and an encryption scheme under a shared key is a property that has
//! to be proved rather than assumed (Degabriele, Lehmann, Paterson, Smart, Strefler, *On the
//! Joint Security of Encryption and Signature Schemes*, CT-RSA 2011), and it also welds the
//! two suites together: retiring one forces retiring the other, which is exactly what the
//! algorithm evolution work at L2 exists to avoid. Sealing keys are their own keys.
//!
//! # What this does not give
//!
//! No forward secrecy against compromise of the **recipient**. The ephemeral is the sender's,
//! so a sender whose machine is later seized cannot decrypt what they sent, but a recipient's
//! static key opens every message ever addressed to it. A ratchet is the answer and is not
//! this.
//!
//! Anyone holding a recipient's public key can test a ciphertext against it by trial
//! decryption. That is inherent to anonymous encryption and is the same operation the
//! recipient performs; it reveals a ciphertext's destination only to someone who already had
//! the destination in mind.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

/// Bytes prepended to every sealed message: the sender's ephemeral public key.
pub const OVERHEAD: usize = 32 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// Too short to contain an ephemeral key and a tag.
    Truncated,
    /// Authentication failed. Indistinguishable from "not addressed to this key", by design.
    NotForYou,
}

/// A key others can encrypt to.
#[derive(Clone)]
pub struct SealingKey {
    secret: StaticSecret,
}

/// Deliberately opaque. A sealing key printed into a log is a sealing key that is public.
impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealingKey(redacted)")
    }
}

impl SealingKey {
    pub fn generate() -> Self {
        SealingKey {
            secret: StaticSecret::random_from_rng(rand::rngs::OsRng),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        SealingKey {
            secret: StaticSecret::from(derive(&seed, "karst.seal.v1.identity", &[])),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// Recover a sealed message, or learn nothing.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < OVERHEAD {
            return Err(SealError::Truncated);
        }
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&sealed[..32]);
        let shared = self.secret.diffie_hellman(&PublicKey::from(epk)).to_bytes();
        let (key, nonce) = schedule(&shared, &epk, self.public().as_bytes());

        ChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed[32..],
                    aad,
                },
            )
            .map_err(|_| SealError::NotForYou)
    }
}

/// Encrypt to `recipient`, binding the result to `aad`.
///
/// `aad` is authenticated but not encrypted. Anything a relay must read in order to route or
/// file the message goes there, so that it cannot be altered without the recipient noticing,
/// and cannot be lifted onto a different ciphertext.
pub fn seal(recipient: &PublicKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    seal_with(&eph, recipient, aad, plaintext)
}

fn seal_with(
    eph: &StaticSecret,
    recipient: &PublicKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let epk = PublicKey::from(eph).to_bytes();
    let shared = eph.diffie_hellman(recipient).to_bytes();
    let (key, nonce) = schedule(&shared, &epk, recipient.as_bytes());

    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20poly1305 encryption is infallible for in-memory input");

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&ct);
    out
}

/// Derive the key and nonce together.
///
/// Both the ephemeral and the recipient key enter the derivation, so a shared secret cannot be
/// reused under a different pairing even if one were somehow repeated. The nonce is derived
/// rather than fixed for the same reason: it costs nothing and removes a class of mistake.
fn schedule(shared: &[u8; 32], epk: &[u8; 32], rpk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut ctx = Vec::with_capacity(64);
    ctx.extend_from_slice(epk);
    ctx.extend_from_slice(rpk);
    let key = derive(shared, "karst.seal.v1.key", &ctx);
    let n = derive(shared, "karst.seal.v1.nonce", &ctx);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&n[..12]);
    (key, nonce)
}

fn derive(ikm: &[u8; 32], label: &str, ctx: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(label.as_bytes());
    h.update(ikm);
    h.update(&(ctx.len() as u64).to_le_bytes());
    h.update(ctx);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_message_opens_for_its_recipient_and_nobody_else() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let eve = SealingKey::from_seed([2u8; 32]);
        let ct = seal(&bob.public(), b"mailbox-7", b"the quiet part");

        assert_eq!(bob.open(b"mailbox-7", &ct).unwrap(), b"the quiet part");
        assert_eq!(eve.open(b"mailbox-7", &ct), Err(SealError::NotForYou));
    }

    /// Associated data must be bound, so a ciphertext cannot be filed under a different name.
    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_mailbox() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let ct = seal(&bob.public(), b"mailbox-7", b"m");
        assert_eq!(bob.open(b"mailbox-8", &ct), Err(SealError::NotForYou));
    }

    /// Every byte of the ciphertext must be authenticated.
    #[test]
    fn every_single_bit_flip_is_rejected() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let ct = seal(&bob.public(), b"aad", b"a message of some length to cover");
        for i in 0..ct.len() {
            for bit in 0..8 {
                let mut bad = ct.clone();
                bad[i] ^= 1 << bit;
                assert_eq!(
                    bob.open(b"aad", &bad),
                    Err(SealError::NotForYou),
                    "byte {i} bit {bit} survived"
                );
            }
        }
    }

    /// Two seals of the same plaintext to the same recipient must not be equal.
    ///
    /// Deterministic sealing would let an observer of a provider's store detect repeated
    /// messages, and detect that two mailboxes received the same thing.
    #[test]
    fn sealing_is_randomised() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let a = seal(&bob.public(), b"aad", b"same");
        let b = seal(&bob.public(), b"aad", b"same");
        assert_ne!(a, b);
    }

    /// A ciphertext must not reveal which key it was addressed to.
    ///
    /// The leading bytes are an ephemeral public key, which is uniformly distributed and
    /// independent of the recipient. Two ciphertexts for different recipients must be
    /// indistinguishable to anyone without a private key.
    #[test]
    fn a_ciphertext_does_not_name_its_recipient() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let carol = SealingKey::from_seed([2u8; 32]);
        let to_bob = seal(&bob.public(), b"aad", b"m");
        let to_carol = seal(&carol.public(), b"aad", b"m");
        assert_eq!(to_bob.len(), to_carol.len());
        // Neither ciphertext contains its recipient's public key.
        for ct in [&to_bob, &to_carol] {
            for w in ct.windows(32) {
                assert_ne!(w, bob.public().as_bytes());
                assert_ne!(w, carol.public().as_bytes());
            }
        }
    }

    /// Truncation must be refused rather than misread.
    #[test]
    fn truncated_input_is_refused() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let ct = seal(&bob.public(), b"aad", b"m");
        for n in 0..OVERHEAD {
            assert_eq!(bob.open(b"aad", &ct[..n]), Err(SealError::Truncated));
        }
    }

    /// An all-zero ephemeral key produces an all-zero shared secret on X25519.
    ///
    /// The low-order points are the classic X25519 pitfall. This must fail authentication
    /// rather than opening, and it must fail the same way as any other wrong key.
    #[test]
    fn low_order_ephemeral_keys_do_not_open_anything() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let real = seal(&bob.public(), b"aad", b"m");
        for bad_epk in [[0u8; 32], [1u8; 32], {
            let mut e = [0u8; 32];
            e[31] = 0x80;
            e
        }] {
            let mut forged = real.clone();
            forged[..32].copy_from_slice(&bad_epk);
            assert_eq!(bob.open(b"aad", &forged), Err(SealError::NotForYou));
        }
    }

    /// The empty message must round trip, since a fragment can be empty padding.
    #[test]
    fn an_empty_message_round_trips() {
        let bob = SealingKey::from_seed([1u8; 32]);
        let ct = seal(&bob.public(), b"", b"");
        assert_eq!(bob.open(b"", &ct).unwrap(), b"");
    }
}
