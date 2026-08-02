//! Encrypt to a public key, revealing nothing about who it was for.
//!
//! A mix network hides who sent a packet and who received it. It does not hide the payload
//! from the party the payload is delivered to, and at L4 that party is a provider rather than
//! the recipient. Content confidentiality is therefore a separate mechanism, not a consequence
//! of mixing, and it must not reintroduce the identifiers mixing just removed.
//!
//! The construction is HPKE base mode, RFC 9180, ciphersuite
//! DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305, as implemented by the `hpke`
//! crate. A fresh encapsulation per message, and the ciphertext bound to associated data.
//!
//! # Why the standard rather than the shape of it
//!
//! This module used to say "HPKE base mode (RFC 9180)" over a key schedule written here: a
//! BLAKE3 derivation of a key and a nonce from the raw Diffie-Hellman output. That
//! construction was defensible and it was not RFC 9180, so the citation was decoration. It
//! also skipped what the RFC's schedule is *for*: `ExtractAndExpand` over a labelled
//! `suite_id`, domain separation between the KEM and the key schedule, and a base nonce
//! XORed with a sequence number rather than a nonce derived once and reused per context.
//!
//! Nothing here was known to be broken. That is the wrong bar: a construction nobody has
//! analysed is not the same as one that has been, and the RFC is the analysed one. The
//! primitive is now the specification, verified against the RFC's own test vectors by the
//! crate that implements it, and the only cryptography in this file is the choice of
//! ciphersuite.
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

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use x25519_dalek::PublicKey;

type Kem = X25519HkdfSha256;

/// Binds every ciphertext to this protocol and version.
///
/// RFC 9180's `info` is the application's own domain separation. Without it a ciphertext
/// produced by any other HPKE application against the same key would decrypt here.
const INFO: &[u8] = b"karst.seal.v2";

/// Bytes prepended to every sealed message: the encapsulated key, then the AEAD tag.
pub const OVERHEAD: usize = 32 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// Too short to contain an encapsulated key and a tag.
    Truncated,
    /// Authentication failed. Indistinguishable from "not addressed to this key", by design.
    NotForYou,
}

/// A key others can encrypt to.
#[derive(Clone)]
pub struct SealingKey {
    secret: <Kem as KemTrait>::PrivateKey,
    public: <Kem as KemTrait>::PublicKey,
}

/// Deliberately opaque. A sealing key printed into a log is a sealing key that is public.
impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealingKey(redacted)")
    }
}

impl SealingKey {
    pub fn generate() -> Self {
        let (secret, public) = Kem::gen_keypair();
        SealingKey { secret, public }
    }

    /// Derive a key from a seed, by the KEM's own `DeriveKeyPair` rather than by treating the
    /// seed as a scalar. RFC 9180 §7.1.3 specifies that derivation; doing it any other way
    /// here would be the same mistake this module just stopped making.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (secret, public) = Kem::derive_keypair(&seed);
        SealingKey { secret, public }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from(<[u8; 32]>::try_from(self.public.to_bytes().as_slice()).expect("32 bytes"))
    }

    /// Recover a sealed message, or learn nothing.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < OVERHEAD {
            return Err(SealError::Truncated);
        }
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed[..32])
            .map_err(|_| SealError::NotForYou)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &self.secret,
            &encapped,
            INFO,
            &sealed[32..],
            aad,
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
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient.as_bytes())
        .expect("an X25519 public key is a valid HPKE public key");
    let (encapped, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        INFO,
        plaintext,
        aad,
    )
    .expect("HPKE sealing is infallible for in-memory input");

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(&encapped.to_bytes());
    out.extend_from_slice(&ct);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ciphersuite is a decision, so it is pinned rather than left to whatever compiles.
    ///
    /// RFC 9180 identifiers: KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001 HKDF-SHA256,
    /// AEAD 0x0003 ChaCha20Poly1305. A silent change here is a change to what every stored
    /// ciphertext was encrypted under.
    #[test]
    fn the_ciphersuite_is_the_one_this_module_documents() {
        use hpke::aead::Aead as AeadTrait;
        use hpke::kdf::Kdf as KdfTrait;
        assert_eq!(<Kem as KemTrait>::KEM_ID, 0x0020);
        assert_eq!(<HkdfSha256 as KdfTrait>::KDF_ID, 0x0001);
        assert_eq!(<ChaCha20Poly1305 as AeadTrait>::AEAD_ID, 0x0003);
    }

    /// A ciphertext from another HPKE application must not open here.
    ///
    /// RFC 9180's `info` is the application's domain separation, and it is the one part of
    /// the construction the RFC leaves to the caller. Omitting it would mean any other
    /// application's ciphertext to the same key decrypts as ours.
    #[test]
    fn a_ciphertext_from_another_application_does_not_open() {
        let k = SealingKey::from_seed([4u8; 32]);
        let pk = <Kem as KemTrait>::PublicKey::from_bytes(k.public().as_bytes()).unwrap();

        let (encapped, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &pk,
            b"some.other.application",
            b"not for karst",
            b"",
        )
        .unwrap();
        let mut sealed = encapped.to_bytes().to_vec();
        sealed.extend_from_slice(&ct);

        assert_eq!(k.open(b"", &sealed), Err(SealError::NotForYou));
    }

    /// A seed derives the same key every time, through the KEM's own derivation.
    #[test]
    fn a_seed_derives_a_stable_key() {
        assert_eq!(
            SealingKey::from_seed([9u8; 32]).public().as_bytes(),
            SealingKey::from_seed([9u8; 32]).public().as_bytes()
        );
        assert_ne!(
            SealingKey::from_seed([9u8; 32]).public().as_bytes(),
            SealingKey::from_seed([10u8; 32]).public().as_bytes()
        );
    }

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
