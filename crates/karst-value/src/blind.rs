//! Blind signatures: the issuer signs what it cannot read.
//!
//! Issue #43. Unlinkability here is a cryptographic guarantee rather than an argument about
//! what a well-behaved implementation passes around. Chaum's construction, standardised as
//! RFC 9474:
//!
//! ```text
//!   blind    b = m · r^e  mod n        holder picks r, issuer cannot recover m
//!   sign     s' = b^d     mod n        issuer signs without reading
//!   unblind  s = s' · r⁻¹ mod n        holder recovers a signature on m
//!   verify   s^e == m     mod n        anyone checks, against the public key alone
//! ```
//!
//! The property that matters is **perfect blinding**: because `r ↦ r^e` is a bijection modulo
//! `n`, every message `m` has exactly one `r` producing any given `b`. A blinded value is
//! therefore consistent with every message, and the issuer's view carries no information about
//! which one it signed.
//!
//! # The implementation is the specification's
//!
//! The scheme is `blind-rsa-signatures`, variant **RSABSSA-SHA384-PSS-Randomized**, the RFC
//! 9474 default. Nothing in this module performs a modular exponentiation, generates a key, or
//! chooses a blinding factor.
//!
//! That division is the point. A blind signature is a scheme where the distance between
//! correct and catastrophic is invisible on inspection: a blinding factor drawn from a
//! predictable source turns information-theoretic unlinkability into an offline search, and the
//! party best placed to run that search is the issuer, which is the party blinding defends
//! against. Randomness comes from the operating system. The only decisions left here are which
//! variant to use and what a credential is bound to.
//!
//! Two consequences of the variant, stated because they are choices:
//!
//! - **PSS rather than full-domain hash.** An unblinded signature verifies with a stock
//!   RSA-PSS verifier, so a verifier needs no code from this repository.
//! - **Randomized rather than deterministic.** The holder mixes 32 bytes of its own randomness
//!   into the encoded message, which removes the issuer's influence over the exact bytes
//!   signed. The randomizer travels with the credential and is not a secret.
//!
//! # On threshold issuance, and a correction
//!
//! The credential design took threshold issuance to be required by error 03, on the grounds
//! that a single issuer is a singleton. That conflates two different properties:
//!
//! - **Plurality of issuer sets** is what error 03 demands. Anyone may run an issuer, many
//!   coexist, and no global one must be used. That is satisfied by there being no registry of
//!   issuers, exactly as L8 has no registry of logs.
//! - **Threshold within a set** protects one set against a member being compromised or
//!   compelled. Valuable, and a different concern.
//!
//! RSA blind signatures give plurality and public verifiability and lose
//! threshold-within-a-set. Recovering it needs Coconut over a pairing curve, or threshold RSA.
//! The `shamir` module carries the threshold structure and the two are not composed.

use blind_rsa_signatures::{
    BlindSignature as RawBlindSignature, BlindingResult, DefaultRng, KeyPairSha384PSSRandomized as Suite,
    MessageRandomizer, PublicKeySha384PSSRandomized as SuitePublic,
    SecretKeySha384PSSRandomized as SuiteSecret, Signature as RawSignature,
};

/// Modulus size for a credential issuer.
///
/// RFC 9474 requires at least 2048 bits, and this is not a parameter worth tuning down: an
/// issuer that chooses less has saved nothing a credential system values.
pub const ISSUER_BITS: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindError {
    /// Key generation failed. Retried rather than worked around.
    KeyGeneration,
    /// The issuer's signature does not correspond to the blinded value it was given.
    BadSignature,
    /// The credential does not verify under this issuer's key.
    NotValid,
    /// A key or signature was not well formed.
    Malformed,
}

impl core::fmt::Display for BlindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlindError::KeyGeneration => write!(f, "issuer key generation failed"),
            BlindError::BadSignature => write!(f, "issuer signature does not match the request"),
            BlindError::NotValid => write!(f, "credential does not verify"),
            BlindError::Malformed => write!(f, "malformed key or signature"),
        }
    }
}

impl std::error::Error for BlindError {}

/// An issuer's signing key.
pub struct IssuerKey {
    secret: SuiteSecret,
    public: SuitePublic,
}

/// Deliberately opaque. An issuing key in a log is an issuing key that mints for everyone.
impl core::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IssuerKey(redacted)")
    }
}

/// What an issuer publishes. A credential verifies against this and nothing else.
#[derive(Clone, Debug)]
pub struct IssuerPublic {
    inner: SuitePublic,
}

impl IssuerKey {
    /// Generate an issuing key from the system randomness the scheme's own crate supplies.
    ///
    /// There is no seeded constructor, deliberately. A seeded issuer key has as much entropy
    /// as its seed, and the wish for reproducible tests is exactly how that gets introduced.
    pub fn generate(bits: usize) -> Result<IssuerKey, BlindError> {
        let kp =
            Suite::generate(&mut DefaultRng, bits).map_err(|_| BlindError::KeyGeneration)?;
        Ok(IssuerKey {
            secret: kp.sk,
            public: kp.pk,
        })
    }

    pub fn public(&self) -> IssuerPublic {
        IssuerPublic {
            inner: self.public.clone(),
        }
    }

    /// Sign a blinded value, learning nothing about what it is.
    pub fn sign_blinded(&self, blinded: &BlindedMessage) -> Result<BlindSignature, BlindError> {
        let sig = self
            .secret
            .blind_sign(&blinded.bytes)
            .map_err(|_| BlindError::Malformed)?;
        Ok(BlindSignature { inner: sig })
    }
}

impl IssuerPublic {
    /// Check a credential against this issuer alone.
    ///
    /// Public verifiability is what separates this from a symmetric tag: a verifier needs no
    /// secret, so a verifier cannot forge.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), BlindError> {
        self.inner
            .verify(&sig.inner, Some(sig.randomizer), msg)
            .map_err(|_| BlindError::NotValid)
    }

    /// The issuer's identity as bytes, for binding a credential to the set that issued it.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_der().unwrap_or_default()
    }
}

/// What the holder sends. Carries no information about the message.
pub struct BlindedMessage {
    bytes: Vec<u8>,
}

impl BlindedMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl core::fmt::Debug for BlindedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BlindedMessage(..)")
    }
}

/// What the holder keeps back. Never sent.
pub struct Blinding {
    result: BlindingResult,
}

impl core::fmt::Debug for Blinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Blinding(redacted)")
    }
}

/// The issuer's output, still blinded.
pub struct BlindSignature {
    inner: RawBlindSignature,
}

impl core::fmt::Debug for BlindSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BlindSignature(..)")
    }
}

/// A credential: a signature on a message the issuer never saw.
#[derive(Clone)]
pub struct Signature {
    inner: RawSignature,
    /// The holder's contribution to the encoded message. Public, and travels with the
    /// signature, so a verifier can reconstruct what was signed.
    randomizer: MessageRandomizer,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.randomizer.0.to_vec();
        v.extend_from_slice(self.inner.as_ref());
        v
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Signature(..)")
    }
}

/// Blind a message for issuance.
///
/// The blinding factor comes from the system CSPRNG, through the scheme's own default. It is
/// the single value unlinkability rests on, and the party it hides from is the party best
/// placed to search for it.
pub fn blind(pk: &IssuerPublic, msg: &[u8]) -> Result<(BlindedMessage, Blinding), BlindError> {
    let result = pk
        .inner
        .blind(&mut DefaultRng, msg)
        .map_err(|_| BlindError::Malformed)?;
    Ok((
        BlindedMessage {
            bytes: result.blind_message.0.clone(),
        },
        Blinding { result },
    ))
}

/// Recover a credential, checking the issuer's work before accepting it.
///
/// Verification happens here rather than at spending time. A holder who discovered a bad
/// credential when a verifier refused it would be identified at exactly the moment anonymity
/// matters, so a malicious issuer has to fail at issuance instead.
pub fn unblind(
    pk: &IssuerPublic,
    msg: &[u8],
    blinding: &Blinding,
    sig: &BlindSignature,
) -> Result<Signature, BlindError> {
    let inner = pk
        .inner
        .finalize(&sig.inner, &blinding.result, msg)
        .map_err(|_| BlindError::BadSignature)?;
    let randomizer = blinding.result.msg_randomizer.ok_or(BlindError::Malformed)?;
    Ok(Signature { inner, randomizer })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Key generation at 2048 bits is slow, so the suite shares one issuer.
    fn issuer() -> &'static IssuerKey {
        use std::sync::OnceLock;
        static K: OnceLock<IssuerKey> = OnceLock::new();
        K.get_or_init(|| IssuerKey::generate(ISSUER_BITS).expect("keygen"))
    }

    fn credential(k: &IssuerKey, msg: &[u8]) -> Signature {
        let pk = k.public();
        let (blinded, blinding) = blind(&pk, msg).unwrap();
        let sig = k.sign_blinded(&blinded).unwrap();
        unblind(&pk, msg, &blinding, &sig).unwrap()
    }

    #[test]
    fn a_credential_verifies_against_the_public_key_alone() {
        let k = issuer();
        let s = credential(k, b"serial-1");
        assert!(k.public().verify(b"serial-1", &s).is_ok());
    }

    #[test]
    fn a_signature_does_not_transfer_to_another_message() {
        let k = issuer();
        let s = credential(k, b"serial-1");
        assert_eq!(k.public().verify(b"serial-2", &s), Err(BlindError::NotValid));
    }

    /// The issuer sees a different value every time, so issuance carries no repetition to key
    /// on even when the same credential is requested twice.
    #[test]
    fn the_same_message_blinds_differently_every_time() {
        let pk = issuer().public();
        let (a, _) = blind(&pk, b"same").unwrap();
        let (b, _) = blind(&pk, b"same").unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    /// Recording the whole issuance exchange yields nothing spendable.
    ///
    /// The blinded value and the blinded signature are what an issuer keeps. Neither is the
    /// credential, and the step between them is the holder's alone.
    #[test]
    fn recording_the_issuance_exchange_yields_nothing_spendable() {
        let k = issuer();
        let pk = k.public();
        let (blinded, blinding) = blind(&pk, b"serial-9").unwrap();
        let blind_sig = k.sign_blinded(&blinded).unwrap();

        let seen_blinded = blinded.to_bytes();
        let seen_sig: Vec<u8> = blind_sig.inner.0.clone();

        let real = unblind(&pk, b"serial-9", &blinding, &blind_sig).unwrap();
        assert!(pk.verify(b"serial-9", &real).is_ok());

        assert_ne!(seen_sig, real.inner.0);
        assert_ne!(seen_blinded, real.to_bytes());
    }

    /// A malicious issuer is caught by the holder, at issuance.
    #[test]
    fn a_malicious_issuer_is_caught_at_unblinding_not_at_spending() {
        let k = issuer();
        let pk = k.public();
        let (_blinded, blinding) = blind(&pk, b"serial-x").unwrap();

        // A signature over something else entirely.
        let (other, _) = blind(&pk, b"unrelated").unwrap();
        let wrong = k.sign_blinded(&other).unwrap();

        assert_eq!(
            unblind(&pk, b"serial-x", &blinding, &wrong).unwrap_err(),
            BlindError::BadSignature
        );
    }

    /// A credential from one issuer does not verify under another.
    #[test]
    fn a_signature_cannot_be_moved_between_issuers() {
        let a = issuer();
        let b = IssuerKey::generate(2048).unwrap();
        let s = credential(a, b"serial-7");
        assert_eq!(b.public().verify(b"serial-7", &s), Err(BlindError::NotValid));
    }

    #[test]
    fn many_credentials_from_one_issuer_all_verify() {
        let k = issuer();
        for i in 0..4u32 {
            let m = format!("serial-{i}");
            assert!(k
                .public()
                .verify(m.as_bytes(), &credential(k, m.as_bytes()))
                .is_ok());
        }
    }

    /// Two credentials never share a randomizer, which is drawn per issuance.
    #[test]
    fn blinding_factors_do_not_repeat_across_credentials() {
        let k = issuer();
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..8u32 {
            let m = format!("serial-{i}");
            assert!(seen.insert(credential(k, m.as_bytes()).randomizer.0));
        }
    }

    /// There is no way to ask for a predictable key or a predictable blinding factor.
    ///
    /// A seeded path here is a total break dressed as a convenience: an issuer key or a
    /// blinding factor with 64 bits of entropy reduces unlinkability to an offline search the
    /// issuer can run. This pins the API shape, which is the thing that would have to change
    /// for the break to come back.
    #[test]
    fn there_is_no_way_to_ask_for_a_predictable_key() {
        let _: fn(usize) -> Result<IssuerKey, BlindError> = IssuerKey::generate;
        let _: fn(&IssuerPublic, &[u8]) -> Result<(BlindedMessage, Blinding), BlindError> = blind;
    }
}
