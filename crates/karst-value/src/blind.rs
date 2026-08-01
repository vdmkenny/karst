//! Blind signatures: the issuer signs what it cannot read.
//!
//! Issue #43. The credential protocol previously argued unlinkability from **data flow**:
//! issuers received `blake3(serial || blinding)` and never saw the serial, so the issuance and
//! spend transcripts shared no field. That is an argument about what a well-behaved
//! implementation passes around, not a cryptographic guarantee, and verification used the
//! issued secret so a verifier could forge credentials it never issued.
//!
//! This is the guarantee. Chaum's construction, standardised as RFC 9474:
//!
//! ```text
//!   blind    b = m · r^e  mod n        holder picks r, issuer cannot recover m
//!   sign     s' = b^d     mod n        issuer signs without reading
//!   unblind  s = s' · r⁻¹ mod n        holder recovers a signature on m
//!   verify   s^e == m     mod n        anyone checks, against the public key alone
//! ```
//!
//! The property that matters is **perfect blinding**: because `r ↦ r^e` is a bijection modulo
//! `n`, every message `m` has exactly one `r` producing any given `b`. So a blinded value is
//! consistent with *every* message, and the issuer's view carries no information about which
//! one it signed. [`tests::a_blinded_value_is_consistent_with_any_message`] demonstrates that
//! constructively rather than asserting it.
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
//! RSA blind signatures give plurality and public verifiability and lose threshold-within-a-set.
//! Recovering it needs Coconut over a pairing curve, or threshold RSA. The `shamir` module still
//! carries the threshold structure and the two are not yet composed.
//!
//! # Status
//!
//! Full-domain-hash RSA rather than RFC 9474's PSS encoding. FDH is Chaum's original and sound
//! in the random oracle model; PSS is what the RFC specifies so that the unblinded signature
//! verifies with a stock RSA-PSS library. **Assembled from primitives and not reviewed.**

use num_bigint_dig::traits::ModInverse;
use num_bigint_dig::BigUint;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Modulus size for a credential issuer. 2048 is the floor for anything real; tests use less
/// so that key generation does not dominate the suite.
pub const ISSUER_BITS: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindError {
    /// The blinding factor was not invertible modulo `n`, which is vanishingly unlikely and
    /// must be retried rather than worked around.
    BadBlinding,
    /// The signature did not verify against the public key.
    Invalid,
}

impl core::fmt::Display for BlindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlindError::BadBlinding => write!(f, "blinding factor not invertible, retry"),
            BlindError::Invalid => write!(f, "signature did not verify"),
        }
    }
}

impl std::error::Error for BlindError {}

/// An issuer's signing key. Never leaves the issuer.
pub struct IssuerKey {
    inner: RsaPrivateKey,
}

/// What a verifier needs, and all it needs. Public verifiability is the point: a verifier can
/// check a credential it did not issue and could not have issued.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuerPublic {
    inner: RsaPublicKey,
}

impl IssuerKey {
    /// Deterministic generation, so tests are reproducible. A real issuer draws from the
    /// system CSPRNG.
    pub fn generate(bits: usize, seed: u64) -> IssuerKey {
        let mut rng = StdRng::seed_from_u64(seed);
        IssuerKey {
            inner: RsaPrivateKey::new(&mut rng, bits).expect("key generation"),
        }
    }

    pub fn public(&self) -> IssuerPublic {
        IssuerPublic {
            inner: RsaPublicKey::from(&self.inner),
        }
    }

    /// Sign a blinded value. **The issuer cannot read what it is signing**, which is what
    /// makes the later spend unlinkable to this moment.
    pub fn sign_blinded(&self, blinded: &BlindedMessage) -> BlindSignature {
        let d = self.inner.d();
        let n = self.inner.n();
        BlindSignature {
            value: blinded.value.modpow(d, n),
        }
    }
}

impl IssuerPublic {
    fn n(&self) -> &BigUint {
        self.inner.n()
    }
    fn e(&self) -> &BigUint {
        self.inner.e()
    }

    /// Full-domain hash of a message into the RSA group.
    ///
    /// Expanded to twice the modulus length before reduction, so the residual bias is far
    /// below anything that matters.
    fn hash_to_group(&self, msg: &[u8]) -> BigUint {
        let n = self.n();
        let width = (n.bits() + 7) / 8;
        let mut buf = vec![0u8; width * 2];
        let mut h = blake3::Hasher::new();
        h.update(b"karst.blind.fdh.v1");
        h.update(msg);
        h.finalize_xof().fill(&mut buf);
        BigUint::from_bytes_be(&buf) % n
    }

    /// Check a signature using nothing but this public key.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), BlindError> {
        let expected = self.hash_to_group(msg);
        if sig.value.modpow(self.e(), self.n()) == expected {
            Ok(())
        } else {
            Err(BlindError::Invalid)
        }
    }
}

/// A message blinded for issuance. This is everything the issuer sees.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindedMessage {
    value: BigUint,
}

impl BlindedMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }
}

/// The holder's secret, kept until unblinding and then discarded.
pub struct Blinding {
    r: BigUint,
}

/// A signature over a blinded message, still blinded.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindSignature {
    value: BigUint,
}

/// A signature on the original message, verifiable by anyone.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    value: BigUint,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }
}

/// Deliberately opaque. A signature is a bearer credential, and a credential that reaches a
/// log has been published.
impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(<{} bytes>)", self.value.to_bytes_be().len())
    }
}

impl core::fmt::Debug for BlindedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlindedMessage(<{} bytes>)", self.value.to_bytes_be().len())
    }
}

impl core::fmt::Debug for BlindSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlindSignature(<{} bytes>)", self.value.to_bytes_be().len())
    }
}

impl core::fmt::Debug for Blinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Blinding(<redacted>)")
    }
}

/// Blind a message for issuance.
pub fn blind(
    pk: &IssuerPublic,
    msg: &[u8],
    seed: u64,
) -> Result<(BlindedMessage, Blinding), BlindError> {
    let n = pk.n();
    let m = pk.hash_to_group(msg);
    let mut rng = StdRng::seed_from_u64(seed);

    for attempt in 0..64u32 {
        let width = ((n.bits() + 7) / 8).max(1);
        let bytes: Vec<u8> = (0..width).map(|_| rng.gen()).collect();
        let r = BigUint::from_bytes_be(&bytes) % n;
        // Reject 0 and 1. **r = 1 is no blinding at all**, so the issuer sees the message
        // directly, and nothing else in the protocol would notice. A weak or failing RNG is
        // exactly how this happens in practice, so it is checked rather than assumed.
        if r <= BigUint::from(1u8) {
            continue;
        }
        // Invertibility is the check that r is usable; a shared factor with n would be a
        // catastrophic accident and is simply retried.
        if (r.clone().mod_inverse(n)).is_none() {
            let _ = attempt;
            continue;
        }
        let blinded = (&m * r.modpow(pk.e(), n)) % n;
        return Ok((BlindedMessage { value: blinded }, Blinding { r }));
    }
    Err(BlindError::BadBlinding)
}

/// Remove the blinding, yielding a signature on the original message.
///
/// **Verifies before returning.** A malicious or malfunctioning issuer can return any value it
/// likes, and without this check the holder would carry away a credential that silently fails
/// later, at a verifier, in a context where the failure is unattributable and possibly
/// incriminating. Detecting it here attributes it to the issuer, immediately.
pub fn unblind(
    pk: &IssuerPublic,
    sig: &BlindSignature,
    blinding: &Blinding,
    msg: &[u8],
) -> Result<Signature, BlindError> {
    let n = pk.n();
    let inv = blinding
        .r
        .clone()
        .mod_inverse(n)
        .ok_or(BlindError::BadBlinding)?
        .to_biguint()
        .ok_or(BlindError::BadBlinding)?;
    let candidate = Signature {
        value: (&sig.value * inv) % n,
    };
    pk.verify(msg, &candidate)?;
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small for test speed. A real issuer uses [`ISSUER_BITS`].
    const TEST_BITS: usize = 1024;

    fn issuer(seed: u64) -> IssuerKey {
        IssuerKey::generate(TEST_BITS, seed)
    }

    #[test]
    fn a_blindly_signed_message_verifies_publicly() {
        let sk = issuer(1);
        let pk = sk.public();
        let msg = b"credential serial 12345";

        let (blinded, blinding) = blind(&pk, msg, 7).unwrap();
        let bs = sk.sign_blinded(&blinded);
        let sig = unblind(&pk, &bs, &blinding, msg).unwrap();

        // Only the public key is used, so a verifier that could not have issued this can
        // still check it. That is what the previous shared-secret scheme lacked.
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn a_verifier_cannot_forge_what_it_did_not_issue() {
        let sk = issuer(1);
        let pk = sk.public();
        let other = issuer(2);

        let msg = b"serial";
        let (b, bl) = blind(&pk, msg, 7).unwrap();
        let sig = unblind(&pk, &sk.sign_blinded(&b), &bl, msg).unwrap();

        assert!(pk.verify(msg, &sig).is_ok());
        assert_eq!(
            other.public().verify(msg, &sig),
            Err(BlindError::Invalid),
            "a signature must not verify under another issuer"
        );
    }

    #[test]
    fn a_signature_does_not_transfer_to_another_message() {
        let sk = issuer(1);
        let pk = sk.public();
        let (b, bl) = blind(&pk, b"serial one", 7).unwrap();
        let sig = unblind(&pk, &sk.sign_blinded(&b), &bl, b"serial one").unwrap();

        assert!(pk.verify(b"serial one", &sig).is_ok());
        assert_eq!(pk.verify(b"serial two", &sig), Err(BlindError::Invalid));
    }

    #[test]
    fn the_wrong_blinding_factor_yields_nothing_usable() {
        let sk = issuer(1);
        let pk = sk.public();
        let msg = b"serial";

        let (b, _correct) = blind(&pk, msg, 7).unwrap();
        let (_, wrong) = blind(&pk, msg, 8).unwrap();
        // Caught at unblinding rather than silently carried to a verifier.
        assert_eq!(
            unblind(&pk, &sk.sign_blinded(&b), &wrong, msg).unwrap_err(),
            BlindError::Invalid
        );
    }

    #[test]
    fn the_same_message_blinds_differently_every_time() {
        let pk = issuer(1).public();
        let msg = b"serial";
        let (a, _) = blind(&pk, msg, 1).unwrap();
        let (b, _) = blind(&pk, msg, 2).unwrap();
        assert_ne!(
            a.to_bytes(),
            b.to_bytes(),
            "issuance must not be linkable by repeated blinding"
        );
    }

    /// **Perfect blinding, demonstrated rather than asserted.**
    ///
    /// Because `r ↦ r^e` is a bijection modulo `n`, for any blinded value `b` and *any* message
    /// `m'`, there exists a blinding factor `r'` with `b = m' · r'^e`. So the issuer's view is
    /// consistent with every possible message, and carries no information about the real one.
    ///
    /// The test constructs that `r'` for an unrelated message, which requires the private key
    /// and so is a demonstration rather than an attack.
    #[test]
    fn a_blinded_value_is_consistent_with_any_message() {
        let sk = issuer(1);
        let pk = sk.public();
        let n = pk.n();

        let real = b"the message actually signed";
        let (blinded, _) = blind(&pk, real, 7).unwrap();

        // Pick an entirely unrelated message.
        let decoy = b"something the holder never asked for";
        let m_decoy = pk.hash_to_group(decoy);

        // Solve for r' such that blinded = m_decoy * r'^e, i.e. r' = (blinded / m_decoy)^d.
        let inv = m_decoy.clone().mod_inverse(n).unwrap().to_biguint().unwrap();
        let quotient = (&blinded.value * inv) % n;
        let r_prime = quotient.modpow(sk.inner.d(), n);

        let reconstructed = (&m_decoy * r_prime.modpow(pk.e(), n)) % n;
        assert_eq!(
            reconstructed, blinded.value,
            "the same blinded value must be explainable by an unrelated message"
        );
    }

    #[test]
    fn many_credentials_from_one_issuer_all_verify() {
        let sk = issuer(1);
        let pk = sk.public();
        for i in 0..8u64 {
            let msg = format!("serial {i}");
            let (b, bl) = blind(&pk, msg.as_bytes(), i).unwrap();
            let sig = unblind(&pk, &sk.sign_blinded(&b), &bl, msg.as_bytes()).unwrap();
            assert!(pk.verify(msg.as_bytes(), &sig).is_ok(), "credential {i}");
        }
    }

    #[test]
    fn a_blind_signature_alone_is_not_a_credential() {
        // The value the issuer returns is not usable until unblinded, so intercepting the
        // issuance response gains nothing without the holder's blinding factor.
        let sk = issuer(1);
        let pk = sk.public();
        let msg = b"serial";
        let (b, _bl) = blind(&pk, msg, 7).unwrap();
        let bs = sk.sign_blinded(&b);

        let as_if = Signature {
            value: bs.value.clone(),
        };
        assert_eq!(pk.verify(msg, &as_if), Err(BlindError::Invalid));
    }
}

/// Attacks, not exercises.
///
/// Each of these is something an adversary with a stated capability actually tries. Two
/// defects in this module were found by writing them: a blinding factor of one, which is no
/// blinding at all and hands the message to the issuer, and an unblind that returned a
/// malicious issuer's garbage without checking it.
#[cfg(test)]
mod adversarial {
    use super::*;

    const TEST_BITS: usize = 1024;
    fn issuer(seed: u64) -> IssuerKey {
        IssuerKey::generate(TEST_BITS, seed)
    }

    /// **A blinding factor of 1 is no blinding.** The issuer sees the message directly and
    /// nothing downstream notices, because every later step still works perfectly.
    #[test]
    fn a_degenerate_blinding_factor_is_never_produced() {
        let pk = issuer(1).public();
        // Sweep many seeds; none may yield an r that fails to hide the message.
        for seed in 0..200u64 {
            let (blinded, blinding) = blind(&pk, b"secret serial", seed).unwrap();
            assert!(
                blinding.r > BigUint::from(1u8),
                "seed {seed} produced a degenerate blinding factor"
            );
            // And the blinded value must not equal the bare message hash, which is what
            // r = 1 would produce.
            assert_ne!(blinded.value, pk.hash_to_group(b"secret serial"));
        }
    }

    /// **A malicious issuer returns garbage.** Without a check at unblinding the holder walks
    /// away with a credential that fails later, at a verifier, where the failure is
    /// unattributable and possibly incriminating.
    #[test]
    fn a_malicious_issuer_is_caught_at_unblinding_not_at_spending() {
        let sk = issuer(1);
        let pk = sk.public();
        let msg = b"serial";
        let (b, bl) = blind(&pk, msg, 7).unwrap();

        for garbage in [
            BigUint::from(0u8),
            BigUint::from(1u8),
            BigUint::from(12345u32),
            b.value.clone(),
        ] {
            let evil = BlindSignature { value: garbage };
            assert_eq!(
                unblind(&pk, &evil, &bl, msg).unwrap_err(),
                BlindError::Invalid,
                "issuer garbage was accepted"
            );
        }
    }

    /// RSA is multiplicatively homomorphic, so `sig(a)·sig(b)` signs `a·b`. The full-domain
    /// hash is what stops that being useful: forging a signature on a *chosen* message needs
    /// `H(m3) = H(m1)·H(m2)`, which is a preimage problem.
    #[test]
    fn the_multiplicative_forgery_does_not_produce_a_usable_signature() {
        let sk = issuer(1);
        let pk = sk.public();
        let n = pk.n();

        let mk = |m: &[u8], seed: u64| {
            let (b, bl) = blind(&pk, m, seed).unwrap();
            unblind(&pk, &sk.sign_blinded(&b), &bl, m).unwrap()
        };
        let s1 = mk(b"one", 1);
        let s2 = mk(b"two", 2);

        // The product is a valid signature on H(one)*H(two), which is not the hash of any
        // message the attacker can name.
        let product = Signature {
            value: (&s1.value * &s2.value) % n,
        };
        for target in [
            b"one".as_ref(),
            b"two".as_ref(),
            b"onetwo".as_ref(),
            b"three".as_ref(),
        ] {
            assert_eq!(
                pk.verify(target, &product),
                Err(BlindError::Invalid),
                "multiplicative forgery verified against {target:?}"
            );
        }
    }

    /// Trivial signature values must not verify for a real message.
    #[test]
    fn degenerate_signatures_are_rejected() {
        let pk = issuer(1).public();
        for v in [0u32, 1, 2, 65537] {
            let s = Signature {
                value: BigUint::from(v),
            };
            assert_eq!(pk.verify(b"a real serial", &s), Err(BlindError::Invalid));
        }
    }

    /// An adversary who records the issuance exchange has the blinded value and the blind
    /// signature, and neither is a credential.
    #[test]
    fn recording_the_issuance_exchange_yields_nothing_spendable() {
        let sk = issuer(1);
        let pk = sk.public();
        let msg = b"serial";
        let (b, _bl) = blind(&pk, msg, 7).unwrap();
        let bs = sk.sign_blinded(&b);

        // Everything the wire carried, tried as a signature.
        for v in [b.value.clone(), bs.value.clone()] {
            assert_eq!(pk.verify(msg, &Signature { value: v }), Err(BlindError::Invalid));
        }
    }

    /// Two issuers, and a holder who tries to mix them.
    #[test]
    fn a_signature_cannot_be_moved_between_issuers() {
        let a = issuer(1);
        let bx = issuer(2);
        let msg = b"serial";

        let (blinded, bl) = blind(&a.public(), msg, 7).unwrap();
        // Ask the wrong issuer to sign it. It will, since it cannot read it.
        let cross = bx.sign_blinded(&blinded);
        // And the result is worthless under either key.
        assert!(unblind(&a.public(), &cross, &bl, msg).is_err());
        assert!(unblind(&bx.public(), &cross, &bl, msg).is_err());
    }

    /// The holder's own key must not be recoverable from what it publishes, so blinding
    /// factors must not repeat across credentials.
    #[test]
    fn blinding_factors_do_not_repeat_across_credentials() {
        let pk = issuer(1).public();
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..64u64 {
            let (_, bl) = blind(&pk, b"same message every time", seed).unwrap();
            assert!(
                seen.insert(bl.r.to_bytes_be()),
                "blinding factor repeated at seed {seed}"
            );
        }
    }
}
