//! Double spending, made self-incriminating rather than prevented.
//!
//! Issue #44. A credential is worth one unit *per verifier*, because two verifiers that
//! cannot see each other both accept the same serial. The options considered were a shared
//! ledger with its consensus cost, short epochs bounding the damage, or accepting per-verifier
//! semantics. All three treat the problem as *prevention*.
//!
//! Chaum, Fiat and Naor solved it differently in 1988: **do not prevent double spending, make
//! it reveal the spender.** A coin carries the holder's identity split into shares. Each spend
//! reveals one half of each pair, chosen by the verifier's challenge, which discloses nothing.
//! Two spends against different challenges reveal both halves of at least one pair, and the
//! identity reconstructs.
//!
//! That fits here better than any of the three, because it needs **no online authority and no
//! consensus**, which is the constraint that made the other options expensive.
//!
//! # Why the punishment is proportionate rather than a privacy failure
//!
//! Revealing the acquirer looks like it contradicts §14's separation of acquisition from
//! spending. It does not. **Acquisition is deliberately linkable already.** An honest spender
//! reveals nothing; a double spender is linked back to a transaction that was never private.
//! The anonymity property holds exactly where it was claimed.
//!
//! Combined with L16, where standing is earned per relationship and does not transfer, a
//! burned identity cannot be replaced by buying a fresh one.
//!
//! # Status
//!
//! The cut-and-choose structure is implemented and tested. Compact E-Cash (Camenisch,
//! Hohenberger, Lysyanskaya, EUROCRYPT 2005) is the modern construction and additionally gives
//! **exculpability**, meaning a verifier can prove a double spend to a third party rather than
//! merely assert it. That property matters more here than in a banked setting, because there
//! is no authority whose word anyone takes. It is not implemented.

use karst_id::Address;
use karst_object::{Cid, Enc};

/// How many identity shares a credential carries.
///
/// Two spends fail to reveal the holder only if the verifiers happen to issue identical
/// challenges, which is `2^-SHARES`. At 64 that is not a risk anyone needs to think about.
pub const SHARES: usize = 64;

/// The identity commitment carried by a credential.
///
/// For each position, two halves that XOR to the holder's address. A spend opens one half per
/// position; opening both halves of any position reconstructs the address.
#[derive(Clone)]
pub struct IdentityShares {
    left: Vec<[u8; 32]>,
    right: Vec<[u8; 32]>,
}

impl IdentityShares {
    /// Split `holder` into `SHARES` independent pairs.
    ///
    /// `blinding` must be unpredictable to the verifier, or it could derive both halves.
    pub fn split(holder: Address, blinding: &[u8; 32]) -> Self {
        let mut left = Vec::with_capacity(SHARES);
        let mut right = Vec::with_capacity(SHARES);
        for i in 0..SHARES {
            let mut h = blake3::Hasher::new();
            h.update(b"karst.cfn.share");
            h.update(blinding);
            h.update(&(i as u64).to_le_bytes());
            let l = *h.finalize().as_bytes();

            let mut r = [0u8; 32];
            for (j, b) in holder.as_bytes().iter().enumerate() {
                r[j] = b ^ l[j];
            }
            left.push(l);
            right.push(r);
        }
        IdentityShares { left, right }
    }

    /// A commitment the issuer signs over, so the shares cannot be swapped after issuance.
    pub fn commitment(&self) -> Cid {
        let mut e = Enc::new();
        e.str("karst.cfn.commit.v1").u64(SHARES as u64);
        for i in 0..SHARES {
            e.bytes(&self.left[i]).bytes(&self.right[i]);
        }
        e.hash()
    }

    /// Open one half per position, as directed by the verifier's challenge.
    pub fn open(&self, challenge: &Challenge) -> Opening {
        let halves = (0..SHARES)
            .map(|i| {
                if challenge.bit(i) {
                    self.right[i]
                } else {
                    self.left[i]
                }
            })
            .collect();
        Opening {
            challenge: *challenge,
            halves,
        }
    }
}

/// A verifier's per-spend challenge. Must be freshly random, or two verifiers issuing the same
/// challenge learn nothing from a double spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge([u8; SHARES / 8]);

impl Challenge {
    pub fn from_bytes(b: [u8; SHARES / 8]) -> Self {
        Challenge(b)
    }

    /// Derive from verifier-local randomness. A verifier that derives this from the credential
    /// would hand every verifier the same challenge and defeat the whole mechanism.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"karst.cfn.challenge");
        h.update(seed);
        let mut b = [0u8; SHARES / 8];
        h.finalize_xof().fill(&mut b);
        Challenge(b)
    }

    pub fn bit(&self, i: usize) -> bool {
        self.0[i / 8] & (1 << (i % 8)) != 0
    }
}

/// What a spender hands a verifier: one half of each pair.
#[derive(Clone)]
pub struct Opening {
    pub challenge: Challenge,
    pub(crate) halves: Vec<[u8; 32]>,
}

/// What two openings of the same credential say about each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consistency {
    /// Every differing position agrees on one address. A real double spend.
    Consistent,
    /// Differing positions disagree, so at least one opening is fabricated. **The credential
    /// is bad and the spend should be refused**, even though nobody can be named.
    Inconsistent,
    /// The challenges did not differ anywhere, so there is nothing to compare.
    NoOverlap,
}

/// Classify a pair of openings without producing a proof.
///
/// A verifier needs this to tell "somebody double spent and I can name them" from "somebody
/// handed me a fabricated credential", which are different problems with different responses.
pub fn consistency(a: &Opening, b: &Opening) -> Consistency {
    if a.halves.len() != b.halves.len() {
        return Consistency::Inconsistent;
    }
    let mut recovered: Option<[u8; 32]> = None;
    let mut differing = 0usize;
    for i in 0..a.halves.len() {
        if a.challenge.bit(i) == b.challenge.bit(i) {
            continue;
        }
        differing += 1;
        let mut addr = [0u8; 32];
        for j in 0..32 {
            addr[j] = a.halves[i][j] ^ b.halves[i][j];
        }
        match recovered {
            None => recovered = Some(addr),
            Some(prev) if prev != addr => return Consistency::Inconsistent,
            Some(_) => {}
        }
    }
    if differing == 0 {
        Consistency::NoOverlap
    } else {
        Consistency::Consistent
    }
}

impl Opening {
    /// Nothing here identifies anyone on its own, which is the point.
    pub fn len(&self) -> usize {
        self.halves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.halves.is_empty()
    }
}

/// Evidence that one credential was spent twice, and who did it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleSpendProof {
    pub serial: [u8; 32],
    pub holder: Address,
    /// Positions where the two challenges differed, which is what made recovery possible.
    pub revealing_positions: usize,
}

/// Attempt to recover the holder from two openings of the same credential.
///
/// Returns `None` when the two challenges are identical, which reveals the same halves twice
/// and therefore nothing. That is a `2^-SHARES` accident, or a verifier reusing a challenge.
pub fn recover_holder(a: &Opening, b: &Opening, serial: [u8; 32]) -> Option<DoubleSpendProof> {
    if a.halves.len() != b.halves.len() {
        return None;
    }
    let mut differing = 0usize;
    let mut recovered: Option<Address> = None;

    for i in 0..a.halves.len() {
        if a.challenge.bit(i) == b.challenge.bit(i) {
            continue;
        }
        differing += 1;
        // Different challenge bits mean opposite halves, so their XOR is the address.
        let mut addr = [0u8; 32];
        for j in 0..32 {
            addr[j] = a.halves[i][j] ^ b.halves[i][j];
        }
        let candidate = Address::from_raw(addr);
        match recovered {
            None => recovered = Some(candidate),
            // Every differing position must agree, or the openings are inconsistent and this
            // is not a valid proof of anything.
            Some(prev) if prev != candidate => return None,
            Some(_) => {}
        }
    }

    recovered.map(|holder| DoubleSpendProof {
        serial,
        holder,
        revealing_positions: differing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_id::Identity;

    fn shares_for(id: &Identity) -> IdentityShares {
        IdentityShares::split(id.address(), &[42u8; 32])
    }

    #[test]
    fn a_single_spend_reveals_nothing() {
        let holder = Identity::generate();
        let s = shares_for(&holder);
        let opening = s.open(&Challenge::from_seed(b"verifier one"));

        // Every half is present exactly once, and no pair is complete.
        assert_eq!(opening.len(), SHARES);
        // Recovering from one opening is not even expressible: it takes two.
        assert!(recover_holder(&opening, &opening, [0u8; 32]).is_none());
    }

    /// **The mechanism.** Two verifiers, two independent challenges, and the holder falls out.
    #[test]
    fn spending_twice_reveals_the_holder() {
        let holder = Identity::generate();
        let s = shares_for(&holder);

        let a = s.open(&Challenge::from_seed(b"verifier one"));
        let b = s.open(&Challenge::from_seed(b"verifier two"));

        let proof = recover_holder(&a, &b, [9u8; 32]).expect("double spend must be provable");
        assert_eq!(proof.holder, holder.address());
        // With 64 positions and independent challenges, roughly half should differ.
        assert!(proof.revealing_positions > 10);
    }

    #[test]
    fn identical_challenges_reveal_nothing_and_the_api_says_so() {
        // A verifier that derives its challenge deterministically from the credential hands
        // every verifier the same one, and the mechanism silently stops working. It returns
        // None rather than a wrong answer.
        let holder = Identity::generate();
        let s = shares_for(&holder);
        let c = Challenge::from_seed(b"same");
        assert!(recover_holder(&s.open(&c), &s.open(&c), [0u8; 32]).is_none());
    }

    #[test]
    fn openings_from_different_credentials_do_not_frame_anyone() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let a = IdentityShares::split(alice.address(), &[1u8; 32]);
        let b = IdentityShares::split(bob.address(), &[2u8; 32]);

        let oa = a.open(&Challenge::from_seed(b"one"));
        let ob = b.open(&Challenge::from_seed(b"two"));

        // Two openings of different credentials disagree across positions, so no consistent
        // address emerges and no proof is produced.
        assert!(recover_holder(&oa, &ob, [0u8; 32]).is_none());
    }

    #[test]
    fn the_commitment_binds_the_shares() {
        let holder = Identity::generate();
        let a = IdentityShares::split(holder.address(), &[1u8; 32]);
        let b = IdentityShares::split(holder.address(), &[2u8; 32]);
        assert_ne!(
            a.commitment(),
            b.commitment(),
            "different blinding must give a different commitment"
        );
        assert_eq!(a.commitment(), a.clone().commitment());
    }

    #[test]
    fn many_holders_are_each_recovered_correctly() {
        for seed in 0..20u8 {
            let holder = Identity::from_seed([seed; 32]);
            let s = IdentityShares::split(holder.address(), &[seed ^ 0xff; 32]);
            let a = s.open(&Challenge::from_seed(&[seed, 1]));
            let b = s.open(&Challenge::from_seed(&[seed, 2]));
            let p = recover_holder(&a, &b, [seed; 32]).unwrap();
            assert_eq!(p.holder, holder.address(), "seed {seed}");
        }
    }
}

/// Attacks on the recovery mechanism itself.
#[cfg(test)]
mod adversarial {
    use super::*;
    use karst_id::Identity;

    /// **A hole, demonstrated rather than described.**
    ///
    /// A holder who double spends and simply *lies* in the second opening, sending random
    /// halves instead of real ones, produces two openings that do not agree on any address.
    /// `recover_holder` returns `None`, so the double spender escapes identification.
    ///
    /// Chaum, Fiat and Naor prevent this with cut-and-choose **at issuance**: the issuer
    /// requires the holder to open many candidate credentials and checks they are well formed,
    /// signing only an unopened one. A holder who embeds garbage is caught with probability
    /// approaching one before the credential exists. That step is not implemented here.
    ///
    /// This test passes, which means the weakness is real. It is filed rather than hidden.
    #[test]
    fn a_lying_holder_currently_escapes_identification() {
        let holder = Identity::generate();
        let s = IdentityShares::split(holder.address(), &[42u8; 32]);

        let honest = s.open(&Challenge::from_seed(b"verifier one"));

        // The second spend sends halves that are not the holder's.
        let fake = IdentityShares::split(Identity::generate().address(), &[99u8; 32]);
        let lie = fake.open(&Challenge::from_seed(b"verifier two"));

        assert!(
            recover_holder(&honest, &lie, [0u8; 32]).is_none(),
            "if this ever fails, the hole has been closed and this test should become an \
             assertion that the liar IS identified"
        );
    }

    /// The verifier can at least tell that something is wrong, which is the difference between
    /// an unattributable double spend and an undetectable one.
    #[test]
    fn an_inconsistent_pair_is_distinguishable_from_a_matching_challenge() {
        let holder = Identity::generate();
        let s = IdentityShares::split(holder.address(), &[42u8; 32]);
        let c = Challenge::from_seed(b"same");

        // Identical challenges: no differing positions at all, so nothing to compare.
        assert_eq!(consistency(&s.open(&c), &s.open(&c)), Consistency::NoOverlap);

        // Different challenges on the same credential: fully consistent.
        let a = s.open(&Challenge::from_seed(b"one"));
        let b = s.open(&Challenge::from_seed(b"two"));
        assert_eq!(consistency(&a, &b), Consistency::Consistent);

        // Different challenges, fabricated halves: detectably inconsistent.
        let fake = IdentityShares::split(Identity::generate().address(), &[99u8; 32]);
        assert_eq!(
            consistency(&a, &fake.open(&Challenge::from_seed(b"two"))),
            Consistency::Inconsistent
        );
    }

    /// A verifier that reuses a challenge across every spend it sees defeats the mechanism
    /// entirely, since two spends at that verifier reveal the same halves twice.
    #[test]
    fn a_verifier_that_reuses_its_challenge_learns_nothing() {
        let holder = Identity::generate();
        let s = IdentityShares::split(holder.address(), &[1u8; 32]);
        let fixed = Challenge::from_seed(b"this verifier never varies");

        assert!(recover_holder(&s.open(&fixed), &s.open(&fixed), [0u8; 32]).is_none());
    }

    /// Two honest holders must never combine into a proof against a third party.
    #[test]
    fn openings_from_unrelated_holders_never_frame_a_third() {
        let victim = Identity::generate();
        for seed in 0..30u8 {
            let a = IdentityShares::split(Identity::from_seed([seed; 32]).address(), &[seed; 32]);
            let b = IdentityShares::split(
                Identity::from_seed([seed ^ 0xff; 32]).address(),
                &[seed ^ 0x0f; 32],
            );
            let proof = recover_holder(
                &a.open(&Challenge::from_seed(&[seed, 1])),
                &b.open(&Challenge::from_seed(&[seed, 2])),
                [0u8; 32],
            );
            if let Some(p) = proof {
                assert_ne!(p.holder, victim.address(), "framed an uninvolved party");
            }
        }
    }

    /// Openings of different lengths are not comparable and must not be treated as evidence.
    #[test]
    fn mismatched_openings_are_refused() {
        let s = IdentityShares::split(Identity::generate().address(), &[1u8; 32]);
        let full = s.open(&Challenge::from_seed(b"a"));
        let truncated = Opening {
            challenge: Challenge::from_seed(b"b"),
            halves: Vec::new(),
        };
        assert!(recover_holder(&full, &truncated, [0u8; 32]).is_none());
    }
}
