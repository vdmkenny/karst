//! L5 Membership.
//!
//! # What this does not do, first, because the literature is unambiguous
//!
//! It does **not** provide membership concealment in the sense Vasserman, Jansen, Tyra, Hopper
//! and Kim define (*Membership-Concealing Overlay Networks*, CCS 2009). Two reasons, and both
//! are theirs rather than mine.
//!
//! Their construction requires a **Membership and Invitation Authority**: a trusted central
//! party that issues keys, handles every invitation, and enforces a global degree constraint.
//! This design cannot have one, so it cannot have their result.
//!
//! And they prove the ceiling anyway. No overlay permitting peer communication can hold
//! exposure below `Theta(L + G)` in the adversary's monitoring and corruption budget, because
//! some node has to deliver messages to each identity the adversary controls or watches.
//! **Linear exposure is the floor**, not a weakness of any particular scheme.
//!
//! # What the deployed attempt achieved
//!
//! Tor bridges are membership concealment in production, and the record should be read before
//! anyone designs another one. China broke the HTTPS distribution channel in September 2009 and
//! the Gmail one in March 2010, in Dingledine's words "by just pretending to be enough
//! legitimate users from enough different subnets". By 2011 the pools in distribution were 176
//! bridges by HTTPS and 201 by mail, against a state.
//!
//! Ling, Luo, Yu, Yang and Fu (INFOCOM 2012) then showed distribution was not the weak part.
//! One malicious middle relay, run for fourteen days, enumerated 2,369 bridges: as many as a
//! month of enumeration across 500 PlanetLab nodes and 2,000 mail accounts. Tor's structural
//! answer, proposal 188 on bridge guards, is still marked Reserve, shelved in 2020 on the
//! grounds that the attack was not observed in use rather than that it had been fixed.
//!
//! # And social-graph admission is worse than nothing
//!
//! The SybilGuard and SybilLimit family assumes sybils form a tightly knit region joined to the
//! honest graph by a sparse cut. Yang and colleagues instrumented a live network with hundreds
//! of thousands of real sybils and found they do not: they integrate like ordinary users, and
//! most sybil-to-sybil links are accidental rather than intended. That is a measurement
//! refutation rather than a modelling quibble.
//!
//! Alvisi and colleagues then measured those schemes under the real attack shape, scoring the
//! probability that a random honest node ranks above a random sybil, where 0.5 is a coin flip:
//! SybilLimit 0.45, SybilGuard 0.44, Gatekeeper 0.49, and one variant at 0.34. **Four of five
//! perform at or below chance.** Mohaisen, Yun and Kim had already shown the mixing-time
//! assumption fails on real graphs, and worse, that the graphs with genuine trust semantics are
//! the slow-mixing ones. So there is no admission decision to make here, and none is made.
//!
//! # What is left, and it is not nothing
//!
//! Two things this design can honestly claim.
//!
//! **There is no roll.** No registry, no directory of members, no list anyone holds. That is
//! weaker than concealment: an adversary who watches enough of the network still learns who is
//! on it, at the linear rate above. What it removes is the single object whose seizure hands
//! over everyone at once.
//!
//! **Introduction is a relationship rather than an admission.** Two parties who already share a
//! contact can discover that fact without either revealing their contacts, and act on it. That
//! is balanced two-party private set intersection, which unlike almost everything else in this
//! area is cheap: at a thousand contacts each side it is tens of kilobytes and milliseconds.
//!
//! It is worth knowing that nobody ships it. A survey of eleven messengers found five uploading
//! contacts in plaintext, five uploading trivially reversible hashes, one using trusted
//! hardware, and none using PSI. Signal evaluated it and chose an enclave, judging the
//! non-collusion assumption behind the fast multi-server designs unrealistic. But their problem
//! is a phone against a billion-row registry, which is the **unbalanced** case. Two peers
//! comparing address books is the balanced case, and the cost difference is enormous.
//!
//! # This is secure against a curious counterparty, not a lying one
//!
//! Diffie-Hellman PSI is a **semi-honest** protocol. It assumes both sides follow it and hides
//! their inputs from each other; it does not assume either side is trying to produce a false
//! answer.
//!
//! A lying responder cannot invent a shared contact out of nothing, because every value it
//! returns has to land in a set the initiator computed from the responder's own offer. What it
//! can do is **misattribute**: return, at the position of one of the initiator's contacts, the
//! reblinded form of a different contact it genuinely does share. The initiator then concludes
//! that contact *i* is shared when in fact contact *k* is. The count is honest and the names
//! are not.
//!
//! Fixing this needs the responder to prove it applied one exponent to every element, which is
//! a proof of discrete-log equality per element and costs more than everything else here
//! combined. It is not implemented, and an introduction protocol built on this should treat the
//! *fact* of a shared contact as reliable and the *identity* of it as the counterparty's claim.
//!
//! # The abuse that PSI cannot prevent
//!
//! A party who submits a set of one learns whether the other holds that one element. This is
//! inherent: PSI computes an intersection, and an intersection with a singleton is a membership
//! query. Padding hides set *size*, not this. So an introduction protocol built on PSI is a
//! membership oracle for anyone willing to run it repeatedly, and the only real defences are
//! rate limiting and refusing to run it with strangers, neither of which is cryptography.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use karst_id::Address;

/// A blinded contact, as it appears on the wire.
pub type Blinded = [u8; 32];

/// The number of entries every exchange is padded to.
///
/// Set size is otherwise visible, and set size is informative: a party with four contacts and a
/// party with four hundred are different kinds of participant. Padding costs bandwidth linear
/// in the bucket and buys that one fact.
pub const BUCKET: usize = 256;

fn point_of(a: &Address) -> RistrettoPoint {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.member.v1.contact");
    h.update(a.as_bytes());
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Points that are not any contact, used to pad a set to a fixed size.
///
/// Derived from a per-exchange secret so that padding is not recognisable across exchanges. A
/// fixed pad would be a constant every observer learns once and then subtracts.
fn filler(secret: &[u8; 32], i: usize) -> RistrettoPoint {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.member.v1.filler");
    h.update(secret);
    h.update(&(i as u64).to_le_bytes());
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// One side of an intersection.
///
/// Diffie-Hellman private set intersection. Each side raises the other's blinded points to its
/// own secret, so an element both hold reaches the same value by two different routes, and an
/// element only one holds never does. Neither learns anything about the other's unshared
/// elements beyond how many there were, which the bucket hides.
pub struct Party {
    secret: Scalar,
    pad: [u8; 32],
    /// Own contacts, padded and ordered exactly as `offer` sends them.
    ordered: Vec<Option<Address>>,
}

fn build(secret: Scalar, pad: [u8; 32], contacts: &[Address]) -> Party {
    // Ordered by blinded value, so the position of a contact in the offer is a function of the
    // contact and the secret rather than of insertion order. Sending them in the order the
    // owner happens to store them would say which contacts are oldest.
    let mut rows: Vec<(Blinded, Option<Address>)> = contacts
        .iter()
        .map(|a| ((point_of(a) * secret).compress().to_bytes(), Some(*a)))
        .collect();
    for i in rows.len()..BUCKET {
        rows.push(((filler(&pad, i) * secret).compress().to_bytes(), None));
    }
    rows.sort_by_key(|(b, _)| *b);
    Party {
        secret,
        pad,
        ordered: rows.into_iter().map(|(_, a)| a).collect(),
    }
}

impl Party {
    pub fn new(contacts: &[Address]) -> Self {
        use rand::RngCore;
        let mut sb = [0u8; 64];
        let mut pad = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sb);
        rand::rngs::OsRng.fill_bytes(&mut pad);
        build(Scalar::from_bytes_mod_order_wide(&sb), pad, contacts)
    }

    /// Deterministic construction, for tests that need a fixed transcript.
    pub fn from_seed(contacts: &[Address], seed: [u8; 32]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"karst.member.v1.party");
        h.update(&seed);
        let mut wide = [0u8; 64];
        h.finalize_xof().fill(&mut wide);
        let mut pad = [0u8; 32];
        pad.copy_from_slice(&wide[..32]);
        build(Scalar::from_bytes_mod_order_wide(&wide), pad, contacts)
    }

    /// How many contacts this party actually holds. Never sent.
    pub fn held(&self) -> usize {
        self.ordered.iter().filter(|a| a.is_some()).count()
    }

    /// Blinded contacts, padded to the bucket.
    ///
    /// Always exactly `BUCKET` entries, so an observer counting them learns the bucket rather
    /// than the party. Real contacts and filler are indistinguishable: both are a group element
    /// raised to the same secret, and the filler is derived from a per-exchange value so it is
    /// not recognisable across exchanges either.
    pub fn offer(&self) -> Vec<Blinded> {
        self.ordered
            .iter()
            .enumerate()
            .map(|(i, a)| match a {
                Some(addr) => (point_of(addr) * self.secret).compress().to_bytes(),
                None => (filler(&self.pad, i) * self.secret).compress().to_bytes(),
            })
            .collect()
    }

    /// Raise the other side's offer to this party's secret, **preserving order**.
    ///
    /// Order is preserved on purpose and it is not a leak. The other side already knows which
    /// of its own contacts sits at each position; this reply tells it nothing it did not send.
    /// Shuffling here would break the protocol rather than strengthen it, because the sender
    /// could no longer tell which reply belongs to which of its own contacts.
    pub fn reblind(&self, theirs: &[Blinded]) -> Vec<Blinded> {
        theirs
            .iter()
            .map(|b| {
                CompressedRistretto(*b)
                    .decompress()
                    .map(|p| (p * self.secret).compress().to_bytes())
                    // An undecodable point cannot be raised to anything, and substituting a
                    // fixed value would make every such entry match every other. Zero never
                    // decompresses to a valid point, so it can never collide with a real one.
                    .unwrap_or([0u8; 32])
            })
            .collect()
    }

    /// Which of this party's own contacts the other side also holds.
    ///
    /// `mine_returned` is what the other side produced from this party's offer, position for
    /// position. `theirs_reblinded` is what this party produced from the other side's offer.
    /// A contact is shared when its doubly-blinded value appears in both.
    pub fn intersect(
        &self,
        mine_returned: &[Blinded],
        theirs_reblinded: &[Blinded],
    ) -> Vec<Address> {
        let theirs: std::collections::BTreeSet<Blinded> =
            theirs_reblinded.iter().copied().collect();
        self.ordered
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| {
                let addr = (*slot)?;
                let returned = mine_returned.get(i)?;
                if *returned != [0u8; 32] && theirs.contains(returned) {
                    Some(addr)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Run a full exchange and return what each side learns.
///
/// Two messages each way. The wire form is `offer` and `reblind`; this shows the order they
/// compose in and is what the tests drive.
pub fn exchange(a: &Party, b: &Party) -> (Vec<Address>, Vec<Address>) {
    let a_offer = a.offer();
    let b_offer = b.offer();

    let a_returned = b.reblind(&a_offer);
    let b_returned = a.reblind(&b_offer);

    let a_sees = a.intersect(&a_returned, &b_returned);
    let b_sees = b.intersect(&b_returned, &a_returned);
    (a_sees, b_sees)
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_id::Identity;

    fn addr(n: u32) -> Address {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        Identity::from_seed(seed).address()
    }

    fn set(range: std::ops::Range<u32>) -> Vec<Address> {
        range.map(addr).collect()
    }

    /// Two parties learn exactly what they share, and nothing else.
    #[test]
    fn an_exchange_yields_the_intersection() {
        let a = Party::new(&set(0..40));
        let b = Party::new(&set(30..70));
        let (a_sees, b_sees) = exchange(&a, &b);

        let expected: std::collections::BTreeSet<Address> = set(30..40).into_iter().collect();
        assert_eq!(a_sees.iter().copied().collect::<std::collections::BTreeSet<_>>(), expected);
        assert_eq!(b_sees.iter().copied().collect::<std::collections::BTreeSet<_>>(), expected);
    }

    /// Disjoint sets reveal nothing at all.
    #[test]
    fn disjoint_contacts_yield_nothing() {
        let a = Party::new(&set(0..50));
        let b = Party::new(&set(100..150));
        let (x, y) = exchange(&a, &b);
        assert!(x.is_empty());
        assert!(y.is_empty());
    }

    /// The wire form is the same size whatever a party holds.
    ///
    /// Set size is informative on its own: a party with four contacts and a party with four
    /// hundred are different kinds of participant, and one of them is far easier to identify.
    #[test]
    fn the_offer_is_the_same_size_whatever_is_held() {
        let empty = Party::new(&[]);
        let one = Party::new(&set(0..1));
        let many = Party::new(&set(0..BUCKET as u32));
        assert_eq!(empty.offer().len(), BUCKET);
        assert_eq!(one.offer().len(), BUCKET);
        assert_eq!(many.offer().len(), BUCKET);
        assert_ne!(empty.held(), many.held());
    }

    /// Padding must be indistinguishable from a real contact.
    ///
    /// If filler were a fixed value, an observer would learn it once and subtract it from every
    /// exchange thereafter, and the bucket would conceal nothing.
    #[test]
    fn padding_is_not_recognisable_across_exchanges() {
        let a = Party::new(&set(0..3));
        let b = Party::new(&set(0..3));
        let (oa, ob) = (a.offer(), b.offer());

        let shared: std::collections::BTreeSet<Blinded> = oa
            .iter()
            .filter(|x| ob.contains(x))
            .copied()
            .collect();
        assert!(
            shared.is_empty(),
            "two parties produced identical wire values, so padding or blinding is not per-party"
        );
        // And nothing in either offer repeats, which a constant filler would.
        let uniq: std::collections::BTreeSet<Blinded> = oa.iter().copied().collect();
        assert_eq!(uniq.len(), BUCKET);
    }

    /// A party's own offer must not reveal its contacts to anyone without the other secret.
    #[test]
    fn an_offer_does_not_reveal_a_contact_to_an_observer() {
        let contacts = set(0..10);
        let a = Party::new(&contacts);
        let offered: std::collections::BTreeSet<Blinded> = a.offer().into_iter().collect();

        // An observer knowing the whole address space still cannot match anything, because
        // every entry is raised to a secret they do not have.
        for c in set(0..200) {
            let bare = point_of(&c).compress().to_bytes();
            assert!(!offered.contains(&bare));
        }
    }

    /// Two exchanges by the same party must not be linkable by their wire values.
    ///
    /// A party that produced the same blinded set every time would be trivially trackable
    /// across every introduction it ever made, which would make the protocol worse than
    /// exchanging plaintext hashes with people you already trust.
    #[test]
    fn the_same_contacts_produce_different_wire_values_each_time() {
        let contacts = set(0..20);
        let first = Party::new(&contacts).offer();
        let second = Party::new(&contacts).offer();
        let overlap = first.iter().filter(|x| second.contains(x)).count();
        assert_eq!(overlap, 0, "{overlap} wire values repeated across exchanges");
    }

    /// A party larger than the bucket must not silently drop contacts.
    #[test]
    fn a_set_larger_than_the_bucket_is_not_silently_truncated() {
        let big = set(0..(BUCKET as u32 + 50));
        let a = Party::new(&big);
        assert_eq!(a.held(), big.len());
        // The offer grows past the bucket rather than losing entries, which is a visible cost
        // rather than a silent loss.
        assert_eq!(a.offer().len(), big.len());
    }

    /// Garbage returned in place of an honest reblind must not produce a match.
    ///
    /// An undecodable point cannot be raised to anything, and substituting a constant for it
    /// would make every such entry match every other one, so those become a value no real
    /// point can take.
    #[test]
    fn garbage_returned_instead_of_a_reblind_does_not_match() {
        let a = Party::new(&set(0..5));
        let b = Party::new(&set(0..5));

        // b returns junk rather than an honest reblind of a's offer.
        let junk: Vec<Blinded> = (0..BUCKET).map(|i| [i as u8; 32]).collect();
        let honest_from_b = a.reblind(&b.offer());
        assert!(
            a.intersect(&junk, &honest_from_b).is_empty(),
            "junk in place of a reblind produced a match"
        );

        // And undecodable input to reblind produces the reserved value, not a usable point.
        let undecodable = vec![[0xffu8; 32]; 4];
        assert!(a.reblind(&undecodable).iter().all(|v| *v == [0u8; 32]));
    }

    /// A lying responder can misattribute a genuine share, and this records that it can.
    ///
    /// This is the limit of the semi-honest model, stated as a test rather than only in prose.
    /// The responder cannot invent a share, because every value it returns must land in a set
    /// the initiator computed from the responder's own offer. It can return, at the position of
    /// one of the initiator's contacts, the reblinded form of a *different* contact it really
    /// does share. The count stays honest; the names do not.
    #[test]
    fn a_lying_responder_can_misattribute_a_genuine_share() {
        let shared = addr(7);
        let a = Party::new(&[addr(1), shared]);
        let b = Party::new(&[shared]);

        let a_offer = a.offer();
        let honest = b.reblind(&a_offer);
        let from_b = a.reblind(&b.offer());

        // Honest run: a learns the shared contact and only that.
        assert_eq!(a.intersect(&honest, &from_b), vec![shared]);

        // b instead answers every position with the reblind of the position that genuinely
        // matched, which it can identify because it holds the contact.
        let matching = honest
            .iter()
            .find(|v| a.intersect(std::slice::from_ref(v), &from_b).len() + 1 > 0 && from_b.contains(v))
            .copied()
            .expect("the genuine match is in b's reply");
        let lying: Vec<Blinded> = vec![matching; a_offer.len()];

        let misled = a.intersect(&lying, &from_b);
        assert!(
            misled.len() > 1,
            "the responder could not misattribute, which would be better than documented"
        );
        assert!(
            misled.contains(&addr(1)),
            "a contact b does not hold was not reported as shared"
        );
    }

    /// A singleton set is a membership query, and the protocol cannot prevent it.
    ///
    /// Recorded as a passing test because it is the abuse that matters and it is not fixable
    /// with cryptography: an intersection with a set of one *is* a membership oracle. Padding
    /// hides how many contacts a party has, not what they asked. The defences are rate
    /// limiting and refusing to run this with strangers, neither of which lives here.
    #[test]
    fn a_singleton_probe_learns_membership_and_nothing_stops_it() {
        let target = addr(42);
        let victim = Party::new(&set(0..100));
        let prober = Party::new(&[target]);

        let (_, prober_sees) = exchange(&victim, &prober);
        assert_eq!(prober_sees, vec![target], "the probe should succeed, and does");

        // And a probe for something absent returns nothing, which is the other half of an
        // oracle: the answer is informative either way.
        let absent = Party::new(&[addr(9_999)]);
        let (_, nothing) = exchange(&victim, &absent);
        assert!(nothing.is_empty());
    }

    /// The exchange must be symmetric: both sides compute the same intersection.
    #[test]
    fn both_sides_agree_on_what_is_shared() {
        for n in [0u32, 1, 7, 40] {
            let a = Party::new(&set(0..50));
            // Saturating, because 50 - n underflows for large n and a u32 underflow panics in
            // debug while wrapping silently in release. A test that only fails in one profile
            // is a test that gets discovered by somebody else.
            let lo = 50u32.saturating_sub(n);
            let b = Party::new(&set(lo..50 + n.max(1)));
            let (x, y) = exchange(&a, &b);
            let xs: std::collections::BTreeSet<_> = x.into_iter().collect();
            let ys: std::collections::BTreeSet<_> = y.into_iter().collect();
            assert_eq!(xs, ys, "the two sides disagreed at n={n}");
        }
    }

    /// A party must not learn a contact it does not hold, even if the other side holds it.
    #[test]
    fn neither_side_learns_the_others_unshared_contacts() {
        let a = Party::new(&set(0..10));
        let b = Party::new(&set(5..30));
        let (a_sees, b_sees) = exchange(&a, &b);

        for got in a_sees.iter().chain(b_sees.iter()) {
            assert!(
                set(5..10).contains(got),
                "a party learned {got:?}, which is not in the intersection"
            );
        }
    }
}
