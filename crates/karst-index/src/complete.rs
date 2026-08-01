//! Telling a sparse topic from a suppressed one.
//!
//! For a layer whose premise is that publishing *is* indexing, **completeness is the property
//! under attack**, and it is the one property content addressing cannot defend. Castro,
//! Druschel, Ganesh, Rowstron and Wallach (OSDI 2002) are explicit about this: self-certifying
//! data removes the need for secure routing when fetching, because the hash is checked, and it
//! gives nothing when verifying that an object is **not** stored.
//!
//! Every mechanism in `karst-index` verifies what a reader receives. None of them says anything
//! about what a reader did not receive, so an adversary who forwards a subset of a publisher's
//! announcements, or none, is unaffected by all of it. A reader searching a topic with no
//! results and a reader whose results were withheld see exactly the same thing.
//!
//! # A publisher commits to what they have said
//!
//! The mechanism already exists one layer down. `karst_object::freshness` implements TUF's
//! timestamp role: expiring signed statements, a monotonic sequence so an old one cannot be
//! replayed, and a **snapshot commitment** so a party forwarding genuine fresh statements while
//! withholding what they refer to is detected rather than believed.
//!
//! A [`Census`] is that applied to an index. A publisher periodically signs how many
//! announcements they have made and a digest over them. A reader holding fewer than the count
//! knows entries are missing, and knows **how many**, without knowing which.
//!
//! # What this can and cannot see
//!
//! It detects withholding of a publisher's **own** entries by anyone between them and the
//! reader, because the publisher's own signature says how many there should be.
//!
//! It does nothing about a publisher a reader has never heard of. **A reader cannot miss what
//! they do not know exists**, and no commitment by a publisher helps a reader who never
//! received one. That residue is the same one Tor's v3 blinded descriptors leave, and it is
//! not closed here or anywhere else that I know of.
//!
//! Two limits inherited from `freshness` carry over unchanged: expiry is only as good as the
//! reader's clock, and a publisher issuing very long validity windows disables the detector
//! without ever lying, so validity is a security parameter rather than a convenience.

use std::collections::BTreeSet;

use karst_id::{Address, Identity};
use karst_object::{Cid, Dec, Enc, Object, ObjectError};

use crate::{Announcement, Catalogue};

pub const CENSUS_KIND: &str = "karst.index.census.v1";

/// A publisher's signed statement of how much they have published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Census {
    pub publisher: Address,
    /// How many announcements this publisher has made, ever.
    pub announced: u64,
    /// Digest over the set of announcement targets, so a reader holding the wrong ones, rather
    /// than merely too few, also finds out.
    pub digest: Cid,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Monotonic, so an old census cannot be replayed to make a reader believe they are
    /// current when the publisher has said more since.
    pub sequence: u64,
}

/// What a reader concludes by comparing what they hold against what was committed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completeness {
    /// Holding everything the publisher committed to, and the commitment is current.
    Complete,
    /// Holding fewer than the publisher says exist. Somebody between them is withholding.
    Missing { held: u64, announced: u64 },
    /// The right number, and not the right ones.
    Divergent { expected: Cid, held: Cid },
    /// The commitment has expired, so nothing can be concluded from it.
    Expired { since: u64 },
    /// No commitment held. Indistinguishable from a publisher who has never made one.
    Unknown,
}

impl Completeness {
    /// Whether a reader should act as though they may be missing something.
    ///
    /// `Unknown` counts. A reader who has heard no commitment is in exactly the position this
    /// mechanism exists to remove them from, and reporting that as fine would be the whole
    /// failure wearing the mechanism's name.
    pub fn suspect(&self) -> bool {
        !matches!(self, Completeness::Complete)
    }
}

/// Digest over a set of announcement targets.
///
/// Sorted, so the digest depends on the set and not on the order a reader happened to hear
/// them in. Two readers holding the same announcements must compute the same value or the
/// comparison is worthless.
pub fn digest_of(targets: &BTreeSet<Cid>) -> Cid {
    let mut e = Enc::new();
    e.str("karst.index.census.digest.v1")
        .u64(targets.len() as u64);
    for t in targets {
        e.cid(t);
    }
    Cid::of(&e.finish())
}

impl Census {
    /// Build and sign a census over everything a publisher has announced.
    pub fn publish(
        publisher: &Identity,
        targets: &BTreeSet<Cid>,
        issued_at: u64,
        valid_for: u64,
        sequence: u64,
    ) -> Object {
        let mut e = Enc::new();
        e.u64(targets.len() as u64)
            .cid(&digest_of(targets))
            .u64(issued_at)
            .u64(issued_at + valid_for)
            .u64(sequence);
        Object::create(publisher, CENSUS_KIND, sequence, e.finish(), None)
    }

    /// Recover a census from a signed object.
    ///
    /// The publisher comes from the verified signature, never from the payload, for the same
    /// reason announcements do: a source that can be impersonated is not a source.
    pub fn from_object(obj: &Object) -> Result<Census, ObjectError> {
        if obj.kind != CENSUS_KIND {
            return Err(ObjectError::CidMismatch);
        }
        let publisher = obj.verify()?;
        let mut d = Dec::new(&obj.payload);
        let announced = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let digest = d.cid().map_err(|_| ObjectError::CidMismatch)?;
        let issued_at = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let expires_at = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let sequence = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        d.end().map_err(|_| ObjectError::CidMismatch)?;
        Ok(Census {
            publisher,
            announced,
            digest,
            issued_at,
            expires_at,
            sequence,
        })
    }
}

/// A reader's view of one publisher's completeness.
#[derive(Debug, Clone, Default)]
pub struct CensusMonitor {
    latest: Option<Census>,
}

impl CensusMonitor {
    pub fn new() -> Self {
        CensusMonitor::default()
    }

    /// Take a census, refusing anything older than what is already held.
    ///
    /// Without the sequence check, replaying an old census makes a reader believe they are
    /// complete when the publisher has said more since, which is the freeze attack arriving
    /// through the detector rather than around it.
    pub fn accept(&mut self, c: Census) -> bool {
        match &self.latest {
            Some(held) if c.sequence <= held.sequence => false,
            _ => {
                self.latest = Some(c);
                true
            }
        }
    }

    pub fn latest(&self) -> Option<&Census> {
        self.latest.as_ref()
    }

    /// Compare a catalogue against what the publisher committed to.
    pub fn check(&self, cat: &Catalogue, now: u64) -> Completeness {
        let Some(c) = &self.latest else {
            return Completeness::Unknown;
        };
        if now >= c.expires_at {
            return Completeness::Expired {
                since: c.expires_at,
            };
        }
        let held: BTreeSet<Cid> = cat
            .announcements()
            .filter(|a: &&Announcement| a.author == c.publisher)
            .map(|a| a.target)
            .collect();

        if (held.len() as u64) < c.announced {
            return Completeness::Missing {
                held: held.len() as u64,
                announced: c.announced,
            };
        }
        let d = digest_of(&held);
        if d != c.digest {
            return Completeness::Divergent {
                expected: c.digest,
                held: d,
            };
        }
        Completeness::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rank::Trust;
    use crate::Verdict;

    fn ident(n: u32) -> Identity {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        Identity::from_seed(seed)
    }

    fn terms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn announce(cat: &mut Catalogue, who: &Identity, target: Cid, trust: &Trust) {
        let obj = Announcement::new(target, who.address(), "doc", &terms(&["topic"]), 0)
            .unwrap()
            .publish(who, 0);
        cat.announce(Announcement::from_object(&obj).unwrap(), trust);
    }

    fn targets(n: u32) -> BTreeSet<Cid> {
        (0..n).map(|i| Cid::of(&i.to_le_bytes())).collect()
    }

    /// A reader holding everything is told so.
    #[test]
    fn holding_everything_reads_as_complete() {
        let pubr = ident(1);
        let mut t = Trust::new();
        t.set(pubr.address(), 1.0);
        let mut cat = Catalogue::new();
        for target in targets(5) {
            announce(&mut cat, &pubr, target, &t);
        }

        let obj = Census::publish(&pubr, &targets(5), 100, 1_000, 1);
        let mut m = CensusMonitor::new();
        assert!(m.accept(Census::from_object(&obj).unwrap()));
        assert_eq!(m.check(&cat, 200), Completeness::Complete);
        assert!(!m.check(&cat, 200).suspect());
    }

    /// A reader holding fewer than were committed to learns how many are missing.
    ///
    /// This is the whole point: without it, a suppressed topic and a sparse one are the same
    /// observation.
    #[test]
    fn withholding_is_visible_and_counted() {
        let pubr = ident(1);
        let mut t = Trust::new();
        t.set(pubr.address(), 1.0);
        let mut cat = Catalogue::new();
        // Somebody between the publisher and this reader forwarded three of eight.
        for target in targets(3) {
            announce(&mut cat, &pubr, target, &t);
        }

        let obj = Census::publish(&pubr, &targets(8), 100, 1_000, 1);
        let mut m = CensusMonitor::new();
        m.accept(Census::from_object(&obj).unwrap());
        assert_eq!(
            m.check(&cat, 200),
            Completeness::Missing {
                held: 3,
                announced: 8
            }
        );
        assert!(m.check(&cat, 200).suspect());
    }

    /// The right number of the wrong entries must also be caught.
    #[test]
    fn substituting_entries_is_caught_by_the_digest() {
        let pubr = ident(1);
        let mut t = Trust::new();
        t.set(pubr.address(), 1.0);
        let mut cat = Catalogue::new();
        // Five announcements, but not the five committed to.
        for i in 100..105u32 {
            announce(&mut cat, &pubr, Cid::of(&i.to_le_bytes()), &t);
        }

        let obj = Census::publish(&pubr, &targets(5), 100, 1_000, 1);
        let mut m = CensusMonitor::new();
        m.accept(Census::from_object(&obj).unwrap());
        assert!(matches!(
            m.check(&cat, 200),
            Completeness::Divergent { .. }
        ));
    }

    /// A reader with no commitment must be told they cannot conclude anything.
    ///
    /// Reporting that as healthy would be the failure this exists to remove, wearing the
    /// mechanism's name.
    #[test]
    fn no_census_is_suspect_rather_than_fine() {
        let cat = Catalogue::new();
        let m = CensusMonitor::new();
        assert_eq!(m.check(&cat, 0), Completeness::Unknown);
        assert!(m.check(&cat, 0).suspect());
    }

    /// An expired census must not be treated as evidence of anything.
    #[test]
    fn an_expired_census_concludes_nothing() {
        let pubr = ident(1);
        let obj = Census::publish(&pubr, &targets(3), 100, 50, 1);
        let mut m = CensusMonitor::new();
        m.accept(Census::from_object(&obj).unwrap());
        let cat = Catalogue::new();
        assert!(matches!(m.check(&cat, 999), Completeness::Expired { .. }));
        assert!(m.check(&cat, 999).suspect());
    }

    /// Replaying an old census must not make a reader believe they are current.
    #[test]
    fn an_old_census_cannot_be_replayed_over_a_newer_one() {
        let pubr = ident(1);
        let newer = Census::from_object(&Census::publish(&pubr, &targets(9), 200, 1_000, 7))
            .unwrap();
        let older = Census::from_object(&Census::publish(&pubr, &targets(2), 100, 1_000, 3))
            .unwrap();

        let mut m = CensusMonitor::new();
        assert!(m.accept(newer));
        assert!(!m.accept(older.clone()), "an older census was accepted");
        assert_eq!(m.latest().unwrap().announced, 9);
        // And a census at the same sequence, which is the cheapest forgery to try.
        assert!(!m.accept(older));
    }

    /// A census must not be forgeable in another publisher's name.
    #[test]
    fn a_census_cannot_be_minted_for_someone_else() {
        let victim = ident(1);
        let forger = ident(2);
        let obj = Census::publish(&forger, &targets(0), 100, 1_000, 1);
        let recovered = Census::from_object(&obj).unwrap();
        assert_eq!(recovered.publisher, forger.address());
        assert_ne!(recovered.publisher, victim.address());
    }

    /// The digest must depend on the set and not on arrival order.
    ///
    /// Two readers holding the same announcements have to compute the same value, or the
    /// comparison detects nothing but the order things happened to arrive in.
    #[test]
    fn the_digest_is_order_independent() {
        let forward: BTreeSet<Cid> = (0..20u32).map(|i| Cid::of(&i.to_le_bytes())).collect();
        let backward: BTreeSet<Cid> = (0..20u32).rev().map(|i| Cid::of(&i.to_le_bytes())).collect();
        assert_eq!(digest_of(&forward), digest_of(&backward));
        // And on the set, so one missing entry changes it.
        let mut fewer = forward.clone();
        fewer.remove(&Cid::of(&7u32.to_le_bytes()));
        assert_ne!(digest_of(&forward), digest_of(&fewer));
    }

    /// Another publisher's announcements must not count toward this publisher's census.
    ///
    /// Otherwise a flood of unrelated announcements from anyone would make a withheld feed
    /// look complete, which turns the detector into a way of hiding the thing it detects.
    #[test]
    fn another_publishers_entries_do_not_fill_the_count() {
        let pubr = ident(1);
        let stranger = ident(2);
        let mut t = Trust::new();
        t.set(pubr.address(), 1.0);
        t.set(stranger.address(), 1.0);
        let mut cat = Catalogue::new();

        announce(&mut cat, &pubr, Cid::of(&0u32.to_le_bytes()), &t);
        for i in 50..70u32 {
            announce(&mut cat, &stranger, Cid::of(&i.to_le_bytes()), &t);
        }

        let obj = Census::publish(&pubr, &targets(6), 100, 1_000, 1);
        let mut m = CensusMonitor::new();
        m.accept(Census::from_object(&obj).unwrap());
        assert_eq!(
            m.check(&cat, 200),
            Completeness::Missing {
                held: 1,
                announced: 6
            },
            "a stranger's announcements filled in for a withheld publisher"
        );
    }

    /// Claims are not announcements and must not count either.
    #[test]
    fn claims_do_not_count_toward_a_census() {
        let pubr = ident(1);
        let mut t = Trust::new();
        t.set(pubr.address(), 1.0);
        let mut cat = Catalogue::new();

        for i in 0..6u32 {
            let target = Cid::of(&i.to_le_bytes());
            let obj = crate::Claim::new(target, pubr.address(), Verdict::Commend, &terms(&["topic"]), 0)
                .unwrap()
                .publish(&pubr, i as u64);
            cat.claim(crate::Claim::from_object(&obj).unwrap(), &t);
        }

        let obj = Census::publish(&pubr, &targets(6), 100, 1_000, 1);
        let mut m = CensusMonitor::new();
        m.accept(Census::from_object(&obj).unwrap());
        assert_eq!(
            m.check(&cat, 200),
            Completeness::Missing {
                held: 0,
                announced: 6
            },
            "claims were counted as announcements"
        );
    }
}
