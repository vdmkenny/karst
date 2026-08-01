//! Knowing that you have stopped hearing.
//!
//! Issue #57. The Ricochet user deanonymised in the BKA operation was running a build that
//! lacked current guard protections. **Tor had shipped the defence. It was not on that
//! endpoint.** A defence that exists and is not running is worth nothing, and that was the
//! proximate cause in the only documented case where a real person was identified through a
//! protocol weakness rather than an endpoint compromise.
//!
//! KARST makes this harder than usual, on purpose. There is no authority to push an update
//! (error 03), no enumerable membership to count who runs what (L5), and no privileged client
//! with standing to insist (L16).
//!
//! # The mechanism, from TUF
//!
//! Samuel, Mathewson, Cappos and Dingledine, *Survivable Key Compromise in Software Update
//! Systems* (CCS 2010), designed exactly for adversarial update distribution. Two of the four
//! authors are Tor.
//!
//! The piece that matters here is the **timestamp role and its defence against freeze
//! attacks**. An adversary who simply withholds updates leaves a client believing it is
//! current, forever, with no error to notice. TUF's answer is short-expiry signed metadata: a
//! client knows what fresh metadata looks like and how often to expect it, so **silence is
//! distinguishable from "nothing new"**.
//!
//! That resolves the tension with L16 that made this hard to decide. It is not a
//! privileged-client mechanism and nobody pushes anything: the client pulls, and detects its
//! own staleness locally. No authority is required for a client to notice it has stopped
//! hearing.
//!
//! # What is here and what is not
//!
//! Freeze detection is implemented. TUF's other mechanisms map onto primitives that already
//! exist and are not wired up: threshold signing (`karst-value::shamir`), role separation, and
//! key rotation ([`crate::Rotation`]). Advisories themselves are ordinary objects distributed
//! as label sets at L15.

use core::fmt;

use karst_id::{Address, Identity};

use crate::{Dec, Enc, Object, ObjectError};

pub const TIMESTAMP_KIND: &str = "karst.timestamp.v1";

/// A signed statement that a publisher was alive and had nothing newer to say.
///
/// Expiry is the whole point. A statement without one can be replayed forever, which is the
/// freeze attack it exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub publisher: Address,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Monotonic, so an old statement cannot be replayed as a new one.
    pub sequence: u64,
    /// Digest of the advisory set this statement vouches for.
    ///
    /// **Without this, freshness is not enough.** An adversary who forwards genuine timestamps
    /// while withholding the advisories they refer to leaves a client that believes it is
    /// current and is missing exactly the update it needs. That is the freeze attack wearing a
    /// disguise, and expiry alone does not catch it. TUF's snapshot role is this commitment.
    pub snapshot: crate::Cid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    /// Heard recently and the statement has not expired.
    Fresh,
    /// The most recent statement has expired. **Assume something is wrong**, because a
    /// publisher with nothing to say still says so.
    Expired { since: u64 },
    /// A statement arrived with a sequence at or below one already seen, which is a replay.
    Rollback { seen: u64, offered: u64 },
    /// Nothing has ever been heard, which is not the same as being current.
    NeverHeard,
    /// Statements are arriving and the content they vouch for is not.
    ///
    /// An adversary forwarding genuine timestamps while withholding advisories produces this,
    /// and expiry alone would report `Fresh`.
    ContentWithheld { expected: crate::Cid },
}

impl fmt::Display for Staleness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Staleness::Fresh => write!(f, "current"),
            Staleness::Expired { since } => {
                write!(f, "no fresh statement since t{since}; assume withheld")
            }
            Staleness::Rollback { seen, offered } => {
                write!(f, "replay: already saw sequence {seen}, offered {offered}")
            }
            Staleness::NeverHeard => write!(f, "never heard from this publisher"),
            Staleness::ContentWithheld { expected } => write!(
                f,
                "statements are fresh but advisory set {} has not arrived",
                expected.short()
            ),
        }
    }
}

impl Staleness {
    /// Whether a client should act as though it may be missing a defence.
    pub fn suspect(&self) -> bool {
        !matches!(self, Staleness::Fresh)
    }
}

impl Timestamp {
    pub fn publish(
        publisher: &Identity,
        issued_at: u64,
        valid_for: u64,
        sequence: u64,
        snapshot: crate::Cid,
    ) -> Object {
        let mut e = Enc::new();
        e.u64(issued_at)
            .u64(issued_at + valid_for)
            .u64(sequence)
            .cid(&snapshot);
        Object::create(publisher, TIMESTAMP_KIND, sequence, e.finish(), None)
    }

    pub fn from_object(obj: &Object) -> Result<Timestamp, ObjectError> {
        if obj.kind != TIMESTAMP_KIND {
            return Err(ObjectError::CidMismatch);
        }
        let publisher = obj.verify()?;
        let mut d = Dec::new(&obj.payload);
        let issued_at = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let expires_at = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let sequence = d.u64().map_err(|_| ObjectError::CidMismatch)?;
        let snapshot = d.cid().map_err(|_| ObjectError::CidMismatch)?;
        d.end().map_err(|_| ObjectError::CidMismatch)?;
        Ok(Timestamp {
            publisher,
            issued_at,
            expires_at,
            sequence,
            snapshot,
        })
    }
}

/// A client's view of one publisher it expects to hear from.
#[derive(Clone, Debug)]
pub struct FreshnessMonitor {
    pub publisher: Address,
    latest: Option<Timestamp>,
}

impl FreshnessMonitor {
    pub fn new(publisher: Address) -> Self {
        FreshnessMonitor {
            publisher,
            latest: None,
        }
    }

    /// Accept a statement, rejecting replays and statements from anyone else.
    pub fn accept(&mut self, ts: Timestamp) -> Result<(), Staleness> {
        if ts.publisher != self.publisher {
            return Err(Staleness::NeverHeard);
        }
        if let Some(prev) = self.latest {
            if ts.sequence <= prev.sequence {
                return Err(Staleness::Rollback {
                    seen: prev.sequence,
                    offered: ts.sequence,
                });
            }
        }
        self.latest = Some(ts);
        Ok(())
    }

    /// **The freeze check.** Silence is not evidence of being current.
    ///
    /// `held` is the digest of the advisory set the client actually has. Passing `None` skips
    /// the content check, which is only correct for a client that has not yet fetched anything.
    pub fn status(&self, now: u64, held: Option<crate::Cid>) -> Staleness {
        match self.latest {
            None => Staleness::NeverHeard,
            Some(ts) if now > ts.expires_at => Staleness::Expired {
                since: ts.expires_at,
            },
            Some(ts) => match held {
                Some(h) if h != ts.snapshot => Staleness::ContentWithheld {
                    expected: ts.snapshot,
                },
                _ => Staleness::Fresh,
            },
        }
    }

    pub fn latest(&self) -> Option<Timestamp> {
        self.latest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cid;

    fn snap(tag: &[u8]) -> Cid {
        Cid::of(tag)
    }

    fn ts(id: &Identity, at: u64, valid: u64, seq: u64, s: Cid) -> Timestamp {
        Timestamp::from_object(&Timestamp::publish(id, at, valid, seq, s)).unwrap()
    }

    #[test]
    fn a_fresh_statement_with_matching_content_is_current() {
        let pubr = Identity::generate();
        let s = snap(b"advisories v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        m.accept(ts(&pubr, 100, 50, 1, s)).unwrap();
        assert_eq!(m.status(120, Some(s)), Staleness::Fresh);
        assert!(!m.status(120, Some(s)).suspect());
    }

    /// **The freeze attack.** Withholding updates leaves a client believing it is current,
    /// forever, with no error to notice. Expiry turns silence into a signal.
    #[test]
    fn withheld_statements_become_visible_rather_than_silent() {
        let pubr = Identity::generate();
        let s = snap(b"v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        m.accept(ts(&pubr, 100, 50, 1, s)).unwrap();

        assert_eq!(m.status(150, Some(s)), Staleness::Fresh);
        assert_eq!(m.status(151, Some(s)), Staleness::Expired { since: 150 });
        assert!(m.status(151, Some(s)).suspect());
    }

    #[test]
    fn never_hearing_is_not_the_same_as_being_current() {
        let pubr = Identity::generate();
        let m = FreshnessMonitor::new(pubr.address());
        assert_eq!(m.status(0, None), Staleness::NeverHeard);
        assert!(m.status(0, None).suspect());
    }

    #[test]
    fn an_old_statement_cannot_be_replayed() {
        let pubr = Identity::generate();
        let s = snap(b"v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        m.accept(ts(&pubr, 100, 50, 5, s)).unwrap();

        assert_eq!(
            m.accept(ts(&pubr, 90, 50, 3, s)),
            Err(Staleness::Rollback { seen: 5, offered: 3 })
        );
        assert_eq!(
            m.accept(ts(&pubr, 100, 50, 5, s)),
            Err(Staleness::Rollback { seen: 5, offered: 5 }),
            "the same sequence again is also a replay"
        );
    }

    #[test]
    fn a_statement_from_somebody_else_is_not_accepted() {
        let pubr = Identity::generate();
        let impostor = Identity::generate();
        let mut m = FreshnessMonitor::new(pubr.address());
        assert!(m.accept(ts(&impostor, 100, 50, 1, snap(b"v1"))).is_err());
        assert_eq!(m.status(100, None), Staleness::NeverHeard);
    }

    #[test]
    fn a_tampered_statement_does_not_verify() {
        let pubr = Identity::generate();
        let obj = Timestamp::publish(&pubr, 100, 50, 1, snap(b"v1"));

        // Rubbish is refused, but only because it stops decoding: the signature check is never
        // reached, so this alone would pass with verification removed entirely.
        assert!(Timestamp::from_object(&obj.tamper(vec![0u8; 40])).is_err());

        // A payload that is still a perfectly valid encoding of a *different* statement. Now
        // only the signature can reject it, which is the property the name claims.
        let forged = Timestamp::publish(&pubr, 100, 5_000_000, 1, snap(b"v1"));
        let swapped = obj.tamper(forged.payload.clone());
        assert!(
            Timestamp::from_object(&swapped).is_err(),
            "a validly encoded but unsigned payload was accepted"
        );
        // And the untouched original still verifies, so the refusals above are about tampering.
        assert!(Timestamp::from_object(&obj).is_ok());
    }

    #[test]
    fn continuing_to_hear_keeps_a_client_current() {
        let pubr = Identity::generate();
        let s = snap(b"v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        for i in 1..10u64 {
            m.accept(ts(&pubr, i * 100, 150, i, s)).unwrap();
            assert_eq!(m.status(i * 100 + 10, Some(s)), Staleness::Fresh);
        }
    }
}

/// Attacks on the detector itself.
#[cfg(test)]
mod adversarial {
    use super::*;
    use crate::Cid;

    fn snap(tag: &[u8]) -> Cid {
        Cid::of(tag)
    }
    fn ts(id: &Identity, at: u64, valid: u64, seq: u64, s: Cid) -> Timestamp {
        Timestamp::from_object(&Timestamp::publish(id, at, valid, seq, s)).unwrap()
    }

    /// **The slow drip.** An adversary who forwards genuine, fresh, correctly-sequenced
    /// timestamps while withholding the advisories they refer to defeats an expiry-only
    /// detector completely: the client reports current and is missing exactly the update it
    /// needs. That is the Ricochet failure with extra steps.
    ///
    /// The snapshot commitment is what catches it.
    #[test]
    fn forwarding_statements_while_withholding_content_is_caught() {
        let pubr = Identity::generate();
        let mut m = FreshnessMonitor::new(pubr.address());

        // The publisher has moved on to v2 and says so.
        m.accept(ts(&pubr, 100, 50, 2, snap(b"advisories v2"))).unwrap();

        // The client still holds v1, because the adversary blocked the fetch.
        let status = m.status(120, Some(snap(b"advisories v1")));
        assert_eq!(
            status,
            Staleness::ContentWithheld {
                expected: snap(b"advisories v2")
            }
        );
        assert!(status.suspect(), "a client missing content must know it");
    }

    /// A client whose clock runs backwards, or is set back by an adversary with local access,
    /// treats expired statements as fresh. The mechanism cannot fix this and the limit is
    /// worth stating: **expiry checks are only as good as the clock**.
    #[test]
    fn a_backdated_clock_defeats_expiry_and_that_is_a_known_limit() {
        let pubr = Identity::generate();
        let s = snap(b"v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        m.accept(ts(&pubr, 100, 50, 1, s)).unwrap();

        assert_eq!(m.status(200, Some(s)), Staleness::Expired { since: 150 });
        // The same monitor, asked about an earlier moment, reports fresh.
        assert_eq!(m.status(120, Some(s)), Staleness::Fresh);
    }

    /// A publisher that issues very long validity windows makes freeze detection useless
    /// without ever being caught lying, so validity is a security parameter rather than a
    /// convenience.
    #[test]
    fn a_long_validity_window_silently_disables_the_detector() {
        let pubr = Identity::generate();
        let s = snap(b"v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        // Valid for a very long time.
        m.accept(ts(&pubr, 0, u64::MAX / 2, 1, s)).unwrap();

        // Years later, still nominally fresh, and the client has heard nothing since.
        assert_eq!(m.status(1_000_000_000, Some(s)), Staleness::Fresh);
    }

    /// A sequence jump is not by itself evidence of anything, since statements are fetched
    /// rather than pushed and a client may simply have missed some. Only going backwards is.
    #[test]
    fn a_forward_sequence_jump_is_accepted_and_a_backward_one_is_not() {
        let pubr = Identity::generate();
        let s = snap(b"v1");
        let mut m = FreshnessMonitor::new(pubr.address());
        m.accept(ts(&pubr, 100, 50, 1, s)).unwrap();
        assert!(m.accept(ts(&pubr, 200, 50, 900, s)).is_ok());
        assert!(m.accept(ts(&pubr, 300, 50, 899, s)).is_err());
    }
}
