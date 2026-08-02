//! L1 Path.
//!
//! # The bug
//!
//! One global routing consensus means one operator's mistake, or one operator's compliance with
//! an order, becomes everybody's outage. BGP has no notion of who is entitled to announce a
//! prefix: an announcement is believed because it was made, so a network that claims a route it
//! does not operate is indistinguishable from one that does until somebody notices.
//!
//! # The mechanism
//!
//! An operator signs the **segments it is willing to carry**, and a sender composes an
//! end-to-end path from segments it holds. There is no convergence, because there is nothing to
//! converge on; there is no allocation authority to revoke from, because nothing was allocated.
//!
//! This is SCION's design rather than a new one.
//!
//! # What a signature buys and what it does not
//!
//! A segment is a **claim of willingness by a named party**, not a promise of delivery. Signing
//! removes exactly one thing: announcing a route you do not operate. It does not stop an
//! operator dropping traffic it agreed to carry, and no signature can, because carriage is a
//! future act and a signature is about the present.
//!
//! So the property is narrow and worth stating narrowly: **a path names, in advance and
//! verifiably, every party that must misbehave for it to fail.** Attribution rather than
//! prevention, which is the shape this design keeps arriving at.
//!
//! # Selection is not made here
//!
//! Which of several valid paths a sender takes is an L4 question and deliberately not answered
//! by this module. A structural preference relay operators can read is a placement target: an
//! adversary with 0.216% of Tor's bandwidth reached 18.22% of guard selections against
//! location-aware selection algorithms (Wan, Johnson, Wails, Wagh, Mittal, PoPETs 2019(4)).
//! Nothing here ranks, scores or prefers, and `compose` returns paths in a deterministic order
//! that carries no preference.

use std::collections::BTreeMap;

use karst_id::{Address, Identity, Peer, Signature};
use karst_object::Enc;

/// A point a segment can start or end at. An operator's own identifier, not an allocation.
pub type Point = Address;

/// One operator's signed statement that it will carry from `from` to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Who is willing to carry it. Taken from the verified signature, never from the payload.
    pub operator: Address,
    pub from: Point,
    pub to: Point,
    /// Not valid at or after this. A segment with no expiry is a standing claim nobody can
    /// withdraw, which is the durability that made stale BGP announcements dangerous.
    pub expires_at: u64,
    signature: Signature,
    key: [u8; 32],
}

fn signing_bytes(operator: &Address, from: &Point, to: &Point, expires_at: u64) -> Vec<u8> {
    let mut e = Enc::new();
    e.str("karst.path.segment.v1")
        .addr(operator)
        .addr(from)
        .addr(to)
        .u64(expires_at);
    e.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// The signature did not check, or the key does not match the claimed operator.
    Unsigned,
    /// A segment had expired.
    Expired { at: u64 },
    /// Consecutive segments do not meet.
    Disjoint,
    /// A path visited the same point twice.
    Loop,
    /// No segments at all.
    Empty,
    /// Longer than a sender will carry.
    TooLong,
    /// The store already holds as many segments from this point as it will keep.
    ///
    /// Identities are free by design, so an adversary mints operators and hands over as many
    /// individually valid segments as it likes. Refusing at the door is what keeps the
    /// composition search from being handed its own input size.
    TooMany,
}

/// The most segments in one path.
///
/// A path is carried in the packet, so its length is bytes on every hop. It is also an
/// amplification bound: without it a sender could be handed a path that costs more to carry
/// than to construct.
pub const MAX_SEGMENTS: usize = 8;

impl Segment {
    /// Sign a willingness to carry.
    pub fn offer(operator: &Identity, from: Point, to: Point, expires_at: u64) -> Segment {
        let addr = operator.address();
        let sig = operator.sign(&signing_bytes(&addr, &from, &to, expires_at));
        Segment {
            operator: addr,
            from,
            to,
            expires_at,
            signature: sig,
            key: operator.key_bytes(),
        }
    }

    /// Check the signature against the key carried with it, and that the key is the operator.
    ///
    /// An address is the hash of a verifying key, so the key must travel with the segment and
    /// the two must agree. Checking only the signature would let anyone re-label a valid
    /// segment with a different operator.
    pub fn verify(&self) -> Result<(), PathError> {
        let peer = Peer::from_key_bytes(&self.key).map_err(|_| PathError::Unsigned)?;
        if peer.address() != self.operator {
            return Err(PathError::Unsigned);
        }
        peer.verify(
            &signing_bytes(&self.operator, &self.from, &self.to, self.expires_at),
            &self.signature,
        )
        .map_err(|_| PathError::Unsigned)
    }

    pub fn valid_at(&self, now: u64) -> bool {
        now < self.expires_at
    }
}

/// A composed end-to-end path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    segments: Vec<Segment>,
}

impl Path {
    /// Build a path from segments, verifying every one.
    ///
    /// Verification here rather than at use, so a `Path` that exists is a path that checked.
    pub fn assemble(segments: Vec<Segment>, now: u64) -> Result<Path, PathError> {
        if segments.is_empty() {
            return Err(PathError::Empty);
        }
        if segments.len() > MAX_SEGMENTS {
            return Err(PathError::TooLong);
        }
        let mut visited = vec![segments[0].from];
        for (i, s) in segments.iter().enumerate() {
            s.verify()?;
            if !s.valid_at(now) {
                return Err(PathError::Expired { at: s.expires_at });
            }
            if i > 0 && segments[i - 1].to != s.from {
                return Err(PathError::Disjoint);
            }
            // A repeated point is a loop, which costs carriage and buys the sender nothing.
            // Refusing here means a hostile segment set cannot be assembled into one.
            if visited.contains(&s.to) {
                return Err(PathError::Loop);
            }
            visited.push(s.to);
        }
        Ok(Path { segments })
    }

    pub fn source(&self) -> Point {
        self.segments[0].from
    }

    pub fn destination(&self) -> Point {
        self.segments[self.segments.len() - 1].to
    }

    pub fn hops(&self) -> usize {
        self.segments.len()
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Every party that must misbehave for this path to fail.
    ///
    /// The honest statement of what a signed path gives: not that it will work, but that if it
    /// does not, this is the list.
    pub fn accountable(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self.segments.iter().map(|s| s.operator).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// What a sender knows about who is willing to carry what.
///
/// Deliberately not a routing table. Nothing here converges, nothing is advertised onward, and
/// two senders holding different segment sets are both correct.
#[derive(Debug, Default)]
pub struct Segments {
    by_from: BTreeMap<Point, Vec<Segment>>,
}

impl Segments {
    /// Segments kept per starting point.
    ///
    /// A sender needs a handful of ways out of any given point; it does not need every offer
    /// in the world, and holding them all is how the search below gets its exponent.
    pub const MAX_PER_POINT: usize = 64;
    /// Paths one composition will return.
    pub const MAX_PATHS: usize = 256;
    /// Search steps one composition will take, whether or not they reach anywhere.
    pub const MAX_VISITS: usize = 1 << 16;

    pub fn new() -> Self {
        Segments::default()
    }

    /// Take a segment, verifying it first.
    ///
    /// Refusing unverified segments at the door means the store never holds one, so a later
    /// composition cannot accidentally trust something nobody signed.
    pub fn learn(&mut self, s: Segment) -> Result<(), PathError> {
        s.verify()?;
        let e = self.by_from.entry(s.from).or_default();
        if e.contains(&s) {
            return Ok(());
        }
        if e.len() >= Self::MAX_PER_POINT {
            return Err(PathError::TooMany);
        }
        e.push(s);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.by_from.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every valid path from `from` to `to`, up to `MAX_SEGMENTS` and [`Segments::MAX_PATHS`].
    ///
    /// Returned in a deterministic order that carries no preference. Ranking paths is an L4
    /// decision, and a structural preference relay operators can read is a placement target.
    ///
    /// # Why this is bounded twice
    ///
    /// `MAX_SEGMENTS` bounds path *length* and says nothing about path *count*. With `k`
    /// segments between each consecutive pair of points, an eight-point chain has `k^7`
    /// paths: at `k = 20` that is 1.28 billion `Path` values built and cloned inside one
    /// call, from segments that are each individually valid and correctly signed. The
    /// enumeration is the attack, not the segments.
    ///
    /// So the search is bounded on output (`MAX_PATHS`) and on work (`MAX_VISITS`), because
    /// the two are not the same: a search can explore exponentially many branches that reach
    /// no destination at all and return nothing while doing it.
    pub fn compose(&self, from: Point, to: Point, now: u64) -> Vec<Path> {
        let mut out = Vec::new();
        let mut stack: Vec<Segment> = Vec::new();
        let mut visits = 0usize;
        self.walk(from, to, now, &mut stack, &mut out, &mut visits);
        out.sort_by_key(|p| {
            (
                p.hops(),
                p.segments.iter().map(|s| s.operator).collect::<Vec<_>>(),
            )
        });
        out
    }

    fn walk(
        &self,
        at: Point,
        to: Point,
        now: u64,
        stack: &mut Vec<Segment>,
        out: &mut Vec<Path>,
        visits: &mut usize,
    ) {
        if stack.len() >= MAX_SEGMENTS || out.len() >= Self::MAX_PATHS {
            return;
        }
        if *visits >= Self::MAX_VISITS {
            return;
        }
        *visits += 1;
        let Some(next) = self.by_from.get(&at) else {
            return;
        };
        for s in next {
            if !s.valid_at(now) {
                continue;
            }
            // No point twice, which bounds the search and refuses loops before building them.
            if stack.iter().any(|p| p.to == s.to) || stack.first().is_some_and(|f| f.from == s.to) {
                continue;
            }
            stack.push(s.clone());
            if s.to == to {
                if let Ok(p) = Path::assemble(stack.clone(), now) {
                    out.push(p);
                }
            } else {
                self.walk(s.to, to, now, stack, out, visits);
            }
            stack.pop();
            if out.len() >= Self::MAX_PATHS || *visits >= Self::MAX_VISITS {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(n: u32) -> Identity {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        Identity::from_seed(seed)
    }

    fn pt(n: u32) -> Point {
        op(n + 10_000).address()
    }

    /// Individually valid segments, arranged so that enumerating them is the attack.
    ///
    /// `k` operators offer carriage between each consecutive pair of points along a chain,
    /// which is a completely ordinary thing for a competitive network to look like. Every
    /// signature checks. `MAX_SEGMENTS` bounds the length of each path and does nothing about
    /// there being `k^7` of them.
    #[test]
    fn a_dense_mesh_does_not_hand_the_sender_an_exponential() {
        let mut segs = Segments::new();
        let mut refused = 0;
        for hop in 0..8u32 {
            for k in 0..20u32 {
                if segs
                    .learn(Segment::offer(
                        &op(hop * 100 + k),
                        pt(hop),
                        pt(hop + 1),
                        100,
                    ))
                    .is_err()
                {
                    refused += 1;
                }
            }
        }
        assert_eq!(refused, 0, "twenty ways out of a point is not a flood");

        let start = std::time::Instant::now();
        let paths = segs.compose(pt(0), pt(8), 0);
        assert!(
            paths.len() <= Segments::MAX_PATHS,
            "returned {} paths",
            paths.len()
        );
        assert!(
            start.elapsed().as_secs() < 5,
            "composition took {:?}",
            start.elapsed()
        );
    }

    /// A store bounds what it holds, so the search cannot be handed its own input size.
    #[test]
    fn a_store_refuses_more_ways_out_of_a_point_than_it_will_keep() {
        let mut segs = Segments::new();
        let mut accepted = 0;
        for k in 0..(Segments::MAX_PER_POINT as u32 + 500) {
            if segs.learn(Segment::offer(&op(k), pt(0), pt(k + 1), 100)).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, Segments::MAX_PER_POINT);
        assert_eq!(
            segs.learn(Segment::offer(&op(9999), pt(0), pt(9998), 100)),
            Err(PathError::TooMany)
        );
    }

    /// A search that reaches nowhere must still stop.
    ///
    /// Output caps do not bound work: a dense mesh with no route to the destination explores
    /// exponentially many branches and returns an empty vector while doing it.
    #[test]
    fn a_search_that_finds_nothing_still_terminates() {
        let mut segs = Segments::new();
        for hop in 0..8u32 {
            for k in 0..20u32 {
                segs.learn(Segment::offer(&op(hop * 100 + k), pt(hop), pt(hop + 1), 100))
                    .unwrap();
            }
        }
        let start = std::time::Instant::now();
        assert!(segs.compose(pt(0), pt(9999), 0).is_empty());
        assert!(start.elapsed().as_secs() < 5, "took {:?}", start.elapsed());
    }

    /// A sender composes a path with nothing consulted but segments it holds.
    #[test]
    fn a_sender_composes_a_path_from_what_it_holds() {
        let mut segs = Segments::new();
        segs.learn(Segment::offer(&op(1), pt(0), pt(1), 100)).unwrap();
        segs.learn(Segment::offer(&op(2), pt(1), pt(2), 100)).unwrap();

        let paths = segs.compose(pt(0), pt(2), 0);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hops(), 2);
        assert_eq!(paths[0].source(), pt(0));
        assert_eq!(paths[0].destination(), pt(2));
        assert_eq!(paths[0].accountable(), vec![op(1).address(), op(2).address()].tap());
    }

    trait Tap {
        fn tap(self) -> Self;
    }
    impl Tap for Vec<Address> {
        fn tap(mut self) -> Self {
            self.sort();
            self.dedup();
            self
        }
    }

    /// Nobody can announce a route they do not operate, which is the whole of the BGP fix.
    ///
    /// An announcement in BGP is believed because it was made. Here a segment carries its
    /// operator's key and the address is that key's hash, so relabelling one is not a matter of
    /// being believed, it is a matter of producing a signature nobody can produce.
    #[test]
    fn a_segment_cannot_be_announced_for_an_operator_you_do_not_control() {
        let honest = op(1);
        let attacker = op(2);
        let genuine = Segment::offer(&honest, pt(0), pt(1), 100);
        assert!(genuine.verify().is_ok());

        // Relabelling the operator while keeping the signature.
        let mut relabelled = genuine.clone();
        relabelled.operator = attacker.address();
        assert_eq!(relabelled.verify(), Err(PathError::Unsigned));

        // Substituting the attacker's key, so key and operator agree but the signature does not.
        let mut swapped = genuine.clone();
        swapped.operator = attacker.address();
        swapped.key = attacker.key_bytes();
        assert_eq!(swapped.verify(), Err(PathError::Unsigned));

        // And a segment the attacker signs is theirs, naming them, which is the point: it is
        // not a forgery, it is an offer nobody has to accept.
        let theirs = Segment::offer(&attacker, pt(0), pt(1), 100);
        assert!(theirs.verify().is_ok());
        assert_eq!(theirs.operator, attacker.address());
    }

    /// An attacker signing bytes that name somebody else must be refused.
    ///
    /// The two mutations above are caught by the signature alone, because the operator is
    /// inside the signed bytes: altering it invalidates the signature. Neither exercises the
    /// operator-to-key binding, and removing that check left the whole test passing.
    ///
    /// The case it actually protects cannot be built through `Segment::offer`, which always
    /// sets the operator to the signer. An attacker constructs the struct directly: sign bytes
    /// naming the **victim**, and present your own key. The signature then verifies under that
    /// key, and without the binding the segment reads as the victim's. That is announcing a
    /// route you do not operate, which is the one thing this layer exists to prevent.
    #[test]
    fn signing_bytes_that_name_someone_else_does_not_make_them_the_operator() {
        let victim = op(1);
        let attacker = op(2);
        let (from, to, exp) = (pt(0), pt(1), 100u64);

        // Bytes that name the victim, signed by the attacker, presented with the attacker's key.
        let bytes = signing_bytes(&victim.address(), &from, &to, exp);
        let forged = Segment {
            operator: victim.address(),
            from,
            to,
            expires_at: exp,
            signature: attacker.sign(&bytes),
            key: attacker.key_bytes(),
        };

        // The signature really does verify under the key presented, which is why the binding
        // is load bearing rather than redundant.
        let peer = Peer::from_key_bytes(&forged.key).unwrap();
        assert!(peer.verify(&bytes, &forged.signature).is_ok());

        assert_eq!(
            forged.verify(),
            Err(PathError::Unsigned),
            "an attacker announced a segment as the victim"
        );

        // And a store refuses to hold it, so composition never sees it.
        let mut segs = Segments::new();
        assert_eq!(segs.learn(forged), Err(PathError::Unsigned));
        assert!(segs.is_empty());
    }

    /// Altering any field of a segment must break it.
    #[test]
    fn no_field_of_a_segment_can_be_altered() {
        let s = Segment::offer(&op(1), pt(0), pt(1), 100);
        let mut a = s.clone();
        a.from = pt(9);
        assert_eq!(a.verify(), Err(PathError::Unsigned));
        let mut b = s.clone();
        b.to = pt(9);
        assert_eq!(b.verify(), Err(PathError::Unsigned));
        let mut c = s.clone();
        c.expires_at = u64::MAX;
        assert_eq!(c.verify(), Err(PathError::Unsigned));
        assert!(s.verify().is_ok(), "the untouched segment stopped verifying");
    }

    /// Segments that do not meet cannot be assembled.
    #[test]
    fn disjoint_segments_do_not_form_a_path() {
        let a = Segment::offer(&op(1), pt(0), pt(1), 100);
        let b = Segment::offer(&op(2), pt(5), pt(6), 100);
        assert_eq!(Path::assemble(vec![a, b], 0), Err(PathError::Disjoint));
    }

    /// An expired segment does not compose, and a standing claim nobody can withdraw is what
    /// made stale announcements dangerous.
    #[test]
    fn an_expired_segment_does_not_compose() {
        let mut segs = Segments::new();
        segs.learn(Segment::offer(&op(1), pt(0), pt(1), 50)).unwrap();
        segs.learn(Segment::offer(&op(2), pt(1), pt(2), 100)).unwrap();

        assert_eq!(segs.compose(pt(0), pt(2), 10).len(), 1);
        assert!(
            segs.compose(pt(0), pt(2), 60).is_empty(),
            "a path composed through an expired segment"
        );
        // And assembling one directly is refused rather than silently dropped.
        let expired = Segment::offer(&op(1), pt(0), pt(1), 50);
        assert_eq!(
            Path::assemble(vec![expired], 60),
            Err(PathError::Expired { at: 50 })
        );
    }

    /// A loop must be refused rather than carried.
    #[test]
    fn a_path_cannot_visit_a_point_twice() {
        let a = Segment::offer(&op(1), pt(0), pt(1), 100);
        let b = Segment::offer(&op(2), pt(1), pt(0), 100);
        assert_eq!(Path::assemble(vec![a, b], 0), Err(PathError::Loop));

        // And composition does not produce one even when the segments allow it.
        let mut segs = Segments::new();
        segs.learn(Segment::offer(&op(1), pt(0), pt(1), 100)).unwrap();
        segs.learn(Segment::offer(&op(2), pt(1), pt(0), 100)).unwrap();
        segs.learn(Segment::offer(&op(3), pt(1), pt(2), 100)).unwrap();
        for p in segs.compose(pt(0), pt(2), 0) {
            let mut seen = vec![p.source()];
            for s in p.segments() {
                assert!(!seen.contains(&s.to), "composed path revisits a point");
                seen.push(s.to);
            }
        }
    }

    /// A hostile segment set must not be composable into an unbounded path.
    #[test]
    fn composition_is_bounded_however_many_segments_are_offered() {
        let mut segs = Segments::new();
        // A long chain, longer than a sender will carry.
        for i in 0..40u32 {
            segs.learn(Segment::offer(&op(i + 1), pt(i), pt(i + 1), 1_000))
                .unwrap();
        }
        assert!(
            segs.compose(pt(0), pt(39), 0).is_empty(),
            "a path longer than the bound was composed"
        );
        // And the bound itself composes.
        assert_eq!(segs.compose(pt(0), pt(8), 0).len(), 1);
        assert_eq!(
            Path::assemble(
                (0..MAX_SEGMENTS + 1)
                    .map(|i| Segment::offer(&op(i as u32 + 1), pt(i as u32), pt(i as u32 + 1), 1_000))
                    .collect(),
                0
            ),
            Err(PathError::TooLong)
        );
    }

    /// An unverified segment must never enter the store.
    #[test]
    fn a_store_never_holds_an_unsigned_segment() {
        let mut segs = Segments::new();
        let mut forged = Segment::offer(&op(1), pt(0), pt(1), 100);
        forged.to = pt(9);
        assert_eq!(segs.learn(forged), Err(PathError::Unsigned));
        assert!(segs.is_empty());
    }

    /// Two senders holding different segments are both correct, which is the absence of
    /// convergence stated as a test.
    ///
    /// In BGP the two would disagree and one would be wrong, and the disagreement propagates.
    /// Here neither advertises anything onward and neither is authoritative.
    #[test]
    fn two_senders_with_different_knowledge_are_both_correct() {
        let direct = Segment::offer(&op(1), pt(0), pt(3), 100);
        let long_a = Segment::offer(&op(2), pt(0), pt(1), 100);
        let long_b = Segment::offer(&op(3), pt(1), pt(3), 100);

        let mut alice = Segments::new();
        alice.learn(direct.clone()).unwrap();
        let mut bob = Segments::new();
        bob.learn(long_a).unwrap();
        bob.learn(long_b).unwrap();

        let a_paths = alice.compose(pt(0), pt(3), 0);
        let b_paths = bob.compose(pt(0), pt(3), 0);
        assert_eq!(a_paths.len(), 1);
        assert_eq!(b_paths.len(), 1);
        assert_ne!(a_paths[0], b_paths[0]);
        // Both reach the same place by different parties, and neither is authoritative.
        assert_eq!(a_paths[0].destination(), b_paths[0].destination());
        assert_ne!(a_paths[0].accountable(), b_paths[0].accountable());
    }

    /// Composition must be deterministic and carry no preference.
    ///
    /// A structural preference relay operators can read is a placement target, so the order
    /// here is a function of the paths rather than of anything an operator can influence by
    /// how it presents itself.
    #[test]
    fn composition_is_deterministic_and_expresses_no_preference() {
        let mut segs = Segments::new();
        segs.learn(Segment::offer(&op(1), pt(0), pt(3), 100)).unwrap();
        segs.learn(Segment::offer(&op(2), pt(0), pt(1), 100)).unwrap();
        segs.learn(Segment::offer(&op(3), pt(1), pt(3), 100)).unwrap();

        let first = segs.compose(pt(0), pt(3), 0);
        let second = segs.compose(pt(0), pt(3), 0);
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        // Shorter first, which is a property of the path rather than of who offered it.
        assert!(first[0].hops() <= first[1].hops());

        // Learning the same segments in a different order changes nothing.
        let mut other = Segments::new();
        other.learn(Segment::offer(&op(3), pt(1), pt(3), 100)).unwrap();
        other.learn(Segment::offer(&op(2), pt(0), pt(1), 100)).unwrap();
        other.learn(Segment::offer(&op(1), pt(0), pt(3), 100)).unwrap();
        assert_eq!(other.compose(pt(0), pt(3), 0), first);
    }

    /// A path names every party that must misbehave for it to fail.
    ///
    /// The honest claim: not that carriage happens, but that if it does not, this is the list.
    /// A signature is about the present and carriage is a future act, so no signature can
    /// promise it.
    #[test]
    fn a_path_names_everyone_who_could_break_it() {
        let mut segs = Segments::new();
        for i in 0..4u32 {
            segs.learn(Segment::offer(&op(i + 1), pt(i), pt(i + 1), 100))
                .unwrap();
        }
        let p = &segs.compose(pt(0), pt(4), 0)[0];
        let named = p.accountable();
        assert_eq!(named.len(), 4);
        for i in 0..4u32 {
            assert!(named.contains(&op(i + 1).address()), "operator {i} unnamed");
        }
    }
}
