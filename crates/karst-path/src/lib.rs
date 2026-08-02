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
    /// Starting points tracked at all.
    pub const MAX_POINTS: usize = 4096;
    /// How far ahead an offer may claim to be good for, in milliseconds. One week.
    ///
    /// Eviction admits a newcomer only if it outlives what it displaces, which is what stops
    /// expiring junk from churning live routes out. Without a ceiling on the claim, the same
    /// rule hands a squatter a permanent hold: fill a point with offers good until the heat
    /// death and nothing can ever displace them. The layer's own reasoning already demanded
    /// this bound, one level up: an offer with no expiry is a standing claim nobody can
    /// withdraw, which is the durability that made stale BGP announcements dangerous.
    pub const MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
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
    ///
    /// # Occupancy is contestable, not first-come
    ///
    /// The first version of this bound refused everything past `MAX_PER_POINT` and evicted
    /// nothing, which turned the bound into the weapon it was meant to remove. Sixty-four
    /// signatures from **one** identity took a point permanently: `Segment` equality covers
    /// every field including `expires_at`, so the same offer at sixty-four different expiry
    /// times was sixty-four distinct segments, and no honest operator could ever get in
    /// again. The same defect broke the honest case with no adversary at all, since a
    /// refreshed segment differs from the one it refreshes and therefore competed with it
    /// rather than replacing it. Every point died at its first expiry wave.
    ///
    /// Three rules follow, and they are the ones L15 already arrived at for the same reason
    /// (`docs/23-discovery.md`: a bound applied at one stage and not another is not a bound):
    ///
    /// 1. **An offer is keyed `(operator, from, to)`.** A refresh replaces its predecessor.
    ///    Varying only the expiry no longer buys a slot.
    /// 2. **Expired segments are dropped on the way in**, so a store sheds what `compose`
    ///    would skip rather than holding it against the cap forever.
    /// 3. **A full bucket evicts rather than refuses**, charging the largest occupant and
    ///    breaking ties by nearest expiry. An incoming segment that expires sooner than
    ///    everything held is the one case still refused, so junk cannot displace live routes.
    ///
    /// # What this does not fix
    ///
    /// Identities are free, so an adversary spends 64 of them instead of one and the bucket
    /// is full of individually valid junk again. Eviction keeps occupancy contestable, so
    /// honest segments continue to get in, and that is the whole of what this layer can do
    /// alone: there is **no symmetric sybilproof allocation** (Cheng and Friedman,
    /// *Sybilproof Reputation Mechanisms*, P2PECON 2005), and the escape is source-anchored
    /// asymmetry, which needs a wire layer that records who handed a segment over. See #130.
    pub fn learn(&mut self, s: Segment, now: u64) -> Result<(), PathError> {
        s.verify()?;
        if !s.valid_at(now) {
            return Err(PathError::Expired { at: s.expires_at });
        }
        if s.expires_at.saturating_sub(now) > Self::MAX_LIFETIME_MS {
            return Err(PathError::TooLong);
        }

        if !self.by_from.contains_key(&s.from) && self.by_from.len() >= Self::MAX_POINTS {
            self.forget_a_point(now);
        }
        let e = self.by_from.entry(s.from).or_default();

        // An offer is a standing claim by one operator about one link. A later one replaces
        // the earlier one; it does not join it.
        if let Some(held) = e
            .iter_mut()
            .find(|h| h.operator == s.operator && h.to == s.to)
        {
            if s.expires_at > held.expires_at {
                *held = s;
            }
            return Ok(());
        }

        e.retain(|h| h.valid_at(now));
        if e.len() >= Self::MAX_PER_POINT {
            let Some(victim) = Self::largest_occupant_victim(e) else {
                return Err(PathError::TooMany);
            };
            if e[victim].expires_at >= s.expires_at {
                // Nothing held expires sooner than the newcomer, so taking a slot would trade
                // a longer-lived route for a shorter one. That is a downgrade an adversary
                // would perform deliberately.
                return Err(PathError::TooMany);
            }
            e.remove(victim);
        }
        e.push(s);
        Ok(())
    }

    /// The slot a newcomer should take: held by whoever holds the most, expiring soonest.
    ///
    /// Charging the largest occupant is what stops one operator monopolising a point. It does
    /// not stop many operators doing so, because identities are free and no allocation rule
    /// over free identities can.
    fn largest_occupant_victim(e: &[Segment]) -> Option<usize> {
        let mut counts: BTreeMap<Address, usize> = BTreeMap::new();
        for h in e {
            *counts.entry(h.operator).or_default() += 1;
        }
        let worst = counts.values().copied().max()?;
        e.iter()
            .enumerate()
            .filter(|(_, h)| counts[&h.operator] == worst)
            .min_by_key(|(i, h)| (h.expires_at, *i))
            .map(|(i, _)| i)
    }

    /// Make room for a new point by dropping one that is doing the least.
    ///
    /// Live segments first, then soonest to lapse. A point whose segments have all expired is
    /// carrying nothing, so it goes before one that is.
    fn forget_a_point(&mut self, now: u64) {
        let victim = self
            .by_from
            .iter()
            .min_by_key(|(p, v)| {
                let live = v.iter().filter(|s| s.valid_at(now)).count();
                let soonest = v.iter().map(|s| s.expires_at).min().unwrap_or(0);
                (live, soonest, **p)
            })
            .map(|(p, _)| *p);
        if let Some(p) = victim {
            self.by_from.remove(&p);
        }
    }

    /// Drop everything that has lapsed. A store that only sheds on insert keeps the dead
    /// around at points nobody is offering carriage from any more.
    pub fn expire(&mut self, now: u64) {
        self.by_from.retain(|_, v| {
            v.retain(|s| s.valid_at(now));
            !v.is_empty()
        });
    }

    /// Starting points tracked.
    pub fn points(&self) -> usize {
        self.by_from.len()
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
                    ), 0)
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

    /// One identity must not be able to take a point, and it took a point for 64 signatures.
    ///
    /// `Segment` equality covers every field, `expires_at` included, so the same offer at 64
    /// different expiry times was 64 distinct segments. First-come occupancy with no eviction
    /// did the rest: the bucket filled, every honest operator got `TooMany` forever, and the
    /// point became uncomposable-through. It survived the expiry of every segment causing it,
    /// because expiry was checked at composition and nothing ever swept the store.
    #[test]
    fn one_identity_cannot_take_a_point_by_reoffering_at_new_expiries() {
        let mut segs = Segments::new();
        let squatter = op(1);
        for t in 0..200u64 {
            let _ = segs.learn(Segment::offer(&squatter, pt(0), pt(1), 1_000 + t), 0);
        }
        assert_eq!(
            segs.len(),
            1,
            "the same operator's offer for the same link is one offer, not {}",
            segs.len()
        );

        // And the honest operators still get in.
        for k in 0..32u32 {
            segs.learn(Segment::offer(&op(100 + k), pt(0), pt(k + 2), 1_000), 0)
                .expect("an honest offer was refused");
        }
    }

    /// A refresh replaces the offer it refreshes, so the honest case survives its own expiry.
    ///
    /// With no adversary at all: 64 honest operators fill a point, their segments lapse, and
    /// every refresh used to be refused, because a refreshed segment differs from the one it
    /// refreshes and therefore competed with it. Every point died at its first expiry wave and
    /// could never be repaired.
    #[test]
    fn an_expiry_wave_does_not_kill_a_point() {
        let mut segs = Segments::new();
        for k in 0..Segments::MAX_PER_POINT as u32 {
            segs.learn(Segment::offer(&op(k), pt(0), pt(k + 1), 100), 0)
                .expect("initial offer refused");
        }
        assert_eq!(segs.len(), Segments::MAX_PER_POINT);

        // Time passes and every one of them lapses. Each operator re-offers.
        for k in 0..Segments::MAX_PER_POINT as u32 {
            segs.learn(Segment::offer(&op(k), pt(0), pt(k + 1), 10_000), 200)
                .expect("a refresh was refused");
        }
        assert_eq!(segs.len(), Segments::MAX_PER_POINT);
        assert_eq!(
            segs.compose(pt(0), pt(1), 200).len(),
            1,
            "the point is dead after its first expiry wave"
        );
    }

    /// A store that only sheds on insert keeps the dead at points nobody offers from any more.
    #[test]
    fn expired_segments_do_not_occupy_the_store_forever() {
        let mut segs = Segments::new();
        for k in 0..20u32 {
            segs.learn(Segment::offer(&op(k), pt(k), pt(k + 1), 100), 0).unwrap();
        }
        assert_eq!(segs.points(), 20);
        segs.expire(500);
        assert_eq!(segs.len(), 0);
        assert_eq!(segs.points(), 0, "empty points were kept");
    }

    /// An offer cannot claim to be good forever, or eviction becomes a permanent hold.
    ///
    /// Admitting a newcomer only when it outlives what it displaces is what stops expiring
    /// junk churning out live routes. Uncapped, the same rule lets a squatter claim the heat
    /// death of the universe and hold the slot against everything.
    #[test]
    fn an_offer_cannot_claim_an_unbounded_lifetime() {
        let mut segs = Segments::new();
        assert_eq!(
            segs.learn(Segment::offer(&op(1), pt(0), pt(1), u64::MAX), 0),
            Err(PathError::TooLong)
        );
        segs.learn(
            Segment::offer(&op(1), pt(0), pt(1), Segments::MAX_LIFETIME_MS),
            0,
        )
        .expect("a week is allowed");
    }

    /// The number of points is bounded too, or the per-point bound bounds nothing.
    #[test]
    fn the_number_of_starting_points_is_bounded() {
        let mut segs = Segments::new();
        for k in 0..(Segments::MAX_POINTS as u32 + 500) {
            let _ = segs.learn(Segment::offer(&op(k), pt(k), pt(k + 1), 1_000), 0);
        }
        assert!(segs.points() <= Segments::MAX_POINTS, "{} points", segs.points());
    }

    /// A store bounds what it holds, so the search cannot be handed its own input size.
    #[test]
    fn a_store_refuses_more_ways_out_of_a_point_than_it_will_keep() {
        let mut segs = Segments::new();
        let mut accepted = 0;
        for k in 0..(Segments::MAX_PER_POINT as u32 + 500) {
            if segs.learn(Segment::offer(&op(k), pt(0), pt(k + 1), 100), 0).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, Segments::MAX_PER_POINT);
        assert_eq!(
            segs.learn(Segment::offer(&op(9999), pt(0), pt(9998), 100), 0),
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
                segs.learn(Segment::offer(&op(hop * 100 + k), pt(hop), pt(hop + 1), 100), 0)
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
        segs.learn(Segment::offer(&op(1), pt(0), pt(1), 100), 0).unwrap();
        segs.learn(Segment::offer(&op(2), pt(1), pt(2), 100), 0).unwrap();

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
        assert_eq!(segs.learn(forged, 0), Err(PathError::Unsigned));
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
        segs.learn(Segment::offer(&op(1), pt(0), pt(1), 50), 0).unwrap();
        segs.learn(Segment::offer(&op(2), pt(1), pt(2), 100), 0).unwrap();

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
        segs.learn(Segment::offer(&op(1), pt(0), pt(1), 100), 0).unwrap();
        segs.learn(Segment::offer(&op(2), pt(1), pt(0), 100), 0).unwrap();
        segs.learn(Segment::offer(&op(3), pt(1), pt(2), 100), 0).unwrap();
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
            segs.learn(Segment::offer(&op(i + 1), pt(i), pt(i + 1), 1_000), 0)
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
        assert_eq!(segs.learn(forged, 0), Err(PathError::Unsigned));
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
        alice.learn(direct.clone(), 0).unwrap();
        let mut bob = Segments::new();
        bob.learn(long_a, 0).unwrap();
        bob.learn(long_b, 0).unwrap();

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
        segs.learn(Segment::offer(&op(1), pt(0), pt(3), 100), 0).unwrap();
        segs.learn(Segment::offer(&op(2), pt(0), pt(1), 100), 0).unwrap();
        segs.learn(Segment::offer(&op(3), pt(1), pt(3), 100), 0).unwrap();

        let first = segs.compose(pt(0), pt(3), 0);
        let second = segs.compose(pt(0), pt(3), 0);
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        // Shorter first, which is a property of the path rather than of who offered it.
        assert!(first[0].hops() <= first[1].hops());

        // Learning the same segments in a different order changes nothing.
        let mut other = Segments::new();
        other.learn(Segment::offer(&op(3), pt(1), pt(3), 100), 0).unwrap();
        other.learn(Segment::offer(&op(2), pt(0), pt(1), 100), 0).unwrap();
        other.learn(Segment::offer(&op(1), pt(0), pt(3), 100), 0).unwrap();
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
            segs.learn(Segment::offer(&op(i + 1), pt(i), pt(i + 1), 100), 0)
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
