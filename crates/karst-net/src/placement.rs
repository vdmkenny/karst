//! Which providers hold a publisher's feed.
//!
//! One provider per publisher is a single point of failure and a single point of seizure. The
//! feed stops when that provider stops, and it stops for everyone, which is the arrangement
//! this whole design exists to avoid.
//!
//! Placement has to be computable by a reader who has never spoken to the publisher, or the
//! reader needs an announcement telling them where to look, and that announcement is one more
//! thing an adversary can withhold. So it is derived from public information: the publisher's
//! address, the epoch, and the provider set.
//!
//! # Rendezvous hashing
//!
//! Each provider is scored `H(publisher || epoch || provider)` and the top `k` hold the feed.
//! Thaler and Ravishankar (*Using Name-Based Mappings to Increase Hit Rates*, IEEE/ACM
//! Transactions on Networking, 1998) introduced this as highest random weight. It needs no
//! shared state and no ring, and when a provider leaves only the publishers it held move,
//! which matters because a placement that reshuffled everything on every membership change
//! would make the set unknowable in practice.
//!
//! # This is capturable, and the cost is known to three decimal places
//!
//! A deterministic function of two public identities can be **ground against**. An adversary
//! who wants a specific publisher's feed generates provider identities until one scores into
//! the top `k`. With `n` providers that is about `n` hashes per slot, so taking every slot is
//! about `k * n` hashes. `grinding_into_a_chosen_publishers_set_is_cheap` measures it here.
//!
//! This is not a theoretical concern and the deployed numbers are worse than the arithmetic
//! suggests. Biryukov, Pustogarov and Weinmann (*Trawling for Tor Hidden Services*, IEEE S&P
//! 2013) ground Tor relay fingerprints into the responsible-directory position for a chosen
//! onion service, reporting that finding a suitable key "takes just a few minutes on a modern
//! multi-core computer", and captured every responsible directory for Silk Road with six
//! precomputed relays. Sridhar, Ascigil, Keizer, Genon, Pierre, Psaras, Rivière and Król
//! (*Content Censorship in the InterPlanetary File System*, NDSS 2024) price the same attack
//! on IPFS at **$0.0005 per generated identity and about $4 total on AWS**.
//!
//! # Rotation only helps if the rotating value is unpredictable
//!
//! An earlier version of this rotated on an epoch **counter** and claimed that converted
//! permanent capture into per-epoch capture. It does not. A counter is public and monotonic,
//! so an adversary grinds an identity that wins for whichever epoch they care about, as far
//! ahead as they like. **Rotation on a predictable value provides no protection whatsoever
//! against precomputation**, and the earlier claim was wrong.
//!
//! Rotating the key a data item is stored under, precisely to make grinding against a specific
//! item harder, is Cerri, Ghioni, Paraboschi and Tiraboschi (*ID mapping attacks in P2P
//! networks*, IEEE GLOBECOM 2005), who proposed it alongside binding an identity to its address
//! so it cannot be freely chosen. The idea is twenty years old and the failure mode below is
//! what makes it insufficient on its own.
//!
//! Rotation works when the value cannot be known in advance. This is exactly the fix Biryukov
//! et al. proposed in the same paper and Tor shipped as proposal 250, the shared random value
//! computed by commit-and-reveal among the directory authorities. Tor's own security analysis
//! records the limit: the reveal phase runs for hours, so **the value is predictable roughly
//! twelve hours ahead**, and Tor argues that is survivable only because earning the directory
//! flag requires sustained uptime, so an identity ground for a future value cannot be assigned
//! by the time that value arrives.
//!
//! Both halves are therefore necessary and neither is sufficient. [`Beacon`] carries the
//! unpredictable value, and [`min_tenure`] refuses providers that have not been present long
//! enough for a grind against a leaked beacon to have gone stale.
//!
//! # And rotation cuts the other way too
//!
//! Elahi, Bauer, AlSabah, Dingledine and Goldberg (*Changing of the Guards*, WPES 2012) found
//! that rotating Tor entry guards **increases** compromise, because every rotation is a fresh
//! independent draw: "guard rotation increases the chances of active guard list compromise
//! substantially", and over enough rotations "all clients will have been compromised at some
//! point". Tor's response was to rotate *less*, moving from 45 days to nine months (Dingledine,
//! Hopper, Kadianakis, Mathewson, *One Fast Guard for Life*, HotPETs 2014).
//!
//! These are not in conflict. Rotation defeats an adversary whose advantage comes from
//! **choosing** a position, and helps an adversary whose advantage comes from **waiting** to be
//! chosen. This design has both properties at once, and which dominates depends on whether the
//! per-epoch grinding cost exceeds the value of one epoch of capture. At $0.0005 an identity it
//! does not. **No paper appears to model that crossover**, and this does not either.
//!
//! Until an identity is expensive to choose, whether by crypto puzzle (Baumgart and Mies,
//! S/Kademlia, ICPADS 2007) or certification (Castro, Druschel, Ganesh, Rowstron, Wallach, OSDI
//! 2002), **placement should be treated as capturable by a determined adversary**, and the
//! defence that carries weight is the reader comparing what several providers show them.
//! Douceur stands behind all of it: without a central authority identity is free, and
//! everything downstream of identity inherits that.
//!
//! Note also that the original rendezvous hashing paper is a load balancing and cache hit rate
//! result with **no adversarial analysis at all**. None of this is a defect in it. Its Theorem
//! 1 does prove that the fraction of objects remapped when a server joins or leaves is bounded
//! below by `1/m` for *any* scheme that spreads objects evenly, and that this scheme attains
//! it, so minimal disruption here is optimal rather than merely good.

use karst_id::Address;

/// How many providers hold one publisher's feed.
///
/// Availability rises with `k` and so does the number of parties who learn that the publisher
/// exists and can watch who collects from them. It is a privacy cost as much as a storage one.
pub const DEFAULT_REPLICAS: usize = 3;

/// The value placement rotates on.
///
/// It must be **unpredictable** before its epoch begins, or rotation buys nothing: an adversary
/// grinds against a value they can compute in advance. A counter is the worst case and was what
/// this used first.
///
/// Producing such a value without a trusted party is its own problem, solved by commit-and-
/// reveal among a quorum (Syta, Jovanovic, Kokoris Kogias, Gailly, Gasser, Khoffi, Fischer,
/// Ford, *Scalable Bias-Resistant Distributed Randomness*, IEEE S&P 2017) and deployed as
/// drand. Nothing here produces one; this type is the shape of the dependency, and
/// [`Beacon::predictable`] exists so tests can be explicit about using the unsafe kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    pub epoch: u64,
    pub value: [u8; 32],
}

impl Beacon {
    pub fn new(epoch: u64, value: [u8; 32]) -> Self {
        Beacon { epoch, value }
    }

    /// A beacon derived from the epoch number alone.
    ///
    /// **Provides no protection against grinding**, because anyone can compute every future
    /// value. Named so that using it is a visible choice rather than an accident.
    pub fn predictable(epoch: u64) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"karst.net.v1.predictable-beacon");
        h.update(&epoch.to_le_bytes());
        Beacon {
            epoch,
            value: *h.finalize().as_bytes(),
        }
    }
}

/// How long a provider must have been present before it can hold anything.
///
/// A beacon is predictable for some window before its epoch, because producing one takes
/// commit-and-reveal rounds. Tenure covers that window: an identity ground against a leaked
/// beacon cannot be assigned until it has been present longer than the leak, by which time the
/// beacon it was ground for has passed. Tor makes the same argument about the uptime required
/// to earn a directory flag.
pub const fn min_tenure() -> u64 {
    2
}

/// Score one provider for one publisher under one beacon.
fn weight(publisher: &Address, beacon: &Beacon, provider: u16) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.net.v1.placement");
    h.update(publisher.as_bytes());
    h.update(&beacon.value);
    h.update(&provider.to_le_bytes());
    *h.finalize().as_bytes()
}

/// A provider and when it first appeared, which is what tenure is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub id: u16,
    pub joined_epoch: u64,
}

/// The providers holding `publisher` under `beacon`, highest weight first.
///
/// Deterministic, so a publisher depositing and a reader collecting compute the same set
/// without ever having spoken.
pub fn placement_among(
    publisher: &Address,
    beacon: &Beacon,
    candidates: &[Candidate],
    k: usize,
) -> Vec<u16> {
    let eligible: Vec<u16> = candidates
        .iter()
        // Too new to hold anything. Without this, an identity created after a beacon leaked
        // can be assigned under that same beacon, which is the whole grind.
        .filter(|c| beacon.epoch.saturating_sub(c.joined_epoch) >= min_tenure())
        .map(|c| c.id)
        .collect();
    rank(publisher, beacon, &eligible, k)
}

/// Rank providers with no eligibility check at all.
fn rank(publisher: &Address, beacon: &Beacon, providers: &[u16], k: usize) -> Vec<u16> {
    let mut scored: Vec<([u8; 32], u16)> = providers
        .iter()
        .map(|&p| (weight(publisher, beacon, p), p))
        .collect();
    // Ties break on the provider id so the order is total and identical everywhere.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(k).map(|(_, p)| p).collect()
}

/// Placement over providers assumed to be long established.
///
/// Convenience for callers that do not track join times yet. It applies **no tenure check**,
/// so it inherits the full grinding exposure described above.
pub fn placement(publisher: &Address, epoch: u64, providers: &[u16], k: usize) -> Vec<u16> {
    rank(publisher, &Beacon::predictable(epoch), providers, k)
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

    fn providers(n: u16) -> Vec<u16> {
        (0..n).collect()
    }

    /// A publisher and a reader who have never spoken must compute the same set.
    #[test]
    fn placement_is_deterministic() {
        let ps = providers(64);
        for i in 0..50u32 {
            let a = placement(&addr(i), 7, &ps, 3);
            let b = placement(&addr(i), 7, &ps, 3);
            assert_eq!(a, b);
            assert_eq!(a.len(), 3);
        }
    }

    /// Load must spread, or one provider carries the network and becomes the thing to seize.
    #[test]
    fn placement_spreads_across_providers() {
        let n = 32u16;
        let ps = providers(n);
        let mut counts = vec![0usize; n as usize];
        let trials = 20_000u32;
        for i in 0..trials {
            for p in placement(&addr(i), 0, &ps, 3) {
                counts[p as usize] += 1;
            }
        }
        let expected = trials as f64 * 3.0 / n as f64;
        for (p, c) in counts.iter().enumerate() {
            let dev = (*c as f64 - expected).abs() / expected;
            assert!(dev < 0.1, "provider {p} took {c}, {:.1}% off", dev * 100.0);
        }
    }

    /// Removing a provider must move only what that provider held.
    ///
    /// A placement that reshuffled everything on every membership change would make the set
    /// unknowable in practice, because a reader and a publisher would have to agree on the
    /// exact membership at the exact moment.
    #[test]
    fn losing_a_provider_moves_only_its_own_publishers() {
        let ps = providers(48);
        let mut reduced = ps.clone();
        reduced.retain(|&p| p != 17);

        let mut moved = 0;
        let mut affected = 0;
        let trials = 4_000u32;
        for i in 0..trials {
            let before = placement(&addr(i), 0, &ps, 3);
            let after = placement(&addr(i), 0, &reduced, 3);
            if before.contains(&17) {
                affected += 1;
            } else if before != after {
                moved += 1;
            }
        }
        assert_eq!(moved, 0, "{moved} publishers moved without being affected");
        assert!(affected > 100, "vacuous: only {affected} were affected");
    }

    /// The set must change between epochs, so a captured position is not permanent.
    #[test]
    fn placement_rotates_between_epochs() {
        let ps = providers(64);
        let mut changed = 0;
        for i in 0..200u32 {
            if placement(&addr(i), 0, &ps, 3) != placement(&addr(i), 1, &ps, 3) {
                changed += 1;
            }
        }
        assert!(changed > 150, "only {changed} of 200 sets rotated");
    }

    /// Asking for more replicas than there are providers must give what exists, not panic.
    #[test]
    fn asking_for_more_replicas_than_exist_returns_everything() {
        let ps = providers(2);
        assert_eq!(placement(&addr(1), 0, &ps, 5).len(), 2);
        assert!(placement(&addr(1), 0, &[], 3).is_empty());
    }

    /// Measure what it costs an adversary to be assigned a chosen publisher's feed.
    ///
    /// Placement is a deterministic function of two public identities, so it can be ground
    /// against: generate provider identities until one scores into the top k for the target.
    /// This is not a hypothetical, and the number matters more than the observation, so it is
    /// measured rather than asserted.
    ///
    /// The honest reading: with free identities, deterministic placement is capturable, and
    /// epoch rotation converts permanent capture into per-epoch capture at almost no cost to
    /// the adversary. What raises the cost is making an identity expensive to choose, which is
    /// S/Kademlia's crypto puzzles or Castro et al.'s certified identifiers, and which this
    /// does not yet have.
    #[test]
    fn grinding_into_a_chosen_publishers_set_is_cheap() {
        let honest = providers(128);
        let target = addr(9_999);
        let k = DEFAULT_REPLICAS;

        // What the honest set scores. An adversary needs to beat the weakest of the top k.
        let incumbent = placement(&target, 0, &honest, k);
        let b0 = Beacon::predictable(0);
        let bar = weight(&target, &b0, *incumbent.last().unwrap());

        let mut tries = 0u32;
        let mut candidate = 1_000u16;
        loop {
            tries += 1;
            if weight(&target, &b0, candidate) > bar {
                break;
            }
            candidate = candidate.wrapping_add(1);
            assert!(tries < 100_000, "could not grind a slot at all");
        }

        assert!(
            tries < 2_000,
            "grinding one slot took {tries} tries, which would make capture expensive"
        );
        // Recorded rather than defended against: taking a slot in a 128 provider set costs a
        // few hundred hashes, so taking all of them costs a few thousand.
        assert!(tries <= 128 * 8, "measured {tries}");
    }

    /// Rotating on a predictable value protects nothing, and this proves it rather than
    /// asserting the comfortable opposite.
    ///
    /// An earlier version of this test showed that a slot ground for epoch 0 does not hold in
    /// epoch 1, and concluded that rotation converts permanent capture into per-epoch capture.
    /// That reasoning is wrong: nothing forces an adversary to grind for the epoch they happen
    /// to be in. When the rotating value is a counter, every future value is computable now, so
    /// they grind for whichever epoch they want, or for many at once.
    ///
    /// Rotation is only a defence when the value cannot be known in advance, which is why
    /// [`Beacon::predictable`] is named the way it is.
    #[test]
    fn grinding_against_a_predictable_beacon_captures_any_epoch_you_like() {
        let honest = providers(128);
        let target = addr(4_242);
        let k = DEFAULT_REPLICAS;

        // The adversary picks an epoch far in the future and grinds for that one.
        let far = 10_000u64;
        let future = Beacon::predictable(far);
        let bar = weight(
            &target,
            &future,
            *placement(&target, far, &honest, k).last().unwrap(),
        );
        let mut candidate = 5_000u16;
        let mut tries = 0;
        while weight(&target, &future, candidate) <= bar {
            candidate = candidate.wrapping_add(1);
            tries += 1;
            assert!(tries < 100_000);
        }
        let mut with_adversary = honest.clone();
        with_adversary.push(candidate);

        assert!(
            placement(&target, far, &with_adversary, k).contains(&candidate),
            "grinding for a chosen future epoch failed, which would be surprising"
        );
        assert!(
            tries < 2_000,
            "capturing a chosen future epoch took {tries} tries"
        );
    }

    /// A newly arrived provider must not be assignable straight away.
    ///
    /// Tenure is what makes an unpredictable beacon worth anything. A beacon takes rounds to
    /// produce and is therefore known slightly before its epoch; without tenure an identity
    /// ground the moment the value leaks is assigned under that same value. Tor makes the same
    /// argument about the uptime required to earn a directory flag.
    #[test]
    fn a_newly_arrived_provider_cannot_be_assigned_yet() {
        let target = addr(77);
        let beacon = Beacon::new(100, [9u8; 32]);
        let established: Vec<Candidate> = (0..64u16)
            .map(|id| Candidate {
                id,
                joined_epoch: 10,
            })
            .collect();

        // An adversary who grinds a winning id but only just arrived.
        let mut with_newcomer = established.clone();
        let bar = weight(
            &target,
            &beacon,
            *placement_among(&target, &beacon, &established, DEFAULT_REPLICAS)
                .last()
                .unwrap(),
        );
        let mut id = 5_000u16;
        while weight(&target, &beacon, id) <= bar {
            id = id.wrapping_add(1);
        }
        with_newcomer.push(Candidate {
            id,
            joined_epoch: beacon.epoch,
        });

        assert!(
            !placement_among(&target, &beacon, &with_newcomer, DEFAULT_REPLICAS).contains(&id),
            "an identity that arrived this epoch was assigned immediately"
        );

        // The same identity, present long enough, does take the slot. Tenure delays capture;
        // it does not prevent it, and an adversary willing to wait is unaffected.
        let mut patient = established.clone();
        patient.push(Candidate {
            id,
            joined_epoch: beacon.epoch - min_tenure(),
        });
        assert!(placement_among(&target, &beacon, &patient, DEFAULT_REPLICAS).contains(&id));
    }
}
