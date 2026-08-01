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
//! # This is capturable, and the cost is measured rather than assumed
//!
//! A deterministic function of two public identities can be **ground against**. An adversary
//! who wants a specific publisher's feed generates provider identities until one scores into
//! the top `k` for that publisher. With `n` providers that costs about `n` hashes per slot, so
//! taking every slot costs about `k * n` hashes: a few hundred, for realistic values. See
//! `grinding_a_provider_identity_into_a_chosen_publishers_set_is_cheap`, which measures it.
//!
//! Epoch rotation does not fix this. It converts permanent capture into per-epoch capture,
//! which raises the adversary's ongoing cost from nothing to almost nothing.
//!
//! What actually raises it is making a provider identity **expensive to choose**, which is what
//! S/Kademlia does with crypto puzzles (Baumgart and Mies, ICPADS 2007) and what Castro,
//! Druschel, Ganesh, Rowstron and Wallach require as certified node identifiers (OSDI 2002).
//! Douceur's result stands behind both: without a central authority, identity is free, and
//! everything downstream of identity inherits that.
//!
//! Until an identity has a cost, **placement should be treated as capturable by a determined
//! adversary**, and the defence that carries weight is the reader comparing what several
//! providers show them rather than trusting any one of them to be honestly chosen.

use karst_id::Address;

/// How many providers hold one publisher's feed.
///
/// Availability rises with `k` and so does the number of parties who learn that the publisher
/// exists and can watch who collects from them. It is a privacy cost as much as a storage one.
pub const DEFAULT_REPLICAS: usize = 3;

/// Score one provider for one publisher in one epoch.
fn weight(publisher: &Address, epoch: u64, provider: u16) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"karst.net.v1.placement");
    h.update(publisher.as_bytes());
    h.update(&epoch.to_le_bytes());
    h.update(&provider.to_le_bytes());
    *h.finalize().as_bytes()
}

/// The providers holding `publisher` this epoch, highest weight first.
///
/// Deterministic, so a publisher depositing and a reader collecting compute the same set
/// without ever having spoken.
pub fn placement(publisher: &Address, epoch: u64, providers: &[u16], k: usize) -> Vec<u16> {
    let mut scored: Vec<([u8; 32], u16)> = providers
        .iter()
        .map(|&p| (weight(publisher, epoch, p), p))
        .collect();
    // Ties break on the provider id so the order is total and identical everywhere.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(k).map(|(_, p)| p).collect()
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
    fn grinding_a_provider_identity_into_a_chosen_publishers_set_is_cheap() {
        let honest = providers(128);
        let target = addr(9_999);
        let k = DEFAULT_REPLICAS;

        // What the honest set scores. An adversary needs to beat the weakest of the top k.
        let incumbent = placement(&target, 0, &honest, k);
        let bar = weight(&target, 0, *incumbent.last().unwrap());

        let mut tries = 0u32;
        let mut candidate = 1_000u16;
        loop {
            tries += 1;
            if weight(&target, 0, candidate) > bar {
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

    /// An adversary must at least have to grind again each epoch.
    ///
    /// This is worth very little and is worth knowing precisely because it is worth very
    /// little: it is the difference between capturing a publisher once and capturing them
    /// repeatedly, and both are cheap.
    #[test]
    fn a_captured_slot_does_not_survive_the_epoch() {
        let honest = providers(128);
        let target = addr(4_242);
        let k = DEFAULT_REPLICAS;

        let mut with_adversary = honest.clone();
        // Find an id that captures a slot in epoch 0.
        let bar = weight(&target, 0, *placement(&target, 0, &honest, k).last().unwrap());
        let mut candidate = 5_000u16;
        while weight(&target, 0, candidate) <= bar {
            candidate = candidate.wrapping_add(1);
        }
        with_adversary.push(candidate);

        assert!(placement(&target, 0, &with_adversary, k).contains(&candidate));
        let mut still_in = 0;
        for epoch in 1..40u64 {
            if placement(&target, epoch, &with_adversary, k).contains(&candidate) {
                still_in += 1;
            }
        }
        assert!(
            still_in < 10,
            "a slot ground for one epoch held in {still_in} of the next 39"
        );
    }
}
