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
/// grinds against a value it can compute in advance. A counter is the worst case and was what
/// this used first.
///
/// # Why it is not a shared beacon
///
/// Every deployed unbiasable beacon rests on an honest-majority assumption over a named set.
/// drand fixes its group by a distributed key generation ceremony, Tor's shared random value
/// needs its directory authorities, a stake-weighted beacon needs a stake register. That named
/// set is error 03, and this design cannot have one.
///
/// Nor is it an engineering gap that better protocol design closes. Cleve (*Limits on the
/// Security of Coin Flips when Half the Processors Are Faulty*, STOC 1986) shows no protocol
/// agrees on a bit with negligible bias once half the parties are faulty, and Douceur (*The
/// Sybil Attack*, IPTPS 2002) shows that without a logically centralised authority an adversary
/// can be half the parties whenever it chooses. Open membership plus free identities rules out
/// distributed coin tossing.
///
/// # So each publisher brings its own
///
/// The value for an epoch is the **publisher's own VRF output** on that epoch, from
/// `schnorrkel`'s Schnorr VRF over Ristretto. Unpredictable to everyone but the publisher,
/// unique so the publisher cannot regrind it, verifiable by anyone holding the publisher's VRF
/// public key, and there are as many of them as there are publishers, which is "zero or n,
/// never one" satisfied literally rather than by analogy.
///
/// # What this buys, and what it does not
///
/// It stops the adversary **aiming**. It cannot take a named publisher's slots by hashing a few
/// hundred candidate identities, because it does not know what to hash against until the epoch
/// starts. That is the attack Biryukov, Pustogarov and Weinmann ran against Tor and Sridhar and
/// colleagues priced on IPFS at about four dollars.
///
/// It does nothing about **presence**. Rendezvous hashing is uniform and uniform is exactly what
/// unpredictability guarantees, so an adversary running a share of the provider set holds that
/// share of every publisher's placement, having ground nothing. Measured in
/// `an_unpredictable_beacon_stops_aiming_and_not_presence`.
///
/// # The cost, which is real
///
/// Placement stops being announcement-free. The reader needs the publisher's beacon for the
/// epoch, so it needs one small unforgeable value that any provider can serve and anyone can
/// verify. A publisher that stops emitting falls back to a stale value, which an adversary then
/// has unlimited time to grind against, so silence is a slow-acting attack on yourself.
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

/// A publisher's beacon key. Separate from its L2 identity, like every other key here.
pub struct BeaconKey {
    keypair: schnorrkel::Keypair,
}

/// What travels with a beacon so a reader can check it.
#[derive(Clone)]
pub struct BeaconProof {
    pub epoch: u64,
    pub value: [u8; 32],
    preout: [u8; 32],
    proof: Vec<u8>,
}

impl core::fmt::Debug for BeaconKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BeaconKey(redacted)")
    }
}

impl core::fmt::Debug for BeaconProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BeaconProof(epoch {})", self.epoch)
    }
}

/// The transcript a beacon is computed over. Domain separated, so a signature over anything
/// else in this system cannot be replayed as a beacon.
fn beacon_transcript(epoch: u64) -> merlin::Transcript {
    let mut t = merlin::Transcript::new(b"karst.net.v2.beacon");
    t.append_message(b"epoch", &epoch.to_le_bytes());
    t
}

impl BeaconKey {
    pub fn generate() -> Self {
        BeaconKey {
            keypair: schnorrkel::Keypair::generate(),
        }
    }

    /// Deterministic, for tests that need a fixed transcript.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mini = schnorrkel::MiniSecretKey::from_bytes(&seed).expect("32 bytes");
        BeaconKey {
            keypair: mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519),
        }
    }

    /// What a reader needs to check this publisher's beacons. Published once.
    pub fn public(&self) -> [u8; 32] {
        self.keypair.public.to_bytes()
    }

    /// The beacon for an epoch, with the proof a reader checks it by.
    ///
    /// The publisher can compute every future epoch immediately, which is fine: the publisher
    /// is not the adversary here, and the value being unique means it cannot shop for a
    /// favourable one. What matters is that nobody else can compute it before it is emitted.
    pub fn beacon(&self, epoch: u64) -> BeaconProof {
        let (inout, proof, _) = self.keypair.vrf_sign(beacon_transcript(epoch));
        BeaconProof {
            epoch,
            value: inout.make_bytes(b"karst.net.v2.beacon.value"),
            preout: inout.to_preout().to_bytes(),
            proof: proof.to_bytes().to_vec(),
        }
    }
}

impl BeaconProof {
    /// Check a beacon against the publisher's beacon key.
    ///
    /// A reader that skips this is taking placement from whoever spoke last, which is the
    /// announcement-withholding attack the computed-placement design existed to remove.
    pub fn verify(&self, publisher_key: &[u8; 32]) -> Option<Beacon> {
        let pk = schnorrkel::PublicKey::from_bytes(publisher_key).ok()?;
        let proof = schnorrkel::vrf::VRFProof::from_bytes(&self.proof).ok()?;
        let preout = schnorrkel::vrf::VRFPreOut::from_bytes(&self.preout).ok()?;
        let (inout, _) = pk
            .vrf_verify(beacon_transcript(self.epoch), &preout, &proof)
            .ok()?;
        let value: [u8; 32] = inout.make_bytes(b"karst.net.v2.beacon.value");
        (value == self.value).then_some(Beacon {
            epoch: self.epoch,
            value,
        })
    }
}

/// How long a provider must have been present before it can hold anything.
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

#[cfg(test)]
mod beacon_tests {
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

    /// A publisher's beacon is unforgeable and verifiable by anyone holding its key.
    #[test]
    fn a_beacon_verifies_against_its_publisher_and_nobody_else() {
        let k = BeaconKey::from_seed([1u8; 32]);
        let other = BeaconKey::from_seed([2u8; 32]);

        let b = k.beacon(7);
        let checked = b.verify(&k.public()).expect("an honest beacon verifies");
        assert_eq!(checked.epoch, 7);
        assert_eq!(checked.value, b.value);

        assert!(
            b.verify(&other.public()).is_none(),
            "a beacon verified against a key that did not produce it"
        );
    }

    /// The value is a function of the key and the epoch, and of nothing the publisher chooses.
    ///
    /// This is what "unique" buys and it is the difference from a signature. A publisher that
    /// could shop for a favourable output would grind its own placement, picking the epoch
    /// value that puts its own providers in the set.
    #[test]
    fn a_publisher_cannot_shop_for_a_favourable_value() {
        let k = BeaconKey::from_seed([3u8; 32]);
        assert_eq!(k.beacon(11).value, k.beacon(11).value, "not deterministic");
        assert_ne!(k.beacon(11).value, k.beacon(12).value, "epochs collide");

        // And a different publisher gets a different value for the same epoch, so the epoch
        // number alone predicts nothing.
        let j = BeaconKey::from_seed([4u8; 32]);
        assert_ne!(k.beacon(11).value, j.beacon(11).value);
    }

    /// A tampered beacon does not verify, so a provider cannot substitute a value it likes.
    #[test]
    fn a_substituted_value_is_refused() {
        let k = BeaconKey::from_seed([5u8; 32]);
        let mut b = k.beacon(2);
        b.value[0] ^= 1;
        assert!(
            b.verify(&k.public()).is_none(),
            "a value that does not match its proof was accepted"
        );

        let mut c = k.beacon(2);
        c.epoch = 3;
        assert!(
            c.verify(&k.public()).is_none(),
            "a beacon was accepted for an epoch it was not computed for"
        );
    }

    /// The grinding attack the beacon exists to stop, run against a real one.
    ///
    /// `grinding_into_a_chosen_publishers_set_is_cheap` shows a slot costs a few hundred
    /// hashes when the value is predictable. That attack needs the value in advance, and here
    /// it is a VRF output the adversary cannot compute without the publisher's secret. What
    /// remains available to them is grinding *after* the epoch's value is published, which is
    /// a race against the epoch rather than unlimited precomputation.
    #[test]
    fn a_vrf_beacon_cannot_be_ground_against_in_advance() {
        let honest = providers(128);
        let target = addr(9_999);
        let k = DEFAULT_REPLICAS;
        let publisher = BeaconKey::from_seed([6u8; 32]);

        // The adversary grinds an identity that wins for epoch 5, knowing everything public.
        let future = 5u64;
        let guessed = Beacon::predictable(future);
        let incumbent = rank(&target, &guessed, &honest, k);
        let bar = weight(&target, &guessed, *incumbent.last().unwrap());
        let mut winner = 1_000u16;
        while weight(&target, &guessed, winner) <= bar {
            winner = winner.wrapping_add(1);
        }

        // Then the epoch arrives and the publisher emits its own value instead.
        let real = publisher
            .beacon(future)
            .verify(&publisher.public())
            .unwrap();
        let mut all = honest.clone();
        all.push(winner);
        assert!(
            !rank(&target, &real, &all, k).contains(&winner),
            "an identity ground in advance still landed, so the value was predictable"
        );
    }

    /// An unpredictable beacon stops targeted grinding and does not stop bulk minting.
    ///
    /// This is the question #79 has to answer before a beacon is worth building, and the
    /// answer is not the flattering one. Unpredictability removes the adversary's ability to
    /// aim: it can no longer take a chosen publisher's slots for a chosen epoch by hashing a
    /// few hundred candidate identities, because it does not know the value to hash against
    /// until the epoch begins.
    ///
    /// What it cannot remove is presence. An adversary that mints many identities and keeps
    /// them holds a share of every publisher's placement proportional to its share of the
    /// provider set, whatever the beacon does, because rendezvous hashing is uniform and
    /// uniform is exactly what an unpredictable value guarantees.
    ///
    /// So a beacon converts "four dollars to capture the publisher you name" into "hold a
    /// proportion of the network to capture a proportion of publishers". That is worth having
    /// and it is not the same as solving it, and the difference is what this measures.
    #[test]
    fn an_unpredictable_beacon_stops_aiming_and_not_presence() {
        let honest = providers(128);
        let k = DEFAULT_REPLICAS;

        // The adversary mints a quarter as many identities as the honest set and keeps them.
        // It does no grinding at all: these are simply providers it runs.
        let minted: Vec<u16> = (5_000u16..5_032).collect();
        let mut all = honest.clone();
        all.extend_from_slice(&minted);

        // Across many publishers and an unpredictable value per epoch, what share does it get?
        let mut captured_slots = 0usize;
        let mut total_slots = 0usize;
        for pubr in 0..200u32 {
            let target = addr(pubr);
            let mut h = blake3::Hasher::new();
            h.update(b"unpredictable");
            h.update(&pubr.to_le_bytes());
            let beacon = Beacon::new(0, *h.finalize().as_bytes());

            let held = rank(&target, &beacon, &all, k);
            total_slots += held.len();
            captured_slots += held.iter().filter(|p| minted.contains(p)).count();
        }

        let share_of_set = minted.len() as f64 / all.len() as f64;
        let share_of_slots = captured_slots as f64 / total_slots as f64;

        // Presence translates into placement at about its own rate. No beacon changes this.
        assert!(
            (share_of_slots - share_of_set).abs() < 0.05,
            "minted identities are {:.1}% of the set and took {:.1}% of slots, so this \
             measurement is not showing what it claims",
            share_of_set * 100.0,
            share_of_slots * 100.0
        );

        // And the thing a beacon does buy: the adversary cannot concentrate that share on a
        // publisher it names. Its share of any one publisher's slots is no better than its
        // share overall.
        let worst = (0..200u32)
            .map(|pubr| {
                let target = addr(pubr);
                let mut h = blake3::Hasher::new();
                h.update(b"unpredictable");
                h.update(&pubr.to_le_bytes());
                let beacon = Beacon::new(0, *h.finalize().as_bytes());
                rank(&target, &beacon, &all, k)
                    .iter()
                    .filter(|p| minted.contains(p))
                    .count()
            })
            .max()
            .unwrap_or(0);
        assert!(
            worst < k,
            "some publisher lost all {k} slots to minted identities without any grinding, \
             so uniformity is not holding"
        );
    }
}
