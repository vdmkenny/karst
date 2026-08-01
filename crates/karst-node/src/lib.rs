//! A mix node that runs.
//!
//! Everything in `karst-mix` describes packets and measures adversaries. This holds the state
//! a node actually keeps: what it has been given, when each thing is due to leave, and what it
//! has already seen.
//!
//! The node is deliberately transport-agnostic. It takes bytes and a clock and produces bytes
//! and destinations, so the same logic runs over UDP, over a test harness with no sockets at
//! all, or over a bearer that has not been invented yet (L0).
//!
//! # The ordering that matters
//!
//! A packet is authenticated, then checked for replay, then scheduled. Doing any of those out
//! of order is a vulnerability rather than an inefficiency: scheduling before authenticating
//! lets forged traffic consume queue space, and checking replay before the MAC lets forged
//! traffic consume the replay window. `karst-mix::packet` enforces the first two internally;
//! this module must not undo that by queueing anything it has not peeled.

use std::collections::BTreeMap;

use karst_mix::clock::Clock;
use karst_mix::packet::{MixError, MixKey, Packet, Peeled, SeenTags};
use rand::seq::SliceRandom;

/// Why a node refused a packet.
///
/// Distinct from `MixError` because a node refuses for reasons a packet knows nothing about,
/// and because reporting the wrong reason sends an operator looking for the wrong attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// The packet itself was bad.
    Mix(MixError),
    /// The queue is full.
    Congested,
    /// The requested delay exceeds what a node will hold.
    DelayTooLong,
}

impl From<MixError> for NodeError {
    fn from(e: MixError) -> Self {
        NodeError::Mix(e)
    }
}

/// What a held item becomes when its delay elapses.
enum Held {
    Forward { next: u16, packet: Packet },
    Deliver { payload: Vec<u8> },
    Absorb,
}

/// An item waiting for its delay to elapse.
struct Pending {
    release_at: u64,
    what: Held,
}

/// What a node emits once a delay has elapsed.
#[derive(Debug)]
pub enum Outbound {
    /// Send onward to this hop id.
    Forward { next: u16, packet: Packet },
    /// This packet terminated here.
    Deliver { payload: Vec<u8> },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeStats {
    /// Packets evicted to make room. Loss, and detectable as loss by loop cover at L4.
    pub evicted: u64,
    pub accepted: u64,
    pub forwarded: u64,
    pub delivered: u64,
    pub cover_absorbed: u64,
    pub rejected_mac: u64,
    pub rejected_replay: u64,
    pub dropped_full: u64,
}

/// A running mix.
pub struct MixNode {
    key: MixKey,
    seen: SeenTags,
    /// Keyed by a monotonically increasing ticket so two packets due at the same instant keep
    /// a defined order without revealing arrival order to anyone outside.
    queue: BTreeMap<(u64, u64), Pending>,
    ticket: u64,
    /// A queue an adversary can inflate is a memory exhaustion primitive. Bounded, but see
    /// `admit` for why the bound is enforced by eviction rather than by refusal.
    capacity: usize,
    epoch_ms: u64,
    stats: NodeStats,
    rng: rand::rngs::StdRng,
    clock: Clock,
}

impl MixNode {
    pub const DEFAULT_CAPACITY: usize = 1 << 16;
    /// How long a replay tag is retained per epoch. Must exceed the longest legitimate flight
    /// time, which L4's delay distribution bounds, and must exceed `MAX_DELAY_MS` so a packet
    /// cannot outlive the memory of having seen it.
    pub const DEFAULT_EPOCH_MS: u64 = 60_000;

    /// The longest a node will hold a packet.
    ///
    /// `delay_ms` is chosen by the sender and is a u32, so without a bound one packet buys a
    /// queue slot for 49 days. The bound must stay well below `DEFAULT_EPOCH_MS` so that a
    /// packet still in flight is still covered by the replay window.
    pub const MAX_DELAY_MS: u32 = 30_000;

    pub fn new(key: MixKey) -> Self {
        MixNode {
            key,
            seen: SeenTags::new(),
            queue: BTreeMap::new(),
            ticket: 0,
            capacity: Self::DEFAULT_CAPACITY,
            epoch_ms: Self::DEFAULT_EPOCH_MS,
            stats: NodeStats::default(),
            rng: <rand::rngs::StdRng as rand::SeedableRng>::from_entropy(),
            clock: Clock::new(),
        }
    }

    pub fn with_capacity(key: MixKey, capacity: usize) -> Self {
        MixNode {
            capacity,
            ..MixNode::new(key)
        }
    }

    pub fn public(&self) -> x25519_dalek::PublicKey {
        self.key.public()
    }

    pub fn stats(&self) -> NodeStats {
        self.stats
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Take a packet off the wire.
    ///
    /// Authentication and replay checking happen inside `peel`, before this function learns
    /// anything, so a forged packet reaches neither the queue nor the replay window.
    pub fn accept(&mut self, packet: Packet, reading_ms: u64) -> Result<(), NodeError> {
        let now_ms = self.clock.advance(reading_ms);
        self.seen.rotate(now_ms / self.epoch_ms);


        match packet.peel(&self.key, &mut self.seen) {
            Err(MixError::BadMac) => {
                self.stats.rejected_mac += 1;
                Err(NodeError::Mix(MixError::BadMac))
            }
            Err(MixError::Replay) => {
                self.stats.rejected_replay += 1;
                Err(NodeError::Mix(MixError::Replay))
            }
            Err(e) => Err(NodeError::Mix(e)),
            Ok(Peeled::Forward {
                next,
                delay_ms,
                packet,
            }) => {
                if delay_ms > Self::MAX_DELAY_MS {
                    return Err(NodeError::DelayTooLong);
                }
                self.stats.accepted += 1;
                let release_at = now_ms.saturating_add(delay_ms as u64);
                self.admit(release_at, Held::Forward { next, packet })
            }
            // Cover ends here. It is still delayed and still counted, because a node that
            // discarded it on arrival would emit a timing signature distinguishing the hop
            // where cover dies, which is the one thing cover must not reveal.
            Ok(Peeled::Drop { delay_ms }) => {
                if delay_ms > Self::MAX_DELAY_MS {
                    return Err(NodeError::DelayTooLong);
                }
                self.stats.accepted += 1;
                self.stats.cover_absorbed += 1;
                let release_at = now_ms.saturating_add(delay_ms as u64);
                self.admit(release_at, Held::Absorb)
            }
            Ok(Peeled::Deliver { delay_ms, payload }) => {
                if delay_ms > Self::MAX_DELAY_MS {
                    return Err(NodeError::DelayTooLong);
                }
                self.stats.accepted += 1;
                let release_at = now_ms.saturating_add(delay_ms as u64);
                // Local delivery is delayed too. Releasing it immediately would make the
                // final hop distinguishable by timing, which is the whole thing L4 prevents.
                self.admit(release_at, Held::Deliver { payload })
            }
        }
    }

    /// Everything whose delay has elapsed, in release order.
    pub fn due(&mut self, reading_ms: u64) -> Vec<Outbound> {
        let now_ms = self.clock.advance(reading_ms);
        let ready: Vec<(u64, u64)> = self
            .queue
            .range(..=(now_ms, u64::MAX))
            .filter(|(_, p)| p.release_at <= now_ms)
            .map(|(k, _)| *k)
            .collect();

        let mut out = Vec::with_capacity(ready.len());
        for k in ready {
            let p = self.queue.remove(&k).expect("key came from the map");
            match p.what {
                Held::Absorb => {}
                Held::Deliver { payload } => {
                    self.stats.delivered += 1;
                    out.push(Outbound::Deliver { payload });
                }
                Held::Forward { next, packet } => {
                    self.stats.forwarded += 1;
                    out.push(Outbound::Forward { next, packet });
                }
            }
        }
        // Release order must not be arrival order. Any node polls `due` on an interval, so
        // every poll emits a batch, and a batch in arrival order is a FIFO at the granularity
        // of the poll: an observer watching both sides recovers the pairing directly. The
        // per-packet delay decorrelates across polls, and this decorrelates within one.
        out.shuffle(&mut self.rng);
        out
    }

    /// Put something in the queue, evicting if the queue is full.
    ///
    /// Refusing when full is the defence Tor tried and withdrew. Jansen, Tschorsch, Johnson and
    /// Scheuermann (*The Sniper Attack*, NDSS 2014) found a size cap is not merely insufficient
    /// but exploitable: an adversary holds many entries so that memory sits just below the
    /// limit, and then honest traffic is what trips it. The adversary's entries survive and
    /// everyone else's are turned away. Tor replaced the cap with age-ordered killing.
    ///
    /// A mix cannot evict by age, because waiting is what a mix is for and the packet waiting
    /// longest is often the one closest to leaving. The equivalent here is **remaining hold**.
    /// Queue occupancy is delay, so the packet costing the queue most is the one with the
    /// longest time still to serve, and that is also exactly the packet a squatter chooses.
    /// Evicting it makes occupancy cost proportional to volume: an adversary who instead draws
    /// delays from the honest distribution gains no leverage per packet and is merely flooding,
    /// which costs them what it costs everyone.
    ///
    /// A new arrival that is itself the longest-held is the one dropped, so the rule cannot be
    /// turned into a way to push others out for free.
    fn admit(&mut self, release_at: u64, what: Held) -> Result<(), NodeError> {
        if self.queue.len() >= self.capacity {
            let worst = self
                .queue
                .keys()
                .next_back()
                .copied()
                .expect("capacity is non-zero, so the queue is non-empty");
            self.stats.dropped_full += 1;
            if worst.0 <= release_at {
                // The arrival is the longest-held. It loses.
                return Err(NodeError::Congested);
            }
            self.queue.remove(&worst);
            self.stats.evicted += 1;
        }
        self.ticket += 1;
        self.queue.insert(
            (release_at, self.ticket),
            Pending { release_at, what },
        );
        Ok(())
    }

    /// How long until the next packet is due, for a caller that would rather sleep than spin.
    ///
    /// Relative rather than absolute, because the node's internal clock is not the caller's.
    pub fn next_due_in(&self) -> Option<u64> {
        self.queue
            .keys()
            .next()
            .map(|(t, _)| t.saturating_sub(self.clock.now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karst_mix::packet::Hop;

    fn mesh(n: usize) -> Vec<MixNode> {
        (0..n)
            .map(|i| MixNode::new(MixKey::from_seed([(i as u8) + 1; 32])))
            .collect()
    }

    fn route(nodes: &[MixNode], delays: &[u32]) -> Vec<Hop> {
        nodes
            .iter()
            .enumerate()
            .map(|(i, n)| Hop {
                id: i as u16,
                public: n.public(),
                delay_ms: delays[i],
            })
            .collect()
    }

    /// Drive a packet through a set of nodes with a virtual clock.
    fn run(nodes: &mut [MixNode], first: Packet, until_ms: u64) -> Vec<Vec<u8>> {
        let mut inflight: Vec<(usize, Packet)> = vec![(0, first)];
        let mut delivered = Vec::new();

        for now in 0..until_ms {
            for (idx, p) in std::mem::take(&mut inflight) {
                let _ = nodes[idx].accept(p, now);
            }
            for i in 0..nodes.len() {
                for out in nodes[i].due(now) {
                    match out {
                        Outbound::Forward { next, packet } => {
                            inflight.push((next as usize, packet))
                        }
                        Outbound::Deliver { payload } => delivered.push(payload),
                    }
                }
            }
        }
        delivered
    }

    #[test]
    fn a_packet_traverses_a_running_mesh_and_is_delivered() {
        let mut nodes = mesh(3);
        let r = route(&nodes, &[5, 10, 0]);
        let p = Packet::wrap(&r, b"hello from the other side", [9u8; 32]).unwrap();

        let got = run(&mut nodes, p, 100);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"hello from the other side");
    }

    #[test]
    fn a_packet_is_held_for_its_delay_and_not_released_early() {
        let mut nodes = mesh(1);
        let r = route(&nodes, &[50]);
        let p = Packet::wrap(&r, b"x", [1u8; 32]).unwrap();

        nodes[0].accept(p, 0).unwrap();
        for t in 0..50 {
            assert!(nodes[0].due(t).is_empty(), "released early at t={t}");
        }
        assert_eq!(nodes[0].due(50).len(), 1);
    }

    #[test]
    fn the_final_hop_is_delayed_too() {
        // Delivering immediately would make the last hop distinguishable by timing.
        let mut nodes = mesh(1);
        let r = route(&nodes, &[30]);
        let p = Packet::wrap(&r, b"payload", [1u8; 32]).unwrap();
        nodes[0].accept(p, 0).unwrap();
        assert!(nodes[0].due(29).is_empty());
        assert_eq!(nodes[0].due(30).len(), 1);
    }

    #[test]
    fn statistics_distinguish_the_reasons_a_packet_was_refused() {
        let mut nodes = mesh(2);
        let r = route(&nodes, &[1, 1]);
        let good = Packet::wrap(&r, b"x", [1u8; 32]).unwrap();

        assert!(nodes[0].accept(good.clone(), 0).is_ok());
        assert_eq!(
            nodes[0].accept(good.clone(), 0),
            Err(NodeError::Mix(MixError::Replay))
        );
        assert_eq!(
            nodes[0].accept(good.tamper_header(3), 0),
            Err(NodeError::Mix(MixError::BadMac))
        );

        let s = nodes[0].stats();
        assert_eq!(s.accepted, 1);
        assert_eq!(s.rejected_replay, 1);
        assert_eq!(s.rejected_mac, 1);
    }

    #[test]
    fn next_due_in_lets_a_caller_sleep_instead_of_spinning() {
        let mut nodes = mesh(1);
        let r = route(&nodes, &[40]);
        assert_eq!(nodes[0].next_due_in(), None);
        nodes[0]
            .accept(Packet::wrap(&r, b"x", [1u8; 32]).unwrap(), 10)
            .unwrap();
        assert_eq!(nodes[0].next_due_in(), Some(40));
    }
}

#[cfg(test)]
mod adversarial {
    //! A node has two things a packet does not: a clock and a queue. Both are attack surface,
    //! and neither is exercised by any test that only checks a packet arrives.

    use super::*;
    use karst_mix::packet::Hop;

    fn node() -> MixNode {
        MixNode::new(MixKey::from_seed([7u8; 32]))
    }

    fn one_hop(n: &MixNode, delay_ms: u32) -> Vec<Hop> {
        vec![Hop {
            id: 0,
            public: n.public(),
            delay_ms,
        }]
    }

    fn pkt(n: &MixNode, delay_ms: u32, seed: u8) -> Packet {
        Packet::wrap(&one_hop(n, delay_ms), b"m", [seed; 32]).unwrap()
    }

    /// A clock that goes backwards must not reopen the replay window.
    ///
    /// NTP is attacker-influenceable (Malhotra et al., NDSS 2016). If rewinding the clock
    /// rewound the replay epoch, an adversary who can skew a node's time gets every packet
    /// it ever saw accepted a second time.
    #[test]
    fn a_rewound_clock_does_not_reopen_the_replay_window() {
        let mut n = node();
        let p = pkt(&n, 1, 1);
        n.accept(p.clone(), 5_000_000).unwrap();
        // Clock yanked back an hour.
        assert_eq!(n.accept(p, 1_400_000), Err(NodeError::Mix(MixError::Replay)));
    }

    /// A clock jumped forward must not age out the replay window either.
    ///
    /// Replay state is epoch-scoped, so forgetting is a matter of elapsed time. Without the
    /// clamp, an adversary buys that elapsed time by lying about the clock: jump two epochs,
    /// and every packet the node ever saw is accepted again. The clamp makes forgetting cost
    /// real time rather than one hostile reading.
    #[test]
    fn a_clock_jumped_forward_does_not_age_out_the_replay_window() {
        let mut n = node();
        let p = pkt(&n, 1, 2);
        n.accept(p.clone(), 0).unwrap();
        let ten_epochs = 10 * MixNode::DEFAULT_EPOCH_MS;
        assert_eq!(
            n.accept(p, ten_epochs),
            Err(NodeError::Mix(MixError::Replay))
        );
    }

    /// Replay state does age out with genuine elapsed time, which is the real bound.
    ///
    /// Stated rather than asserted away: a tag is retained across one epoch rotation and
    /// dropped after two, so the window is between one and two epochs. It exceeds
    /// `MAX_DELAY_MS` by a wide margin, so no packet can outlive the memory of having seen it.
    #[test]
    fn replay_state_ages_out_with_genuine_elapsed_time() {
        let mut n = node();
        let p = pkt(&n, 1, 2);
        n.accept(p.clone(), 0).unwrap();
        // Advance at the clamped rate, which is what honest elapsed time looks like.
        let mut r = 0;
        while r < 3 * MixNode::DEFAULT_EPOCH_MS {
            r += 5_000;
            n.due(r);
        }
        assert!(n.accept(p, r).is_ok());
        assert!(
            (MixNode::MAX_DELAY_MS as u64) < MixNode::DEFAULT_EPOCH_MS,
            "a packet must not be able to outlive the memory of having seen it"
        );
    }

    /// Packets due in the same release must not leave in arrival order.
    ///
    /// This is the defect a functional test cannot see. Any real node polls `due` on an
    /// interval, so every poll releases a batch, and a batch ordered by arrival is a FIFO at
    /// the granularity of the poll. An observer correlating the node's input and output
    /// recovers the pairing directly.
    #[test]
    fn a_release_batch_is_not_in_arrival_order() {
        // 64 packets all becoming due at the same instant, entered in a known order.
        let mut arrival_order_count = 0;
        let trials = 40;
        for t in 0..trials {
            let mut n = MixNode::new(MixKey::from_seed([t as u8 + 1; 32]));
            for i in 0..64u8 {
                let p = Packet::wrap(&one_hop(&n, 100), &[i], [i + 1; 32]).unwrap();
                n.accept(p, 0).unwrap();
            }
            let out: Vec<u8> = n
                .due(100)
                .into_iter()
                .map(|o| match o {
                    Outbound::Deliver { payload } => payload[0],
                    _ => unreachable!(),
                })
                .collect();
            assert_eq!(out.len(), 64);
            let sorted: Vec<u8> = (0..64u8).collect();
            if out == sorted {
                arrival_order_count += 1;
            }
        }
        assert_eq!(
            arrival_order_count, 0,
            "{arrival_order_count}/{trials} release batches came out in arrival order"
        );
    }

    /// An adversary must not be able to squat queue slots indefinitely.
    ///
    /// `delay_ms` is chosen by the sender and is a u32, so an unbounded node holds a slot for
    /// up to 49 days at the cost of one packet. Filling the queue that way is permanent
    /// rather than transient denial of service.
    #[test]
    fn an_absurd_delay_is_refused_rather_than_squatting_a_slot() {
        let mut n = node();
        let r = n.accept(pkt(&n, u32::MAX, 3), 0);
        assert_eq!(r, Err(NodeError::DelayTooLong));
        assert_eq!(n.queued(), 0);
        // The bound itself is accepted.
        assert!(n.accept(pkt(&n, MixNode::MAX_DELAY_MS, 4), 0).is_ok());
    }

    /// A congested node says it is congested rather than claiming a replay.
    ///
    /// Reporting the wrong reason is not cosmetic: an operator reading replay counters sees
    /// an attack that is not happening and misses the one that is.
    #[test]
    fn congestion_is_reported_as_congestion() {
        let mut n = MixNode::with_capacity(MixKey::from_seed([7u8; 32]), 2);
        assert!(n.accept(pkt(&n, 500, 10), 0).is_ok());
        assert!(n.accept(pkt(&n, 500, 11), 0).is_ok());
        // Longest-held itself, so it is the one refused rather than evicting anyone.
        assert_eq!(n.accept(pkt(&n, 900, 12), 0), Err(NodeError::Congested));
        assert_eq!(n.stats().dropped_full, 1);
        assert_eq!(n.stats().rejected_replay, 0);
    }

    /// A squatter must not be able to lock honest traffic out of a full queue.
    ///
    /// This is the sniper attack's second lesson, which is that the obvious defence has the
    /// wrong sign. With a plain size cap the adversary's long holds survive and every honest
    /// packet arriving afterwards is refused, so the cap does the adversary's work.
    #[test]
    fn a_squatter_cannot_lock_honest_traffic_out_of_a_full_queue() {
        let mut n = MixNode::with_capacity(MixKey::from_seed([7u8; 32]), 32);
        // The adversary fills every slot with the longest hold a node allows.
        for i in 0..32u8 {
            n.accept(pkt(&n, MixNode::MAX_DELAY_MS, i + 1), 0).unwrap();
        }
        assert_eq!(n.queued(), 32);

        // Honest traffic, with ordinary delays, still gets in.
        for i in 0..32u8 {
            assert!(
                n.accept(pkt(&n, 40, i + 100), 0).is_ok(),
                "honest packet {i} refused while a squatter held the queue"
            );
        }
        assert_eq!(n.stats().evicted, 32, "the squatter should have been displaced");

        // And all of what is left is the honest traffic, leaving on its own schedule.
        let out = n.due(40);
        assert_eq!(out.len(), 32);
        assert_eq!(n.queued(), 0);
    }

    /// Eviction must not be usable as a way to push others out for free.
    ///
    /// If a new arrival always won, an adversary would send max-delay packets to evict
    /// max-delay packets and the rule would just be a slower refusal. The longest hold loses
    /// whether it is already queued or arriving.
    #[test]
    fn the_longest_hold_loses_even_when_it_is_the_new_arrival() {
        let mut n = MixNode::with_capacity(MixKey::from_seed([7u8; 32]), 4);
        for i in 0..4u8 {
            n.accept(pkt(&n, 100, i + 1), 0).unwrap();
        }
        assert_eq!(
            n.accept(pkt(&n, MixNode::MAX_DELAY_MS, 50), 0),
            Err(NodeError::Congested)
        );
        assert_eq!(n.stats().evicted, 0);
        assert_eq!(n.queued(), 4);
    }

    /// Flooding must not flush a held packet **on demand**.
    ///
    /// This is a narrower claim than it is tempting to make. Against a threshold or pool mix
    /// the n-1 attack is exact: fill the batch and the one unknown packet is forced out alone.
    /// A mix where every packet carries its own independent delay has no batch boundary to
    /// force, which is what this asserts.
    ///
    /// It is **not** immunity to n-1, and the literature is clear that no such immunity
    /// exists. Kesdogan, Egner and Buschkes note in their own paper that random delay alone
    /// does not stop the attack, because an adversary can flood and keep flooding until the
    /// real packet emerges. Serjantov, Dingledine and Syverson (*From a Trickle to a Flood*,
    /// IH 2002) explicitly decline to clear stop-and-go mixes, deferring the analysis. Loopix
    /// treats n-1 as live and answers it with detection rather than structure: mixes send
    /// self-loops and compare the returning fraction against a threshold, following Danezis
    /// and Sassaman (*Heartbeat Traffic to Counter (n-1) Attacks*, WPES 2003).
    ///
    /// So the honest claim is that a continuous mix converts an exact attack into a
    /// probabilistic one, and the residue is handled at L4 by `loops`, not here.
    #[test]
    fn flooding_does_not_flush_a_held_packet_on_demand() {
        let mut n = node();
        // The target, held for 400ms.
        let target = Packet::wrap(&one_hop(&n, 400), b"target", [200u8; 32]).unwrap();
        n.accept(target, 0).unwrap();

        // The adversary floods 5000 packets that release immediately.
        for i in 0..5000u32 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            seed[8..12].copy_from_slice(&i.to_le_bytes());
            let p = Packet::wrap(&one_hop(&n, 0), b"flood", seed).unwrap();
            n.accept(p, 1).unwrap();
        }
        let flushed = n.due(1);
        assert_eq!(flushed.len(), 5000, "the flood leaves, as it asked to");
        // The target is untouched by any of it.
        assert_eq!(n.queued(), 1);
        assert!(n.due(399).is_empty());
        assert_eq!(n.due(400).len(), 1, "the target leaves on its own schedule");
    }

    /// A forged packet must not consume a queue slot.
    #[test]
    fn forged_packets_do_not_consume_queue_slots() {
        let mut n = MixNode::with_capacity(MixKey::from_seed([7u8; 32]), 4);
        for i in 0..1000u16 {
            let p = pkt(&n, 100, (i % 250) as u8 + 1).tamper_header(3);
            let _ = n.accept(p, 0);
        }
        assert_eq!(n.queued(), 0);
        assert!(n.accept(pkt(&n, 100, 99), 0).is_ok());
    }

    /// Time standing still must not release anything early, and must not lose anything.
    #[test]
    fn a_stopped_clock_holds_rather_than_leaks_or_drops() {
        let mut n = node();
        n.accept(pkt(&n, 50, 1), 1000).unwrap();
        for _ in 0..100 {
            assert!(n.due(1000).is_empty());
        }
        assert_eq!(n.queued(), 1);
        assert_eq!(n.due(1050).len(), 1);
    }

    /// A clock yanked forward must not flush the queue.
    ///
    /// This is the attack that makes the clock worth defending. An adversary who can push a
    /// node's time forward releases everything held with no delay, which is a mixing bypass
    /// obtained without touching a single packet.
    #[test]
    fn a_clock_yanked_forward_does_not_flush_the_queue() {
        let mut n = node();
        for i in 0..32u8 {
            n.accept(pkt(&n, MixNode::MAX_DELAY_MS, i + 1), 1000).unwrap();
        }
        assert_eq!(n.queued(), 32);
        // A year into the future, in one reading.
        assert!(
            n.due(1000 + 86_400_000 * 365).is_empty(),
            "the queue flushed on a single hostile clock reading"
        );
        assert_eq!(n.queued(), 32);
    }

    /// The clamp bounds how fast a hostile clock drains a queue, rather than stopping it.
    ///
    /// Stating the bound is the point: a node reading time from one source cannot detect that
    /// source lying, so the guarantee is that lying costs throughput and not anonymity.
    #[test]
    fn a_hostile_clock_drains_at_the_clamped_rate_and_no_faster() {
        let mut n = node();
        n.accept(pkt(&n, MixNode::MAX_DELAY_MS, 1), 0).unwrap();
        let mut readings = 0;
        // Feeding wildly advancing readings, the packet still takes MAX_DELAY/MAX_ADVANCE
        // readings to come out.
        while n.queued() > 0 {
            readings += 1;
            n.due(readings * 1_000_000_000);
            assert!(readings < 100, "drained faster than the clamp allows");
        }
        assert_eq!(
            readings,
            (MixNode::MAX_DELAY_MS as u64).div_ceil(5_000),
            "the clamp is the binding constraint"
        );
    }

    /// An absurd clock reading must not overflow into an early release.
    #[test]
    fn an_absurd_clock_reading_does_not_wrap() {
        let mut n = node();
        n.accept(pkt(&n, 1000, 1), u64::MAX - 10).unwrap();
        assert!(n.due(u64::MAX).is_empty());
        assert_eq!(n.queued(), 1);
    }
}
