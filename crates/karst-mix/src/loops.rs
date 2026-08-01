//! Loop cover traffic, and telling an attack apart from a bad afternoon.
//!
//! A loop is a packet a node addresses back to itself, routed through the network like any
//! other. Because Sphinx hides the destination and the payload from every intermediate hop, a
//! loop is indistinguishable from real traffic, so **an adversary cannot suppress traffic
//! without suppressing loops**. Loops that fail to return are evidence.
//!
//! That is the easy half. The hard half is that networks drop packets anyway. A detector that
//! alarms on any loss is useless, and one that needs certainty never fires. The mechanism is
//! therefore a **statistical test against a measured baseline**, with an explicit false alarm
//! rate, and the number that matters is not "loops detect attacks" but *how many loops it
//! takes to detect a suppression of a given intensity*.
//!
//! `crate::active` reports 100% detection against the n-1 attack. That figure came from an
//! analytic model of a mechanism that did not exist. This is the mechanism, and it puts a
//! sample count on the claim.

use std::collections::BTreeMap;

use crate::packet::{Hop, MixError, Packet};

/// A loop this node is waiting to receive back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopToken {
    pub nonce: [u8; 16],
    pub dispatched_at: u64,
    /// After this tick the loop counts as lost rather than late.
    pub deadline: u64,
}

/// Why the detector fired.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Alarm {
    pub observed_losses: usize,
    pub samples: usize,
    pub observed_rate: f64,
    pub baseline_rate: f64,
    /// Probability of seeing at least this many losses if nothing were wrong.
    pub p_value: f64,
}

/// Where the baseline loss rate comes from, which is a security decision and not a detail.
///
/// **A measured baseline is attacker-controlled.** An adversary who drops packets steadily
/// before attacking raises the measured baseline, and then attacks underneath the inflated
/// figure without ever crossing the threshold. Any detector that learns its own normal from a
/// channel the adversary sits on has this problem.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Baseline {
    /// Set out of band, from a source the adversary does not sit on. Not poisonable.
    Fixed(f64),
    /// Learned from observation, and permitted to fall but never to rise beyond `ceiling`.
    ///
    /// The ratchet is what stops poisoning: an adversary can degrade the channel, and cannot
    /// convince the detector that degradation is normal. The cost is that genuine long-term
    /// deterioration produces standing alarms rather than a quietly raised threshold, which is
    /// the correct direction to fail.
    Ratcheted { current: f64, ceiling: f64 },
}

impl Baseline {
    pub fn rate(&self) -> f64 {
        match self {
            Baseline::Fixed(p) => *p,
            Baseline::Ratcheted { current, .. } => *current,
        }
    }

    /// Fold in an observation. Fixed baselines ignore it entirely.
    pub fn observe(&mut self, observed: f64) {
        if let Baseline::Ratcheted { current, ceiling } = self {
            let capped = observed.min(*ceiling);
            if capped < *current {
                *current = capped;
            }
        }
    }
}

/// Tracks outstanding loops and decides when loss stops looking like weather.
pub struct LoopTracker {
    outstanding: BTreeMap<[u8; 16], LoopToken>,
    returned: usize,
    lost: usize,
    /// What this node considers normal loss. See [`Baseline`] for why the source matters.
    pub baseline: Baseline,
    /// Tolerated false alarm probability.
    pub alpha: f64,
}

impl LoopTracker {
    pub fn new(baseline_loss: f64, alpha: f64) -> Self {
        LoopTracker {
            outstanding: BTreeMap::new(),
            returned: 0,
            lost: 0,
            baseline: Baseline::Fixed(baseline_loss),
            alpha,
        }
    }

    pub fn with_baseline(baseline: Baseline, alpha: f64) -> Self {
        LoopTracker {
            outstanding: BTreeMap::new(),
            returned: 0,
            lost: 0,
            baseline,
            alpha,
        }
    }

    pub fn dispatch(&mut self, nonce: [u8; 16], now: u64, timeout: u64) {
        self.outstanding.insert(
            nonce,
            LoopToken {
                nonce,
                dispatched_at: now,
                deadline: now + timeout,
            },
        );
    }

    /// A loop came back. Returns false for a nonce this node did not send, which is either a
    /// duplicate or someone else's traffic and is not evidence of anything.
    pub fn observe_return(&mut self, nonce: &[u8; 16]) -> bool {
        if self.outstanding.remove(nonce).is_some() {
            self.returned += 1;
            true
        } else {
            false
        }
    }

    /// Move overdue loops to the lost pile.
    pub fn expire(&mut self, now: u64) -> usize {
        let overdue: Vec<[u8; 16]> = self
            .outstanding
            .values()
            .filter(|t| now > t.deadline)
            .map(|t| t.nonce)
            .collect();
        for n in &overdue {
            self.outstanding.remove(n);
        }
        self.lost += overdue.len();
        overdue.len()
    }

    pub fn samples(&self) -> usize {
        self.returned + self.lost
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    pub fn loss_rate(&self) -> f64 {
        let n = self.samples();
        if n == 0 {
            return 0.0;
        }
        self.lost as f64 / n as f64
    }

    /// Fire if the observed loss would be improbable under the baseline.
    ///
    /// The test is a one-sided binomial tail: given `n` completed loops and a baseline loss
    /// rate `p`, how likely is it to lose at least this many by chance. Below `alpha`, call it
    /// an attack.
    ///
    /// This is the whole reason the mechanism is not trivial. Alarming on any loss cries wolf
    /// on every congested evening; requiring certainty never fires at all.
    pub fn alarm(&self) -> Option<Alarm> {
        let n = self.samples();
        if n == 0 {
            return None;
        }
        let p = binomial_tail(self.lost, n, self.baseline.rate());
        if p < self.alpha {
            Some(Alarm {
                observed_losses: self.lost,
                samples: n,
                observed_rate: self.loss_rate(),
                baseline_rate: self.baseline.rate(),
                p_value: p,
            })
        } else {
            None
        }
    }
}

/// `P(X >= k)` for `X ~ Binomial(n, p)`.
///
/// Computed by forward recurrence on the PMF, which is stable enough at the sample sizes a
/// node actually accumulates and needs no special functions.
pub fn binomial_tail(k: usize, n: usize, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > n {
        return 0.0;
    }
    if p <= 0.0 {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }

    let mut pmf = (1.0 - p).powi(n as i32);
    let ratio = p / (1.0 - p);
    let mut tail = 0.0;
    for i in 0..=n {
        if i >= k {
            tail += pmf;
        }
        pmf *= ((n - i) as f64 / (i + 1) as f64) * ratio;
    }
    tail.clamp(0.0, 1.0)
}

/// How many completed loops are needed before a suppression of the given intensity is called.
///
/// Returns `None` if the attack is too weak to separate from baseline within `max_samples`.
pub fn samples_to_detect(
    baseline: f64,
    attack_loss: f64,
    alpha: f64,
    max_samples: usize,
) -> Option<usize> {
    if attack_loss <= baseline {
        return None;
    }
    for n in 1..=max_samples {
        // The expected number of losses at this sample size, rounded down: the detector needs
        // this to be improbable under baseline.
        let k = (attack_loss * n as f64).floor() as usize;
        if k > 0 && binomial_tail(k, n, baseline) < alpha {
            return Some(n);
        }
    }
    None
}

/// Build a loop: a packet routed through the network and back to this node.
///
/// The final hop is the sender itself, so delivery lands at home. Every intermediate hop sees
/// an ordinary packet, because Sphinx gives it no way to see otherwise, which is what makes
/// loops uncensorable without censoring everything.
pub fn loop_packet(
    route_out: &[Hop],
    self_hop: Hop,
    nonce: [u8; 16],
    seed: [u8; 32],
) -> Result<Packet, MixError> {
    let mut route: Vec<Hop> = route_out.to_vec();
    route.push(self_hop);
    Packet::wrap(&route, &nonce, seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{MixKey, Peeled, SeenTags};

    #[test]
    fn a_loop_returns_to_its_sender_and_is_recognised() {
        let mids: Vec<MixKey> = (0..2).map(|i| MixKey::from_seed([i + 1; 32])).collect();
        let home = MixKey::from_seed([200u8; 32]);

        let route: Vec<Hop> = mids
            .iter()
            .enumerate()
            .map(|(i, k)| Hop {
                id: i as u16,
                public: k.public(),
                delay_ms: 5,
            })
            .collect();
        let self_hop = Hop {
            id: 99,
            public: home.public(),
            delay_ms: 0,
        };

        let nonce = [7u8; 16];
        let p = loop_packet(&route, self_hop, nonce, [3u8; 32]).unwrap();

        let mut tracker = LoopTracker::new(0.01, 0.001);
        tracker.dispatch(nonce, 0, 100);
        assert_eq!(tracker.outstanding(), 1);

        // Walk it through the network and home.
        let mut seen: Vec<SeenTags> = (0..3).map(|_| SeenTags::new()).collect();
        let mut cur = p;
        for (i, k) in mids.iter().enumerate() {
            let Peeled::Forward { packet, .. } = cur.peel(k, &mut seen[i]).unwrap() else {
                panic!("hop {i} should forward")
            };
            cur = packet;
        }
        let Peeled::Deliver { payload, .. } = cur.peel(&home, &mut seen[2]).unwrap() else {
            panic!("should have come home")
        };

        let mut got = [0u8; 16];
        got.copy_from_slice(&payload);
        assert!(tracker.observe_return(&got));
        assert_eq!(tracker.outstanding(), 0);
        assert_eq!(tracker.samples(), 1);
        assert_eq!(tracker.loss_rate(), 0.0);
    }

    #[test]
    fn a_nonce_this_node_did_not_send_is_not_evidence() {
        let mut t = LoopTracker::new(0.01, 0.001);
        assert!(!t.observe_return(&[1u8; 16]));
        assert_eq!(t.samples(), 0);
    }

    #[test]
    fn overdue_loops_become_losses_and_late_ones_do_not() {
        let mut t = LoopTracker::new(0.01, 0.001);
        t.dispatch([1u8; 16], 0, 10);
        t.dispatch([2u8; 16], 0, 10);

        assert_eq!(t.expire(5), 0, "not yet due");
        assert_eq!(t.expire(11), 2);
        assert_eq!(t.loss_rate(), 1.0);
    }

    /// **The property that makes this usable.** Ordinary loss must not cry wolf, or operators
    /// turn the detector off and the mechanism is worth nothing.
    #[test]
    fn ambient_loss_does_not_raise_an_alarm() {
        let mut t = LoopTracker::new(0.05, 0.001);
        // 500 loops at exactly the baseline rate.
        for i in 0..500u32 {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            t.dispatch(n, 0, 10);
            if i % 20 == 0 {
                continue; // 5% never come back
            }
            t.observe_return(&n);
        }
        t.expire(11);

        assert!((t.loss_rate() - 0.05).abs() < 0.01);
        assert!(
            t.alarm().is_none(),
            "fired at baseline: {:?}",
            t.alarm()
        );
    }

    #[test]
    fn sustained_suppression_raises_an_alarm() {
        let mut t = LoopTracker::new(0.05, 0.001);
        // Half the loops disappear.
        for i in 0..200u32 {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            t.dispatch(n, 0, 10);
            if i % 2 == 0 {
                continue;
            }
            t.observe_return(&n);
        }
        t.expire(11);

        let a = t.alarm().expect("50% loss against a 5% baseline must fire");
        assert!(a.observed_rate > 0.4);
        assert!(a.p_value < 0.001);
    }

    /// The number that turns the claim into a measurement. An n-1 attack against a Poisson mix
    /// costs hundreds of suppressed packets (see `crate::active`), so the question is whether
    /// the detector fires well inside that budget.
    #[test]
    fn detection_arrives_long_before_an_n_minus_one_attack_completes() {
        let baseline = 0.05;
        let alpha = 0.001;

        // A drain suppresses most traffic through the target mix.
        let n = samples_to_detect(baseline, 0.5, alpha, 10_000)
            .expect("heavy suppression must be detectable");
        assert!(
            n < 40,
            "needed {n} loops to call a 50% suppression, which is too slow"
        );

        // Even a light touch is caught, just later.
        let light = samples_to_detect(baseline, 0.15, alpha, 10_000)
            .expect("a 15% suppression must eventually be detectable");
        assert!(light > n, "a subtler attack should take longer, not less");
    }

    #[test]
    fn an_attack_at_the_baseline_rate_is_not_detectable_and_the_api_says_so() {
        // An adversary who suppresses only as much as the network already loses is invisible
        // to this mechanism. That is a real limit and it returns None rather than a number.
        assert_eq!(samples_to_detect(0.05, 0.05, 0.001, 10_000), None);
        assert_eq!(samples_to_detect(0.05, 0.01, 0.001, 10_000), None);
    }

    #[test]
    fn a_tighter_false_alarm_rate_costs_samples() {
        let loose = samples_to_detect(0.05, 0.3, 0.01, 10_000).unwrap();
        let tight = samples_to_detect(0.05, 0.3, 1e-9, 10_000).unwrap();
        assert!(
            tight > loose,
            "demanding more certainty must cost more loops: {loose} then {tight}"
        );
    }

    #[test]
    fn the_binomial_tail_behaves() {
        assert_eq!(binomial_tail(0, 10, 0.5), 1.0);
        assert_eq!(binomial_tail(11, 10, 0.5), 0.0);
        // Ten of ten at p=0.5 is 1/1024.
        assert!((binomial_tail(10, 10, 0.5) - 0.0009765625).abs() < 1e-9);
        // Monotone in k.
        for k in 1..10 {
            assert!(binomial_tail(k, 10, 0.3) >= binomial_tail(k + 1, 10, 0.3));
        }
    }
}


/// Attacks on the detector.
#[cfg(test)]
mod adversarial {
    use super::*;

    fn run_loops(t: &mut LoopTracker, total: u32, lose_every: u32) {
        for i in 0..total {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            t.dispatch(n, 0, 10);
            if lose_every > 0 && i % lose_every == 0 {
                continue;
            }
            t.observe_return(&n);
        }
        t.expire(11);
    }

    /// **Baseline poisoning.** An adversary who degrades the channel steadily before attacking
    /// raises a learned baseline, then attacks underneath it. Any detector that learns its
    /// normal from a channel the adversary sits on has this problem.
    #[test]
    fn a_learned_baseline_can_be_poisoned_and_the_ratchet_stops_it() {
        // Naive: the detector adopts whatever it sees.
        let mut naive = Baseline::Ratcheted {
            current: 0.05,
            ceiling: 1.0,
        };
        // An adversary drives observed loss to 40%, hoping the detector accepts it as normal.
        naive.observe(0.40);
        assert_eq!(
            naive.rate(),
            0.05,
            "the ratchet must refuse to raise the baseline"
        );

        // Genuine improvement is still adopted, which is the point of learning at all.
        naive.observe(0.01);
        assert_eq!(naive.rate(), 0.01);

        // And having fallen, it will not be talked back up.
        naive.observe(0.30);
        assert_eq!(naive.rate(), 0.01);
    }

    #[test]
    fn a_fixed_baseline_ignores_observation_entirely() {
        let mut b = Baseline::Fixed(0.05);
        b.observe(0.99);
        b.observe(0.0);
        assert_eq!(b.rate(), 0.05);
    }

    /// **The adaptive adversary**, and the permanent limit. Suppressing at or below what the
    /// network already loses is invisible however long you watch.
    #[test]
    fn an_adversary_who_stays_under_the_baseline_is_never_detected() {
        let mut t = LoopTracker::new(0.10, 0.001);
        // 10% loss against a 10% baseline, over a large sample.
        run_loops(&mut t, 2_000, 10);
        assert!(
            t.alarm().is_none(),
            "an at-baseline attacker fired the alarm, which would be a false positive"
        );
        assert_eq!(samples_to_detect(0.10, 0.10, 0.001, 100_000), None);
    }

    /// An adversary who delays rather than drops causes loops to time out and then arrive.
    /// The tracker counts them lost, which is a false alarm an adversary can induce
    /// deliberately to make the detector untrustworthy and get it turned off.
    #[test]
    fn delayed_loops_are_counted_lost_and_a_late_return_does_not_undo_it() {
        let mut t = LoopTracker::new(0.01, 0.001);
        t.dispatch([1u8; 16], 0, 10);
        t.expire(11);
        assert_eq!(t.loss_rate(), 1.0);

        // The loop finally arrives. It is no longer outstanding, so it is not credited.
        assert!(
            !t.observe_return(&[1u8; 16]),
            "a late return must not silently reverse a recorded loss"
        );
        assert_eq!(t.loss_rate(), 1.0);
    }

    /// A hostile peer replaying returns cannot inflate the success count.
    #[test]
    fn replayed_returns_do_not_manufacture_successes() {
        let mut t = LoopTracker::new(0.01, 0.001);
        t.dispatch([1u8; 16], 0, 10);
        assert!(t.observe_return(&[1u8; 16]));
        for _ in 0..100 {
            assert!(!t.observe_return(&[1u8; 16]));
        }
        assert_eq!(t.samples(), 1);
    }

    /// A single unlucky loss must not fire the alarm, or the detector is noise.
    #[test]
    fn a_tiny_sample_does_not_fire() {
        let mut t = LoopTracker::new(0.05, 0.001);
        t.dispatch([1u8; 16], 0, 10);
        t.expire(11);
        assert_eq!(t.loss_rate(), 1.0);
        assert!(
            t.alarm().is_none(),
            "one lost loop out of one is not evidence of anything"
        );
    }
}
