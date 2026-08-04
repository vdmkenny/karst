//! The active adversary, and whether Poisson delay earns its place.
//!
//! Issue #26. The passive harness in [`crate::sim`] produced a negative result: constant
//! rate cover did all the work, and cover with prompt forwarding scored identically to
//! cover with Poisson delay. Uniform emission every tick is effectively a **synchronous
//! batch mix**, and a batch mix is strong against an observer who only watches.
//!
//! Loopix justifies continuous-time mixing on two grounds the passive harness cannot
//! reach. This module tests both.
//!
//! # 1. The n-1 attack
//!
//! An adversary who can suppress traffic isolates a target message: block every other
//! honest packet entering a mix, inject packets it can recognise, and any departing
//! packet it did not inject is the target.
//!
//! Against a **batch mix** this is cheap. Suppress one round's arrivals and the mix
//! flushes empty except for the target.
//!
//! Against a **Poisson mix** there is no flush, so there is no moment when the mix is
//! empty except for the target. Residents from before the attack are still inside, and
//! because the exponential is memoryless their remaining delay does not shrink with how
//! long they have already waited. The adversary must suppress long enough to *drain* the
//! backlog, which costs a number of suppressed packets that this module measures.
//!
//! # 2. Loop cover traffic makes suppression loud
//!
//! Clients and mixes send packets addressed back to themselves. A suppressed loop is a loop
//! that never returns, which is evidence. The more packets an attack must suppress, the more
//! certainly it is detected. This is why the *cost* of the n-1 attack is the security
//! property, not just its possibility.
//!
//! The detection probability computed here is a per-packet model. [`crate::loops`] implements
//! the mechanism and answers the operational question instead: against a 5% ambient loss
//! baseline at a 0.001 false alarm rate, a 50% suppression is called within **8 completed
//! loops** and a 30% suppression within 20. An n-1 drain against a Poisson mix costs hundreds
//! of suppressed packets, so the alarm fires far inside the attack.
//!
//! # 3. Batching needs a clock, and continuous time does not
//!
//! A synchronous batch mix requires every node to agree on round boundaries. Under clock
//! skew the batches fragment, and a fragmented batch is a small anonymity set. A
//! continuous-time mix has no rounds and is indifferent.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Which mixing discipline is under attack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discipline {
    /// Flush everything at the end of each round. What cover-plus-prompt-forwarding is.
    Batch { round_ticks: u64 },
    /// Independent exponential delay per packet. What Loopix specifies.
    Poisson,
}

impl Discipline {
    pub fn label(&self) -> String {
        match self {
            Discipline::Batch { round_ticks } => format!("batch mix (round {round_ticks})"),
            Discipline::Poisson => "Poisson mix".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActiveConfig {
    pub discipline: Discipline,
    /// Honest packets arriving at this mix per tick.
    pub arrival_rate: f64,
    /// Mean per-packet delay, for the Poisson discipline.
    pub mean_delay: f64,
    /// Fraction of honest traffic that is loop cover, used for detection.
    pub loop_fraction: f64,
    /// How many independent attacks to run.
    pub trials: usize,
    pub seed: u64,
}

impl Default for ActiveConfig {
    fn default() -> Self {
        ActiveConfig {
            discipline: Discipline::Poisson,
            arrival_rate: 10.0,
            mean_delay: 8.0,
            loop_fraction: 0.10,
            trials: 300,
            seed: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActiveResult {
    pub label: String,
    /// Honest packets still inside the mix when the target departed. The adversary
    /// cannot tell the target from these. **1.0 means the target was fully isolated.**
    pub mean_anonymity_set: f64,
    /// Fraction of trials where the target left with no honest company at all.
    pub isolation_rate: f64,
    /// Honest packets the adversary had to suppress to mount the attack.
    pub mean_suppressed: f64,
    /// Probability that at least one suppressed packet was a loop, and the attack was
    /// therefore detected.
    pub detection_probability: f64,
}

/// Knuth's method. Fine at the rates used here.
fn poisson(rng: &mut StdRng, lambda: f64) -> usize {
    let l = (-lambda).exp();
    let mut k = 0usize;
    let mut p = 1.0f64;
    loop {
        p *= rng.gen_range(0.0f64..1.0);
        if p <= l {
            return k;
        }
        k += 1;
        if k > 10_000 {
            return k;
        }
    }
}

fn exp_sample(rng: &mut StdRng, mean: f64) -> f64 {
    let u: f64 = rng.gen_range(1e-12f64..1.0);
    -mean * (1.0 - u).ln()
}

/// Mount the n-1 attack against one mix and measure what it costs and what it yields.
///
/// Protocol per trial:
/// 1. Warm the mix to steady state with honest arrivals.
/// 2. The target packet enters.
/// 3. The adversary suppresses **all** further honest arrivals, and injects its own
///    packets, which it can recognise on the way out and therefore discounts.
/// 4. When the target departs, count the honest packets still inside. Those are the only
///    thing standing between the adversary and a positive identification.
pub fn n_minus_one(cfg: &ActiveConfig) -> ActiveResult {
    let mut rng = StdRng::seed_from_u64(cfg.seed);

    let mut sets = Vec::with_capacity(cfg.trials);
    let mut isolations = 0usize;
    let mut suppressed_total = 0.0f64;

    for _ in 0..cfg.trials {
        // Departure times of honest packets already inside, relative to t = 0 when the
        // target enters.
        let mut residents: Vec<f64> = Vec::new();

        match cfg.discipline {
            Discipline::Poisson => {
                // Warm to steady state. Occupancy of an M/M/infinity queue is
                // arrival_rate * mean_delay, so warm for well past that.
                let warm = (cfg.mean_delay * 10.0).ceil() as i64;
                for t in -warm..0 {
                    let n = poisson(&mut rng, cfg.arrival_rate);
                    for _ in 0..n {
                        let dep = t as f64 + exp_sample(&mut rng, cfg.mean_delay);
                        if dep > 0.0 {
                            residents.push(dep);
                        }
                    }
                }
            }
            Discipline::Batch { round_ticks } => {
                // Everything from the previous round has already flushed. What is inside
                // is whatever arrived since the last boundary. The adversary picks its
                // moment, so assume the worst case for the defender: the target enters
                // just after a flush.
                let r = round_ticks as f64;
                let elapsed_fraction: f64 = rng.gen_range(0.0f64..0.15);
                let n = poisson(&mut rng, cfg.arrival_rate * r * elapsed_fraction);
                for _ in 0..n {
                    residents.push(r);
                }
            }
        }

        // The target enters at t = 0 and departs when its own delay elapses.
        let target_departure = match cfg.discipline {
            Discipline::Poisson => exp_sample(&mut rng, cfg.mean_delay),
            Discipline::Batch { round_ticks } => round_ticks as f64,
        };

        // From t = 0 the adversary suppresses every honest arrival until the target is
        // out. That is the cost of the attack, and it is what loop traffic detects.
        let suppressed = cfg.arrival_rate * target_departure;
        suppressed_total += suppressed;

        // Honest packets still inside when the target leaves.
        let company = residents.iter().filter(|d| **d >= target_departure).count();

        sets.push(company as f64 + 1.0);
        if company == 0 {
            isolations += 1;
        }
    }

    let n = cfg.trials.max(1) as f64;
    let mean_suppressed = suppressed_total / n;
    // At least one of the suppressed packets being a loop.
    let detection_probability = 1.0 - (1.0 - cfg.loop_fraction).powf(mean_suppressed);

    ActiveResult {
        label: cfg.discipline.label(),
        mean_anonymity_set: sets.iter().sum::<f64>() / n,
        isolation_rate: isolations as f64 / n,
        mean_suppressed,
        detection_probability,
    }
}

/// How long an adversary must suppress traffic to drain a Poisson mix to a given
/// occupancy, and what that costs in suppressed packets.
///
/// Occupancy decays as `arrival_rate * mean_delay * exp(-t / mean_delay)`, so draining is
/// exponential in time and therefore linear in a logarithm of the backlog. There is no
/// equivalent for a batch mix: one round boundary empties it completely.
pub fn drain_cost(arrival_rate: f64, mean_delay: f64, target_occupancy: f64) -> (f64, f64) {
    let steady = arrival_rate * mean_delay;
    if steady <= target_occupancy {
        return (0.0, 0.0);
    }
    let ticks = mean_delay * (steady / target_occupancy).ln();
    (ticks, ticks * arrival_rate)
}

// ---------------------------------------------------------------- clock skew

#[derive(Clone, Debug)]
pub struct SkewResult {
    pub skew_ticks: f64,
    /// Mean packets sharing a batch. This is the anonymity set for a batch mix.
    pub mean_batch: f64,
    /// The worst batch observed. A batch of one is a packet with no anonymity at all.
    pub min_batch: usize,
    /// Fraction of batches with fewer than three packets in them.
    pub degenerate_fraction: f64,
}

/// A synchronous batch mix needs every node to agree on where a round begins. Under skew,
/// packets that should have shared a batch land in different ones, and the batches
/// fragment.
///
/// A Poisson mix has no rounds, so this function has no meaning for it, which is the
/// point.
pub fn batch_under_skew(
    arrival_rate: f64,
    round_ticks: f64,
    skew_ticks: f64,
    rounds: usize,
    seed: u64,
) -> SkewResult {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut batches: Vec<usize> = Vec::with_capacity(rounds);

    for r in 0..rounds {
        let nominal = r as f64 * round_ticks;
        // This node believes the round starts here.
        let perceived_start = nominal + rng.gen_range(-skew_ticks..=skew_ticks);
        let perceived_end = perceived_start + round_ticks;

        let n = poisson(&mut rng, arrival_rate * round_ticks);
        let mut count = 0usize;
        for _ in 0..n {
            // Arrival uniformly within the true round.
            let at = nominal + rng.gen_range(0.0..round_ticks);
            if at >= perceived_start && at < perceived_end {
                count += 1;
            }
        }
        batches.push(count);
    }

    let total: usize = batches.iter().sum();
    let degenerate = batches.iter().filter(|b| **b < 3).count();

    SkewResult {
        skew_ticks,
        mean_batch: total as f64 / rounds.max(1) as f64,
        min_batch: batches.iter().copied().min().unwrap_or(0),
        degenerate_fraction: degenerate as f64 / rounds.max(1) as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch_cfg() -> ActiveConfig {
        ActiveConfig {
            discipline: Discipline::Batch { round_ticks: 1 },
            ..ActiveConfig::default()
        }
    }

    #[test]
    fn a_batch_mix_falls_to_the_n_minus_one_attack() {
        let r = n_minus_one(&batch_cfg());
        assert!(
            r.isolation_rate > 0.5,
            "a batch mix should be isolated most of the time, got {:.2}",
            r.isolation_rate
        );
        assert!(
            r.mean_anonymity_set < 2.0,
            "target should leave nearly alone, got {:.2}",
            r.mean_anonymity_set
        );
    }

    #[test]
    fn a_poisson_mix_rarely_isolates_the_target_but_it_is_not_impossible() {
        let r = n_minus_one(&ActiveConfig::default());
        // Not zero. If the target happens to draw a long delay and every resident happens
        // to leave before it, it walks out alone. That is a real residual risk of a
        // probabilistic defence, it is roughly 1 trial in 150 at these parameters, and
        // rounding it to "never" would be the same overclaiming the passive harness was
        // already caught doing once.
        assert!(
            r.isolation_rate < 0.02,
            "isolation should be rare, got {:.4}",
            r.isolation_rate
        );
        assert!(
            r.mean_anonymity_set > 10.0,
            "target should almost always leave in company, got {:.2}",
            r.mean_anonymity_set
        );
    }

    /// This is the result the passive harness could not produce, and the reason the delay
    /// layer stays in the design.
    #[test]
    fn poisson_beats_batch_against_an_active_adversary() {
        let batch = n_minus_one(&batch_cfg());
        let poisson_mix = n_minus_one(&ActiveConfig::default());

        assert!(
            poisson_mix.mean_anonymity_set > batch.mean_anonymity_set * 10.0,
            "Poisson {:.1} vs batch {:.1}",
            poisson_mix.mean_anonymity_set,
            batch.mean_anonymity_set
        );
    }

    #[test]
    fn the_attack_is_far_louder_against_a_poisson_mix() {
        let batch = n_minus_one(&batch_cfg());
        let poisson_mix = n_minus_one(&ActiveConfig::default());

        assert!(
            poisson_mix.mean_suppressed > batch.mean_suppressed * 5.0,
            "suppression cost must be much higher: {:.0} vs {:.0}",
            poisson_mix.mean_suppressed,
            batch.mean_suppressed
        );
        assert!(
            poisson_mix.detection_probability > 0.99,
            "loop traffic should catch it, got {:.3}",
            poisson_mix.detection_probability
        );
    }

    #[test]
    fn draining_a_poisson_mix_is_expensive_and_a_batch_mix_needs_no_draining() {
        // Steady occupancy of 80 packets, drained to 1.
        let (ticks, packets) = drain_cost(10.0, 8.0, 1.0);
        assert!(ticks > 30.0, "should take many mean-delays, got {ticks:.1}");
        assert!(
            packets > 300.0,
            "should cost hundreds of suppressed packets, got {packets:.0}"
        );

        // Already below target means no work at all, which is the batch mix case after a
        // single flush.
        assert_eq!(drain_cost(10.0, 8.0, 100.0), (0.0, 0.0));
    }

    #[test]
    fn loop_detection_scales_with_how_much_the_attack_must_suppress() {
        let quiet = 1.0 - 0.9f64.powf(10.0);
        let loud = 1.0 - 0.9f64.powf(350.0);
        assert!(quiet < 0.7);
        assert!(loud > 0.999);
    }

    #[test]
    fn clock_skew_fragments_batches() {
        let none = batch_under_skew(10.0, 1.0, 0.0, 400, 5);
        let some = batch_under_skew(10.0, 1.0, 0.5, 400, 5);
        let lots = batch_under_skew(10.0, 1.0, 1.0, 400, 5);

        assert!(none.mean_batch > some.mean_batch);
        assert!(some.mean_batch > lots.mean_batch);
        assert!(
            lots.degenerate_fraction > none.degenerate_fraction,
            "skew must produce tiny batches: {:.3} vs {:.3}",
            lots.degenerate_fraction,
            none.degenerate_fraction
        );
    }

    #[test]
    fn a_poisson_mix_has_no_rounds_to_desynchronise() {
        // Nothing to assert numerically. The point is structural: batch_under_skew has no
        // Poisson equivalent because there is no round boundary to disagree about, and a
        // mechanism you cannot misconfigure is worth something.
        let r = n_minus_one(&ActiveConfig {
            discipline: Discipline::Poisson,
            ..ActiveConfig::default()
        });
        assert!(r.mean_anonymity_set > 10.0);
    }
}

/// What the delay parameter actually buys, measured against the adversary it is for.
///
/// The passive adversary is saturated by cover traffic alone, so it cannot price delay. The
/// n-1 attack can: an adversary drains a mix to isolate one message, and how hard that is
/// depends on how much is resident when it starts.
///
/// Measured, 600 trials per row:
///
/// | rate | delay | occupancy | isolation | suppressed |
/// |---|---|---|---|---|
/// | 10 | 0.5 | 5 | 0.518 | 5 |
/// | 10 | 1 | 10 | 0.185 | 10 |
/// | 10 | 2 | 20 | 0.058 | 20 |
/// | 10 | 8 | 80 | 0.015 | 83 |
/// | 10 | 16 | 160 | 0.005 | 168 |
/// | 40 | 0.5 | 20 | **0.157** | 19 |
/// | 40 | 2 | 80 | 0.022 | 82 |
/// | 2.5 | 8 | 20 | 0.052 | 20 |
/// | 2.5 | 32 | 80 | 0.022 | 83 |
///
/// **Mean pool occupancy governs isolation, and the delay itself does not, with one exception
/// that matters.** Occupancy is `arrival_rate * mean_delay` for an M/M/infinity queue, and the
/// rows at occupancy 80 agree to within 0.007 across a sixteen-fold spread of arrival rates.
/// So a deployment can pick its delay from its own arrival rate and an isolation target rather
/// than choosing a number.
///
/// The exception is the row in bold. At occupancy 20 the three samples are 0.052, 0.058 and
/// **0.157**, and the outlier is the one with a mean delay of half a tick. Below roughly one
/// tick the exponential has no room to spread, most packets leave in the tick they arrive, and
/// the discipline degrades toward the batch behaviour it exists to avoid. Occupancy alone stops
/// predicting it.
///
/// So the rule has two parts, and a derivation that uses only the first will pick a delay that
/// does not work: **set occupancy from the isolation target, and keep the mean delay above the
/// granularity of the schedule.**
///
/// Returns `(arrival_rate, mean_delay, occupancy, isolation, suppressed)`.
pub fn delay_frontier(seed: u64) -> Vec<(f64, f64, f64, f64, f64)> {
    let mut out = Vec::new();
    for (rate, delay) in [
        (10.0, 0.5),
        (10.0, 1.0),
        (10.0, 2.0),
        (10.0, 4.0),
        (10.0, 8.0),
        (10.0, 16.0),
        // Same occupancies reached from a different rate, to test the product hypothesis.
        (40.0, 0.5),
        (40.0, 2.0),
        (2.5, 8.0),
        (2.5, 32.0),
    ] {
        let cfg = ActiveConfig {
            discipline: Discipline::Poisson,
            arrival_rate: rate,
            mean_delay: delay,
            trials: 600,
            seed,
            ..ActiveConfig::default()
        };
        let r = n_minus_one(&cfg);
        out.push((
            rate,
            delay,
            rate * delay,
            r.isolation_rate,
            r.mean_suppressed,
        ));
    }
    out
}

#[cfg(test)]
mod delay_frontier_tests {
    use super::*;

    /// Isolation tracks mean pool occupancy, not delay on its own.
    ///
    /// This is what makes the delay derivable rather than chosen: two configurations with the
    /// same `arrival_rate * mean_delay` are about equally hard to drain, so a deployment
    /// reasons from its own arrival rate to its own delay.
    ///
    /// Restricted to mean delays of at least one tick, because that is where it holds. The
    /// companion test below establishes that it stops holding below that, and the two together
    /// are the rule: occupancy sets the target, and the delay has to stay above the schedule's
    /// granularity for occupancy to mean anything.
    #[test]
    fn isolation_is_governed_by_occupancy_rather_than_delay_alone() {
        let rows = delay_frontier(5);

        let mut groups: std::collections::BTreeMap<u64, Vec<f64>> = Default::default();
        for (_, delay, occ, iso, _) in &rows {
            if *delay < 1.0 {
                continue;
            }
            groups.entry(occ.round() as u64).or_default().push(*iso);
        }
        let mut compared = 0;
        for (occ, isos) in &groups {
            if isos.len() < 2 {
                continue;
            }
            compared += 1;
            let lo = isos.iter().cloned().fold(f64::MAX, f64::min);
            let hi = isos.iter().cloned().fold(f64::MIN, f64::max);
            assert!(
                hi - lo < 0.02,
                "at occupancy {occ} isolation ranged {lo:.3} to {hi:.3} across arrival rates, \
                 so the product does not govern it and the delay cannot be derived"
            );
        }
        assert!(
            compared >= 2,
            "fewer than two occupancies had multiple samples, so this compared nothing"
        );
    }

    /// Below a tick of mean delay, occupancy stops predicting isolation.
    ///
    /// A derivation that used occupancy alone would happily trade a long delay for a high
    /// arrival rate and arrive at a configuration that does not defend. At half a tick the
    /// exponential has no room to spread: most packets leave in the tick they arrive, and the
    /// discipline degrades toward the batch behaviour delay exists to avoid.
    ///
    /// Asserted rather than mentioned, because it is the failure mode of the rule above and
    /// the rule is the useful output of this module.
    #[test]
    fn a_sub_tick_delay_is_worse_than_its_occupancy_predicts() {
        let rows = delay_frontier(5);
        let at = |r: f64, d: f64| {
            rows.iter()
                .find(|x| x.0 == r && x.1 == d)
                .map(|x| x.3)
                .expect("row")
        };
        // Three configurations, all at occupancy 20.
        let sub_tick = at(40.0, 0.5);
        let ordinary = at(10.0, 2.0);
        let long = at(2.5, 8.0);

        assert!(
            (ordinary - long).abs() < 0.02,
            "the two above-tick samples disagree ({ordinary:.3} vs {long:.3}), so this test \
             cannot attribute the outlier to the sub-tick delay"
        );
        assert!(
            sub_tick > ordinary * 2.0,
            "half a tick of delay gave isolation {sub_tick:.3} against {ordinary:.3} at the \
             same occupancy, so the granularity floor this documents does not exist"
        );
    }

    /// More occupancy is monotonically harder to drain, so there is something to solve for.
    #[test]
    fn draining_a_fuller_mix_is_harder() {
        let rows = delay_frontier(5);
        let at = |r: f64, d: f64| {
            rows.iter()
                .find(|x| x.0 == r && x.1 == d)
                .map(|x| (x.3, x.4))
                .expect("row")
        };
        let (thin_iso, thin_cost) = at(10.0, 0.5);
        let (thick_iso, thick_cost) = at(10.0, 16.0);

        assert!(
            thin_iso > thick_iso,
            "a nearly empty mix ({thin_iso:.3}) was not easier to isolate in than a full one \
             ({thick_iso:.3})"
        );
        assert!(
            thick_cost > thin_cost * 4.0,
            "draining the full mix cost {thick_cost:.0} suppressed packets against \
             {thin_cost:.0} for the thin one, which is not the separation the delay is for"
        );
    }
}
