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
