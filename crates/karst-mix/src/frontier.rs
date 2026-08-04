//! Where KARST sits against a proven lower bound.
//!
//! Das, Meiser, Mohammadi and Kate prove an **anonymity trilemma** (*Strong Anonymity, Low
//! Bandwidth Overhead, Low Latency: Choose Two*, IEEE S&P 2018): an anonymous communication
//! protocol can have at most two of strong anonymity, low bandwidth overhead, and low latency
//! overhead, against a global passive adversary.
//!
//! This matters for two reasons.
//!
//! **The costs are not sloppiness.** KARST's roughly 200x bandwidth and seconds of latency
//! read like implementation waste. They are not. Strong anonymity against a whole-network
//! observer requires paying at least one of them, and the theorem says so independently of
//! how well anyone codes.
//!
//! **KARST pays both, which is more than the theorem demands.** That is worth stating plainly
//! rather than presenting as thoroughness. Either the extra payment buys margin against
//! attacks the trilemma does not model, which the active-adversary results suggest it does,
//! or there is slack here to reclaim. This module maps the empirical frontier so the question
//! has numbers attached instead of opinions.

use crate::sim::{run, SimConfig};

/// One point on the cost/anonymity surface.
#[derive(Clone, Debug)]
pub struct FrontierPoint {
    /// Packets sent per real message.
    pub bandwidth_overhead: f64,
    /// Mean per-hop delay, in ticks.
    pub latency: f64,
    /// Clients the adversary cannot rule out, as a fraction of the population.
    pub anonymity_fraction: f64,
    /// How much better than guessing the adversary does. 1.0 means the design held.
    pub adversary_gain: f64,
}

impl FrontierPoint {
    /// Whether this configuration resists the modelled global passive adversary.
    pub fn strong(&self) -> bool {
        self.adversary_gain < 1.05
    }
}

/// Sweep the two costs the trilemma names and report where anonymity survives.
///
/// `cover` false means a client transmits only when it has traffic, which is the
/// low-bandwidth corner. `mean_delay` is the latency knob.
pub fn sweep(cover: bool, delays: &[f64], seed: u64) -> Vec<FrontierPoint> {
    delays
        .iter()
        .map(|d| {
            let mut cfg = SimConfig::karst(seed);
            cfg.cover = cover;
            cfg.mean_delay = *d;
            let r = run(&cfg);
            FrontierPoint {
                bandwidth_overhead: r.bandwidth_overhead(),
                latency: *d,
                anonymity_fraction: r.mean_anonymity_set / r.clients as f64,
                adversary_gain: r.advantage(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The low-bandwidth corner. Without cover traffic, buying anonymity with latency alone
    /// works but is expensive in delay and never quite reaches the padded result.
    #[test]
    fn latency_alone_buys_anonymity_slowly() {
        let pts = sweep(false, &[1.0, 8.0, 32.0, 128.0], 7);

        assert!(
            pts.iter().all(|p| p.bandwidth_overhead < 2.0),
            "this corner is cheap on bandwidth"
        );
        // Monotone: more delay, more anonymity.
        for w in pts.windows(2) {
            assert!(
                w[1].anonymity_fraction >= w[0].anonymity_fraction - 0.02,
                "delay {} to {} lost ground",
                w[0].latency,
                w[1].latency
            );
        }
        assert!(
            !pts[0].strong(),
            "one tick of delay and no padding cannot be strong"
        );
    }

    /// The high-bandwidth corner. Cover traffic reaches strong anonymity at every latency,
    /// including the lowest one tested.
    #[test]
    fn bandwidth_alone_buys_anonymity_immediately() {
        let pts = sweep(true, &[1.0, 8.0, 32.0], 7);
        for p in &pts {
            assert!(
                p.strong(),
                "cover at delay {} failed: gain {:.2}x",
                p.latency,
                p.adversary_gain
            );
            assert!(p.bandwidth_overhead > 100.0, "and it is not cheap");
        }
    }

    /// The shipping configuration pays both costs, and the trilemma requires one.
    ///
    /// That is not an overpayment, and `docs/15-fundamental-limits.md` settles why: the two
    /// costs buy two properties from two different adversaries. The trilemma governs the
    /// bandwidth cost against a passive adversary; the n-1 attack governs the latency cost
    /// against an active one, where a batch mix is isolated 51.7% of the time and a Poisson
    /// mix 0.7%. This asserts the shape of the tradeoff, not a defect.
    ///
    /// One thing it does **not** show, and used to be read as showing: that cover traffic is
    /// sufficient in general. It is measured at one packet per client per tick, which is
    /// twenty-four packets in flight per client. See `sim::passive_frontier` for where that
    /// stops holding.
    #[test]
    fn the_shipping_configuration_pays_both_costs() {
        let cfg = SimConfig::karst(7);
        let r = run(&cfg);

        assert!(r.bandwidth_overhead() > 100.0, "high bandwidth overhead");
        assert!(cfg.mean_delay >= 8.0, "and high latency");
        assert!(
            r.advantage() < 1.05,
            "for anonymity that one of them alone achieves"
        );

        // Cover traffic at minimal delay reaches the same anonymity for far less latency.
        let mut cheap = SimConfig::karst(7);
        cheap.mean_delay = 1.0;
        let c = run(&cheap);
        assert!(
            c.advantage() < 1.05,
            "delay is not what is buying the passive result"
        );
    }
}

/// The shipping parameter set, derived rather than chosen.
///
/// Every number here follows from a constraint measured or cited elsewhere, and the derivation
/// is checked by `the_parameters_follow_from_their_constraints`. The point is not that these
/// are the only defensible values; it is that changing one of them has a consequence somebody
/// can compute.
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    /// Clients simultaneously online. Everything below scales with it.
    pub clients: f64,
    /// Emission interval in seconds, per direction.
    pub emission_interval_s: f64,
    /// Mixes per layer.
    pub width: f64,
    /// Delayed hops on a path: the mix layers plus the terminal provider.
    pub hops: f64,
    /// Mean per-hop delay in seconds.
    pub mean_delay_s: f64,
}

impl Parameters {
    /// Emission rate per client, packets per second.
    pub fn rate(&self) -> f64 {
        1.0 / self.emission_interval_s
    }

    /// Honest packets arriving at one mix per second.
    pub fn arrival_rate(&self) -> f64 {
        self.clients * self.rate() / self.width
    }

    /// Mean pool occupancy, which is what governs n-1 isolation. See `active::delay_frontier`.
    pub fn occupancy(&self) -> f64 {
        self.arrival_rate() * self.mean_delay_s
    }

    /// Mean end-to-end latency. The per-hop delays are exponential, so this is Erlang(k, d).
    pub fn end_to_end_s(&self) -> f64 {
        self.hops * self.mean_delay_s
    }

    /// Standard deviation of end-to-end latency.
    pub fn end_to_end_sd_s(&self) -> f64 {
        self.hops.sqrt() * self.mean_delay_s
    }

    /// Packets of one client in flight at any moment, by Little's law.
    pub fn in_flight(&self) -> f64 {
        self.rate() * self.hops * self.mean_delay_s
    }

    /// Bytes per month per client, both directions, at 1024 bytes per packet.
    pub fn monthly_bytes(&self) -> f64 {
        1024.0 * 2.0 * 30.0 * 86_400.0 * self.rate()
    }

    /// The set this ships with.
    ///
    /// `emission_interval_s = 5` comes from three independent directions agreeing, in
    /// `docs/15-fundamental-limits.md`: it is inside the deployed precedent band, it costs
    /// about 1.06 GB per month, and shorter intervals leave that budget.
    ///
    /// `mean_delay_s` is then not a choice. Occupancy 80 is the isolation target of about 2%
    /// from `active::delay_frontier`, and occupancy is `arrival_rate * mean_delay`, so the
    /// delay is whatever satisfies it at this population and width.
    pub fn shipping() -> Self {
        Parameters {
            clients: 1000.0,
            emission_interval_s: 5.0,
            width: 4.0,
            hops: 4.0,
            mean_delay_s: 1.6,
        }
    }
}

#[cfg(test)]
mod parameter_tests {
    use super::*;

    /// Each parameter follows from a constraint, and the constraints are satisfied together.
    ///
    /// This is the check that the set is derived rather than assembled. If any assertion here
    /// fails after someone edits a value, the edit broke a constraint somebody measured, and
    /// the failure says which.
    #[test]
    fn the_parameters_follow_from_their_constraints() {
        let p = Parameters::shipping();

        // The active constraint. Occupancy near 80 gives about 2% isolation, measured in
        // `active::delay_frontier`. This is what fixes the delay.
        let occ = p.occupancy();
        assert!(
            (occ - 80.0).abs() < 5.0,
            "occupancy is {occ:.1}, so the isolation target of about 2% is not what this \
             delay achieves"
        );

        // The passive constraint. Packets in flight must stay above the measured boundary of
        // roughly 0.2, from `sim::passive_frontier`. Note this is far below the one packet
        // Little's law would demand, which is the correction that made 5 s affordable.
        let f = p.in_flight();
        assert!(
            f > 0.5,
            "only {f:.2} packets in flight, which is inside the region where the anonymity \
             set falls away from the ceiling"
        );

        // The granularity floor from `active::delay_frontier`: a mean delay below the spacing
        // of arrivals leaves the exponential no room and degrades toward batching.
        let spacing = 1.0 / p.arrival_rate();
        assert!(
            p.mean_delay_s > spacing * 10.0,
            "mean delay {:.2}s against arrival spacing {:.3}s is too close to the floor",
            p.mean_delay_s,
            spacing
        );

        // The budget constraint. 1.06 GB per month, both directions.
        let gb = p.monthly_bytes() / 1e9;
        assert!(
            (0.9..1.3).contains(&gb),
            "monthly cost is {gb:.2} GB, which is not the figure the emission interval was \
             chosen against"
        );
    }

    /// Halving the emission interval does not halve the delay, and the test says why.
    ///
    /// Doubling the rate doubles the arrival rate at each mix, so the same occupancy is
    /// reached at half the delay. Latency and bandwidth therefore trade against each other at
    /// fixed anonymity, which is the trilemma showing up in a concrete parameter set rather
    /// than as a slogan.
    #[test]
    fn rate_and_delay_trade_at_fixed_anonymity() {
        let base = Parameters::shipping();
        let faster = Parameters {
            emission_interval_s: base.emission_interval_s / 2.0,
            mean_delay_s: base.mean_delay_s / 2.0,
            ..base
        };
        assert!(
            (faster.occupancy() - base.occupancy()).abs() < 1.0,
            "halving both did not hold occupancy, so they do not trade"
        );
        assert!(faster.end_to_end_s() < base.end_to_end_s());
        assert!(faster.monthly_bytes() > base.monthly_bytes());
    }
}
