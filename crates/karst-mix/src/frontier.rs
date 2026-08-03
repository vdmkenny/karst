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

    /// **The self-challenge.** KARST's shipping configuration pays both costs, and the
    /// trilemma only requires one. This asserts the overpayment exists rather than hiding it,
    /// so the question of whether to reclaim it stays open and visible.
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
